/*
 * test_nss_cache.c - Regression test for the in-memory LRU cache of the
 * NSS module (libnss_openbastion.c).
 *
 * Reproduces the double-free that crashed nscd (SIGABRT,
 * "double free or corruption (out)") roughly every 4-5h on bastions:
 *
 *   - cache_find()/cache_find_by_uid() free an expired entry's pw_buffer
 *     but (before the fix) leave the pointer dangling, only nulling username.
 *   - The slot stays within [0, count) as a hole with its old (oldest)
 *     timestamp.
 *   - cache_add(), once the cache is full, evicts the oldest entry and frees
 *     username + pw_buffer again => double free of the dangling pw_buffer.
 *
 * This only fires in a long-lived consumer whose cache reaches capacity
 * (nscd); short-lived callers (ls/id/sudo/sshd) exit first, which is why it
 * went unnoticed.
 *
 * We include the module source directly to drive the static cache helpers
 * (init_cache/cache_add/cache_find) against the real g_cache/g_config state.
 */

/* Point the on-disk cache at a throwaway directory: file_cache_save() must
 * never touch the real /var/cache/nss_llng from a unit test. */
#define CACHE_DIR "/tmp/test_nss_openbastion_cache"

#include "../nss/libnss_openbastion.c"

#include <assert.h>

/* Release everything init_cache()/cache_add() allocated, so the test leaves
 * no leaks under LeakSanitizer (free() is NULL-safe for expired holes). */
static void cache_teardown(void)
{
    if (!g_cache.entries) {
        return;
    }
    for (size_t i = 0; i < g_cache.count; i++) {
        free(g_cache.entries[i].username);
        free(g_cache.entries[i].pw_buffer);
    }
    free(g_cache.entries);
    g_cache.entries = NULL;
    g_cache.count = 0;
    g_cache.capacity = 0;
}

static struct passwd make_pw(const char *name, uid_t uid)
{
    struct passwd pw;
    pw.pw_name = (char *)name;
    pw.pw_passwd = (char *)"x";
    pw.pw_uid = uid;
    pw.pw_gid = uid;
    pw.pw_gecos = (char *)"";
    pw.pw_dir = (char *)"/home/x";
    pw.pw_shell = (char *)"/bin/bash";
    return pw;
}

/*
 * Fill the cache to capacity, expire+find one entry (creating a dangling
 * pw_buffer hole in the buggy code), then force an eviction that lands on
 * that hole. The buggy code double-frees here and aborts; the fixed code
 * survives because pw_buffer was nulled.
 */
static int test_expire_then_evict_no_double_free(void)
{
    if (init_cache() != 0) {
        fprintf(stderr, "init_cache failed\n");
        return 0;
    }
    /* Long TTL so entries don't expire on their own; we backdate manually. */
    g_config.cache_ttl = 1000000;

    char name[32];
    for (size_t i = 0; i < g_cache.capacity; i++) {
        snprintf(name, sizeof(name), "user%zu", i);
        struct passwd pw = make_pw(name, (uid_t)(100000 + i));
        cache_add(name, &pw, 1);
    }
    assert(g_cache.count == g_cache.capacity);

    /* Make slot 0 both expired and the oldest entry. */
    g_cache.entries[0].timestamp = time(NULL) - (g_config.cache_ttl + 100);

    /* Look it up: expired => freed. Buggy code leaves pw_buffer dangling. */
    cache_entry_t *e = cache_find("user0");
    assert(e == NULL);

    /* Adding one more triggers eviction of the oldest = slot 0. The buggy
     * code frees the dangling pw_buffer a second time -> SIGABRT here. */
    struct passwd extra = make_pw("newcomer", 200000);
    cache_add("newcomer", &extra, 1);

    /* If we reach this line, no double free occurred. */
    cache_teardown();
    return 1;
}

/* Same scenario through the UID lookup path. */
static int test_expire_by_uid_then_evict_no_double_free(void)
{
    if (init_cache() != 0) {
        fprintf(stderr, "init_cache failed\n");
        return 0;
    }
    g_config.cache_ttl = 1000000;

    char name[32];
    for (size_t i = 0; i < g_cache.capacity; i++) {
        snprintf(name, sizeof(name), "u%zu", i);
        struct passwd pw = make_pw(name, (uid_t)(300000 + i));
        cache_add(name, &pw, 1);
    }
    assert(g_cache.count == g_cache.capacity);

    g_cache.entries[0].timestamp = time(NULL) - (g_config.cache_ttl + 100);

    cache_entry_t *e = cache_find_by_uid(300000);
    assert(e == NULL);

    struct passwd extra = make_pw("uidnewcomer", 400000);
    cache_add("uidnewcomer", &extra, 1);

    cache_teardown();
    return 1;
}

/*
 * trim() used to compute `str + strlen(str) - 1` before looking at the string,
 * which is undefined behaviour (a pointer before the start of the object) for
 * an empty or all-blank value - exactly what a "key =" line in
 * nss_openbastion.conf produces. Detected by UBSan/ASan; here we simply assert
 * the result is a well-formed empty string.
 */
static int test_trim_empty_is_not_ub(void)
{
    char empty[] = "";
    char blanks[] = "   \t";
    char value[] = "  hello  ";

    if (strcmp(trim(empty), "") != 0) return 0;
    if (strcmp(trim(blanks), "") != 0) return 0;
    if (strcmp(trim(value), "hello") != 0) return 0;
    return 1;
}

/*
 * file_cache_save() writes the shared uid -> passwd cache under CACHE_DIR.
 * Only root may do so: an NSS module is loaded into every process that
 * resolves a user, so an unprivileged caller must never be able to create or
 * rewrite entries the whole host then trusts.
 *
 * Running as root we cannot observe the refusal, so we check the modes the
 * fix installs instead (directory 0711 = traversable but not listable, entry
 * 0644 root-owned - it must stay readable, see file_cache_save()).
 */
static int test_file_cache_save_privileges(void)
{
    struct passwd pw = make_pw("cacheduser", 123456);
    char entry[256];
    snprintf(entry, sizeof(entry), "%s/%u", CACHE_DIR, (unsigned)pw.pw_uid);

    /* Start from a clean slate. */
    unlink(entry);
    rmdir(CACHE_DIR);

    file_cache_save(&pw);

    struct stat st;
    if (geteuid() != 0) {
        /* Unprivileged: nothing at all must have been created. */
        if (stat(CACHE_DIR, &st) == 0) {
            fprintf(stderr, "unprivileged file_cache_save created %s\n", CACHE_DIR);
            unlink(entry);
            rmdir(CACHE_DIR);
            return 0;
        }
        return 1;
    }

    int ok = 1;
    if (stat(CACHE_DIR, &st) != 0 || (st.st_mode & 07777) != 0711) {
        fprintf(stderr, "cache dir mode %04o, expected 0711\n",
                (unsigned)(st.st_mode & 07777));
        ok = 0;
    }
    if (stat(entry, &st) != 0 || (st.st_mode & 07777) != 0644 || st.st_uid != 0) {
        fprintf(stderr, "cache entry mode %04o uid %u, expected 0644 root\n",
                (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid);
        ok = 0;
    }
    unlink(entry);
    rmdir(CACHE_DIR);
    return ok;
}

int main(void)
{
    int ok = 1;

    printf("  Testing expire_then_evict_no_double_free... ");
    if (test_expire_then_evict_no_double_free()) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        ok = 0;
    }

    printf("  Testing expire_by_uid_then_evict_no_double_free... ");
    if (test_expire_by_uid_then_evict_no_double_free()) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        ok = 0;
    }

    printf("  Testing trim_empty_is_not_ub... ");
    if (test_trim_empty_is_not_ub()) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        ok = 0;
    }

    printf("  Testing file_cache_save_privileges... ");
    if (test_file_cache_save_privileges()) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        ok = 0;
    }

    printf("%s\n", ok ? "All NSS cache tests passed" : "NSS cache tests FAILED");
    return ok ? 0 : 1;
}
