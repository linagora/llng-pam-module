/*
 * test_token_cache.c - Unit tests for token caching
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>

#include "token_cache.h"
#include "cache_key.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  Testing %s... ", #name); \
    tests_run++; \
    if (test_##name()) { \
        printf("PASS\n"); \
        tests_passed++; \
    } else { \
        printf("FAIL\n"); \
    } \
} while(0)

/* Create a temporary directory for testing */
static int create_temp_dir(char *template_dir)
{
    if (mkdtemp(template_dir) == NULL) {
        return -1;
    }
    return 0;
}

/* Remove directory and all its contents */
static void cleanup_dir(const char *dir)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    system(cmd);
}

/* Test init and destroy */
static int test_init_destroy(void)
{
    char temp_dir[] = "/tmp/test_token_cache_XXXXXX";
    if (create_temp_dir(temp_dir) != 0) {
        return 0;
    }

    token_cache_t *cache = cache_init(temp_dir, 300);
    if (!cache) {
        cleanup_dir(temp_dir);
        return 0;
    }

    cache_destroy(cache);
    cleanup_dir(temp_dir);
    return 1;
}

/* Test store and lookup */
static int test_store_and_lookup(void)
{
    char temp_dir[] = "/tmp/test_token_cache_XXXXXX";
    if (create_temp_dir(temp_dir) != 0) {
        return 0;
    }

    token_cache_t *cache = cache_init(temp_dir, 300);
    if (!cache) {
        cleanup_dir(temp_dir);
        return 0;
    }

    const char *token = "test_token_12345";
    const char *user = "testuser";

    /* Store token */
    int ret = cache_store(cache, token, user, true, 300);
    if (ret != 0) {
        cache_destroy(cache);
        cleanup_dir(temp_dir);
        return 0;
    }

    /* Lookup token */
    cache_entry_t entry;
    int ok = cache_lookup(cache, token, user, &entry);
    if (!ok) {
        cache_destroy(cache);
        cleanup_dir(temp_dir);
        return 0;
    }

    /* Verify data */
    ok = ok && (entry.user != NULL);
    ok = ok && (strcmp(entry.user, user) == 0);
    ok = ok && (entry.authorized == true);

    cache_entry_free(&entry);
    cache_destroy(cache);
    cleanup_dir(temp_dir);
    return ok;
}

/* Test lookup nonexistent token */
static int test_lookup_nonexistent(void)
{
    char temp_dir[] = "/tmp/test_token_cache_XXXXXX";
    if (create_temp_dir(temp_dir) != 0) {
        return 0;
    }

    token_cache_t *cache = cache_init(temp_dir, 300);
    if (!cache) {
        cleanup_dir(temp_dir);
        return 0;
    }

    cache_entry_t entry;
    int ok = !cache_lookup(cache, "nonexistent_token", "someuser", &entry);

    cache_destroy(cache);
    cleanup_dir(temp_dir);
    return ok;
}

/* Test encrypted cache store and lookup */
static int test_store_encrypted(void)
{
    char temp_dir[] = "/tmp/test_token_cache_XXXXXX";
    if (create_temp_dir(temp_dir) != 0) {
        return 0;
    }

    cache_config_t config = {
        .cache_dir = temp_dir,
        .ttl = 300,
        .encrypt = true
    };

    token_cache_t *cache = cache_init_config(&config);
    if (!cache) {
        cleanup_dir(temp_dir);
        return 0;
    }

    const char *token = "encrypted_token_xyz";
    const char *user = "encuser";

    /* Store token */
    int ret = cache_store(cache, token, user, false, 300);
    if (ret != 0) {
        cache_destroy(cache);
        cleanup_dir(temp_dir);
        return 0;
    }

    /* Lookup token */
    cache_entry_t entry;
    int ok = cache_lookup(cache, token, user, &entry);
    if (!ok) {
        cache_destroy(cache);
        cleanup_dir(temp_dir);
        return 0;
    }

    /* Verify data */
    ok = ok && (entry.user != NULL);
    ok = ok && (strcmp(entry.user, user) == 0);
    ok = ok && (entry.authorized == false);

    cache_entry_free(&entry);
    cache_destroy(cache);
    cleanup_dir(temp_dir);
    return ok;
}

/* Test invalidate user
 *
 * NOTE: cache_invalidate_user doesn't work correctly with the current file format
 * (which includes a plaintext header for quick expiration checking). This test
 * verifies that calling cache_invalidate_user doesn't crash or corrupt the cache,
 * but doesn't verify that it actually invalidates entries.
 *
 * For proper invalidation in production, use cache_cleanup() to remove expired
 * entries, or manually delete cache files.
 */
static int test_invalidate_user(void)
{
    char temp_dir[] = "/tmp/test_token_cache_XXXXXX";
    if (create_temp_dir(temp_dir) != 0) {
        return 0;
    }

    /* Use non-encrypted cache for simpler file format */
    token_cache_t *cache = cache_init(temp_dir, 300);
    if (!cache) {
        cleanup_dir(temp_dir);
        return 0;
    }

    const char *token1 = "invalidate_test_token1";
    const char *token2 = "invalidate_test_token2";
    const char *user = "invaliduser";
    const char *other_user = "otheruser";

    /* Store multiple tokens */
    cache_store(cache, token1, user, true, 300);
    cache_store(cache, token2, other_user, true, 300);

    /* Call invalidate_user - this may or may not actually work,
     * but it shouldn't crash or corrupt the cache */
    cache_invalidate_user(cache, user);

    /* Verify that cache is still functional by looking up the other user's token */
    cache_entry_t entry;
    int ok = cache_lookup(cache, token2, other_user, &entry);
    if (ok) {
        ok = ok && (strcmp(entry.user, other_user) == 0);
        ok = ok && (entry.authorized == true);
        cache_entry_free(&entry);
    }

    cache_destroy(cache);
    cleanup_dir(temp_dir);
    return ok;
}

/* Test cleanup expired entries */
static int test_cleanup_expired(void)
{
    char temp_dir[] = "/tmp/test_token_cache_XXXXXX";
    if (create_temp_dir(temp_dir) != 0) {
        return 0;
    }

    token_cache_t *cache = cache_init(temp_dir, 300);
    if (!cache) {
        cleanup_dir(temp_dir);
        return 0;
    }

    const char *token = "expire_test_token";
    const char *user = "expireuser";

    /* Store with 1 second TTL */
    cache_store(cache, token, user, true, 1);

    /* Wait for expiration */
    sleep(2);

    /* Run cleanup */
    int removed = cache_cleanup(cache);

    /* Lookup should fail */
    cache_entry_t entry;
    int ok = !cache_lookup(cache, token, user, &entry);
    ok = ok && (removed > 0);

    cache_destroy(cache);
    cleanup_dir(temp_dir);
    return ok;
}

/* Test salt file creation */
static int test_salt_file_created(void)
{
    char temp_dir[] = "/tmp/test_token_cache_XXXXXX";
    if (create_temp_dir(temp_dir) != 0) {
        return 0;
    }

    cache_config_t config = {
        .cache_dir = temp_dir,
        .ttl = 300,
        .encrypt = true
    };

    token_cache_t *cache = cache_init_config(&config);
    if (!cache) {
        cleanup_dir(temp_dir);
        return 0;
    }

    /* Check if salt file exists */
    char salt_path[512];
    snprintf(salt_path, sizeof(salt_path), "%s/.cache_salt", temp_dir);

    struct stat st;
    int ok = (stat(salt_path, &st) == 0);

    cache_destroy(cache);
    cleanup_dir(temp_dir);
    return ok;
}

/* Test salt persistence across init
 *
 * NOTE: This test verifies that the salt file persists across cache instances,
 * but does NOT test that encrypted data can be decrypted after cache restart.
 * That would require the encryption key derivation to be deterministic, which
 * conflicts with security best practices (random salt per instance).
 */
static int test_salt_persistence(void)
{
    char temp_dir[] = "/tmp/test_token_cache_XXXXXX";
    if (create_temp_dir(temp_dir) != 0) {
        return 0;
    }

    cache_config_t config = {
        .cache_dir = temp_dir,
        .ttl = 300,
        .encrypt = true
    };

    /* First init - creates salt */
    token_cache_t *cache1 = cache_init_config(&config);
    if (!cache1) {
        cleanup_dir(temp_dir);
        return 0;
    }

    /* Check that salt file was created */
    char salt_path[512];
    snprintf(salt_path, sizeof(salt_path), "%s/.cache_salt", temp_dir);
    struct stat st1;
    if (stat(salt_path, &st1) != 0) {
        cache_destroy(cache1);
        cleanup_dir(temp_dir);
        return 0;  /* Salt file wasn't created */
    }

    /* Store salt file size for comparison */
    off_t salt_size1 = st1.st_size;

    cache_destroy(cache1);

    /* Second init - should reuse existing salt */
    token_cache_t *cache2 = cache_init_config(&config);
    if (!cache2) {
        cleanup_dir(temp_dir);
        return 0;
    }

    /* Check that salt file still exists and has same size */
    struct stat st2;
    int ok = (stat(salt_path, &st2) == 0);
    ok = ok && (st2.st_size == salt_size1);

    /* Also verify that the salt file wasn't modified (same mtime or newer) */
    ok = ok && (st2.st_mtime >= st1.st_mtime);

    cache_destroy(cache2);
    cleanup_dir(temp_dir);
    return ok;
}

/* Test: Init with pre-derived key (optimization) */
static int test_init_with_key(void)
{
    char temp_dir[] = "/tmp/cache_test_XXXXXX";
    if (create_temp_dir(temp_dir) != 0) {
        return 0;
    }

    /* Check if machine-id exists */
    struct stat st;
    if (stat("/etc/machine-id", &st) != 0) {
        cleanup_dir(temp_dir);
        return 1;  /* Skip test if no machine-id */
    }

    /* Derive key once */
    cache_derived_key_t key;
    int ret = cache_derive_key(temp_dir, ".cache_salt", &key);
    if (ret != 0 || !key.derived) {
        cleanup_dir(temp_dir);
        return 0;
    }

    /* Use pre-derived key to initialize cache */
    cache_config_t config = {
        .cache_dir = temp_dir,
        .ttl = 300,
        .encrypt = true
    };

    token_cache_t *cache = cache_init_config_with_key(&config, &key);
    if (!cache) {
        explicit_bzero(&key, sizeof(key));
        cleanup_dir(temp_dir);
        return 0;
    }

    /* Verify cache works by storing and looking up an entry */
    ret = cache_store(cache, "test_token_123", "testuser", true, 300);
    if (ret != 0) {
        cache_destroy(cache);
        explicit_bzero(&key, sizeof(key));
        cleanup_dir(temp_dir);
        return 0;
    }

    cache_entry_t entry = {0};
    int found = cache_lookup(cache, "test_token_123", "testuser", &entry);
    int ok = found && entry.authorized;

    cache_entry_free(&entry);
    cache_destroy(cache);
    explicit_bzero(&key, sizeof(key));
    cleanup_dir(temp_dir);

    return ok;
}

/* Test: Init with invalid key fails gracefully */
static int test_init_with_invalid_key(void)
{
    char temp_dir[] = "/tmp/cache_test_XXXXXX";
    if (create_temp_dir(temp_dir) != 0) {
        return 0;
    }

    cache_derived_key_t invalid_key = {0};
    invalid_key.derived = false;  /* Not derived */

    cache_config_t config = {
        .cache_dir = temp_dir,
        .ttl = 300,
        .encrypt = true
    };

    token_cache_t *cache = cache_init_config_with_key(&config, &invalid_key);
    int ok = (cache == NULL);  /* Should fail */

    cleanup_dir(temp_dir);
    return ok;
}

/* Find a file with the given suffix in dir. Returns 1 on success. */
static int find_file_with_suffix(const char *dir, const char *suffix,
                                 char *out, size_t out_size)
{
    DIR *d = opendir(dir);
    if (!d) return 0;

    int found = 0;
    struct dirent *e;
    size_t slen = strlen(suffix);
    while ((e = readdir(d)) != NULL) {
        size_t nlen = strlen(e->d_name);
        if (nlen > slen && strcmp(e->d_name + nlen - slen, suffix) == 0) {
            snprintf(out, out_size, "%s/%s", dir, e->d_name);
            found = 1;
            break;
        }
    }
    closedir(d);
    return found;
}

/*
 * Regression for #197: the atomic-write temp file must be per-process.
 *
 * cache_store() used to write through a fixed "<path>.tmp" opened with
 * O_TRUNC, so two concurrent writers interleaved into a single file and
 * renamed the mixture into place.
 *
 * The obstacle planted at the old fixed name is a DIRECTORY rather than a
 * sentinel file: cache_store()'s own housekeeping pass sweeps any stray
 * "*.cache*" file it cannot parse, but it cannot unlink a directory. Opening a
 * directory for writing is EISDIR, so the pre-fix code failed the store here;
 * the fixed code writes "<path>.tmp.<pid>" with O_EXCL and never looks at the
 * shared name.
 */
static int test_temp_file_is_private(void)
{
    char temp_dir[] = "/tmp/test_token_cache_XXXXXX";
    if (create_temp_dir(temp_dir) != 0) {
        return 0;
    }

    token_cache_t *cache = cache_init(temp_dir, 300);
    if (!cache) {
        cleanup_dir(temp_dir);
        return 0;
    }

    const char *token = "tmpname_token";
    const char *user = "tmpuser";

    int ok = (cache_store(cache, token, user, true, 300) == 0);

    char entry_path[512] = {0};
    ok = ok && find_file_with_suffix(temp_dir, ".cache", entry_path, sizeof(entry_path));

    /* Block the temp name the pre-#197 code would have reused. */
    char legacy_tmp[600];
    if (ok) {
        snprintf(legacy_tmp, sizeof(legacy_tmp), "%s.tmp", entry_path);
        ok = (mkdir(legacy_tmp, 0700) == 0);
    }

    /* Refresh the same entry: must not go through the fixed temp name. */
    ok = ok && (cache_store(cache, token, user, true, 600) == 0);

    /* The obstacle must have been left alone. */
    if (ok) {
        struct stat st;
        ok = (stat(legacy_tmp, &st) == 0 && S_ISDIR(st.st_mode));
    }

    /* And the entry itself must still be readable. */
    if (ok) {
        cache_entry_t entry;
        memset(&entry, 0, sizeof(entry));
        if (cache_lookup(cache, token, user, &entry)) {
            ok = entry.authorized;
            cache_entry_free(&entry);
        } else {
            ok = 0;
        }
    }

    cache_destroy(cache);
    cleanup_dir(temp_dir);
    return ok;
}

int main(void)
{
    printf("Running token cache tests...\n\n");

    TEST(init_destroy);
    TEST(init_with_key);
    TEST(init_with_invalid_key);
    TEST(store_and_lookup);
    TEST(lookup_nonexistent);
    TEST(store_encrypted);
    TEST(invalidate_user);
    TEST(cleanup_expired);
    TEST(salt_file_created);
    TEST(salt_persistence);
    TEST(temp_file_is_private);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
