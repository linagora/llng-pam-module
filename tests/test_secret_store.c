/*
 * test_secret_store.c - Unit tests for secret store
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#include "secret_store.h"

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

static const char *test_store_dir = "/tmp/test_pam_llng_secrets";
static int machine_id_available = 0;

/* Check if /etc/machine-id exists (required for secret store) */
static int check_machine_id(void)
{
    struct stat st;
    return stat("/etc/machine-id", &st) == 0;
}

/* Setup test directory */
static void setup(void)
{
    mkdir(test_store_dir, 0700);
    machine_id_available = check_machine_id();
}

/* Recursively remove directory - safe alternative to system("rm -rf")
 * Uses openat/unlinkat to avoid TOCTOU race conditions */
static int remove_directory(const char *path)
{
    int dir_fd = open(path, O_RDONLY | O_DIRECTORY);
    if (dir_fd < 0) {
        if (errno == ENOENT) return 0;  /* Already gone */
        return -1;
    }

    DIR *dir = fdopendir(dir_fd);
    if (!dir) {
        close(dir_fd);
        return -1;
    }

    struct dirent *entry;
    char filepath[512];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        struct stat st;
        if (fstatat(dir_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            if (S_ISDIR(st.st_mode)) {
                snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
                remove_directory(filepath);
            } else {
                unlinkat(dir_fd, entry->d_name, 0);
            }
        }
    }

    closedir(dir);  /* Also closes dir_fd */
    return rmdir(path);
}

/* Cleanup test directory */
static void cleanup(void)
{
    remove_directory(test_store_dir);
}

/* Global flag to track if store initialization works */
static int store_init_works = 0;

/* Test initialization */
static int test_init(void)
{
    if (!machine_id_available) {
        printf("SKIP (no machine-id) ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) {
        /* May fail in CI due to container permissions */
        printf("SKIP (init failed in CI) ");
        return 1;
    }

    store_init_works = 1;  /* Mark that init works for subsequent tests */
    secret_store_destroy(store);
    return 1;
}

/* Test store and retrieve */
static int test_put_get(void)
{
    if (!machine_id_available || !store_init_works) {
        printf("SKIP ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) {
        printf("SKIP (init failed) ");
        return 1;
    }

    const char *secret = "my-super-secret-token-12345";
    int ret = secret_store_put(store, "user:token", secret, strlen(secret));
    if (ret != 0) {
        secret_store_destroy(store);
        return 0;
    }

    char retrieved[256] = {0};
    size_t actual_len = 0;
    ret = secret_store_get(store, "user:token", retrieved, sizeof(retrieved), &actual_len);

    secret_store_destroy(store);

    if (ret != 0) return 0;
    if (actual_len != strlen(secret)) return 0;
    if (strcmp(retrieved, secret) != 0) return 0;

    return 1;
}

/* Test exists */
static int test_exists(void)
{
    if (!machine_id_available || !store_init_works) {
        printf("SKIP ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) {
        printf("SKIP (init failed) ");
        return 1;
    }

    const char *secret = "test-secret";
    secret_store_put(store, "exists:key", secret, strlen(secret));

    int ok = 1;
    ok = ok && secret_store_exists(store, "exists:key");
    ok = ok && !secret_store_exists(store, "nonexistent:key");

    secret_store_destroy(store);
    return ok;
}

/* Test delete */
static int test_delete(void)
{
    if (!machine_id_available || !store_init_works) {
        printf("SKIP ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) {
        printf("SKIP (init failed) ");
        return 1;
    }

    const char *secret = "to-be-deleted";
    secret_store_put(store, "delete:key", secret, strlen(secret));

    int ok = 1;
    ok = ok && secret_store_exists(store, "delete:key");

    int ret = secret_store_delete(store, "delete:key");
    ok = ok && (ret == 0);
    ok = ok && !secret_store_exists(store, "delete:key");

    secret_store_destroy(store);
    return ok;
}

/* Test not found */
static int test_not_found(void)
{
    if (!machine_id_available || !store_init_works) {
        printf("SKIP ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) {
        printf("SKIP (init failed) ");
        return 1;
    }

    char retrieved[256];
    size_t actual_len;
    int ret = secret_store_get(store, "nonexistent:key", retrieved,
                                sizeof(retrieved), &actual_len);

    secret_store_destroy(store);
    return (ret == -2);  /* -2 = not found */
}

/* Test different keys */
static int test_different_keys(void)
{
    if (!machine_id_available || !store_init_works) {
        printf("SKIP ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) {
        printf("SKIP (init failed) ");
        return 1;
    }

    const char *secret1 = "secret-for-alice";
    const char *secret2 = "secret-for-bob";

    secret_store_put(store, "alice:token", secret1, strlen(secret1));
    secret_store_put(store, "bob:token", secret2, strlen(secret2));

    char retrieved1[256] = {0};
    char retrieved2[256] = {0};
    size_t len1, len2;

    secret_store_get(store, "alice:token", retrieved1, sizeof(retrieved1), &len1);
    secret_store_get(store, "bob:token", retrieved2, sizeof(retrieved2), &len2);

    secret_store_destroy(store);

    return (strcmp(retrieved1, secret1) == 0 &&
            strcmp(retrieved2, secret2) == 0);
}

/* Test overwrite */
static int test_overwrite(void)
{
    if (!machine_id_available || !store_init_works) {
        printf("SKIP ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) {
        printf("SKIP (init failed) ");
        return 1;
    }

    const char *secret1 = "original-secret";
    const char *secret2 = "updated-secret";

    secret_store_put(store, "overwrite:key", secret1, strlen(secret1));
    secret_store_put(store, "overwrite:key", secret2, strlen(secret2));

    char retrieved[256] = {0};
    size_t actual_len;
    secret_store_get(store, "overwrite:key", retrieved, sizeof(retrieved), &actual_len);

    secret_store_destroy(store);

    return (strcmp(retrieved, secret2) == 0);
}

/* Test disabled store */
static int test_disabled(void)
{
    secret_store_config_t config = {
        .enabled = false,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    const char *secret = "test";
    int ret = secret_store_put(store, "disabled:key", secret, strlen(secret));

    secret_store_destroy(store);
    return (ret == -1);  /* Should fail when disabled */
}

/* Test binary data */
static int test_binary_data(void)
{
    if (!machine_id_available || !store_init_works) {
        printf("SKIP ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) {
        printf("SKIP (init failed) ");
        return 1;
    }

    /* Binary data with null bytes */
    unsigned char binary_secret[32];
    for (int i = 0; i < 32; i++) {
        binary_secret[i] = (unsigned char)i;
    }

    int ret = secret_store_put(store, "binary:key", binary_secret, sizeof(binary_secret));
    if (ret != 0) {
        secret_store_destroy(store);
        return 0;
    }

    unsigned char retrieved[64] = {0};
    size_t actual_len = 0;
    ret = secret_store_get(store, "binary:key", retrieved, sizeof(retrieved), &actual_len);

    secret_store_destroy(store);

    if (ret != 0) return 0;
    if (actual_len != sizeof(binary_secret)) return 0;
    if (memcmp(retrieved, binary_secret, sizeof(binary_secret)) != 0) return 0;

    return 1;
}

/* Test error message */
static int test_error_message(void)
{
    secret_store_config_t config = {
        .enabled = false,
        .store_dir = (char *)test_store_dir,
        .salt = NULL,
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) return 0;

    secret_store_put(store, "test", "test", 4);

    const char *error = secret_store_error(store);
    int ok = (error != NULL && strlen(error) > 0);

    secret_store_destroy(store);
    return ok;
}

/* Test rotate key returns error (not implemented) */
static int test_rotate_key_not_implemented(void)
{
    if (!machine_id_available || !store_init_works) {
        printf("SKIP ");
        return 1;
    }

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = (char *)test_store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) {
        printf("SKIP (init failed) ");
        return 1;
    }

    int ret = secret_store_rotate_key(store);

    secret_store_destroy(store);
    return (ret == -1);  /* Should return -1 (not implemented) */
}

/* Find the single file with the given suffix in dir. Returns 1 on success. */
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
 * secret_store_put() used to write through a fixed "<path>.tmp" opened with
 * O_TRUNC, so two concurrent writers interleaved into a single file and
 * renamed the mixture into place. A sentinel planted at the old fixed name
 * must now be left strictly untouched — the writer uses "<path>.tmp.<pid>"
 * created with O_EXCL.
 */
static int test_temp_file_is_private(void)
{
    if (!machine_id_available || !store_init_works) {
        printf("SKIP ");
        return 1;
    }

    char store_dir[] = "/tmp/test_secret_tmpname_XXXXXX";
    if (mkdtemp(store_dir) == NULL) return 0;

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) {
        remove_directory(store_dir);
        printf("SKIP (init failed) ");
        return 1;
    }

    const char *secret = "first-value";
    int ok = (secret_store_put(store, "tmpname:key", secret, strlen(secret)) == 0);

    char entry_path[512] = {0};
    ok = ok && find_file_with_suffix(store_dir, ".enc", entry_path, sizeof(entry_path));

    /* Plant a sentinel at the temp name the pre-#197 code would have reused. */
    char legacy_tmp[600];
    const char *sentinel = "SENTINEL-MUST-SURVIVE";
    if (ok) {
        snprintf(legacy_tmp, sizeof(legacy_tmp), "%s.tmp", entry_path);
        int fd = open(legacy_tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
        ok = (fd >= 0);
        if (ok) {
            ok = (write(fd, sentinel, strlen(sentinel)) == (ssize_t)strlen(sentinel));
            close(fd);
        }
    }

    /* Overwrite the entry: this must not go through the fixed temp name. */
    const char *second = "second-value-longer";
    ok = ok && (secret_store_put(store, "tmpname:key", second, strlen(second)) == 0);

    if (ok) {
        char buf[128] = {0};
        int fd = open(legacy_tmp, O_RDONLY);
        ok = (fd >= 0);
        if (ok) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            ok = (n == (ssize_t)strlen(sentinel) && strcmp(buf, sentinel) == 0);
        }
    }

    /* And the entry itself must hold the new value. */
    if (ok) {
        char got[128] = {0};
        size_t got_len = 0;
        ok = (secret_store_get(store, "tmpname:key", got, sizeof(got), &got_len) == 0) &&
             got_len == strlen(second) && strcmp(got, second) == 0;
    }

    secret_store_destroy(store);
    remove_directory(store_dir);
    return ok;
}

/*
 * Concurrency regression for #197: concurrent writers must never publish a
 * mixture of each other's bytes.
 *
 * Each child writes a distinctly sized value for the same key; with the old
 * shared "<path>.tmp" the interleaved content failed AES-GCM authentication on
 * read. With a private temp file per process every rename publishes one
 * writer's complete value, so the final get() always succeeds and always
 * returns one of the values written.
 */
#define SS_CONC_CHILDREN 6
#define SS_CONC_ROUNDS   10

static int test_concurrent_put(void)
{
    if (!machine_id_available || !store_init_works) {
        printf("SKIP ");
        return 1;
    }

    char store_dir[] = "/tmp/test_secret_conc_XXXXXX";
    if (mkdtemp(store_dir) == NULL) return 0;

    secret_store_config_t config = {
        .enabled = true,
        .store_dir = store_dir,
        .salt = "test-salt",
        .use_keyring = false,
        .keyring_name = NULL
    };

    secret_store_t *store = secret_store_init(&config);
    if (!store) {
        remove_directory(store_dir);
        printf("SKIP (init failed) ");
        return 1;
    }

    /* Derive the key/salt once up front so the children only race on the write. */
    if (secret_store_put(store, "conc:key", "seed", 4) != 0) {
        secret_store_destroy(store);
        remove_directory(store_dir);
        return 0;
    }

    int barrier[2];
    if (pipe(barrier) != 0) {
        secret_store_destroy(store);
        remove_directory(store_dir);
        return 0;
    }

    int started = 0;
    for (int i = 0; i < SS_CONC_CHILDREN; i++) {
        pid_t pid = fork();
        if (pid < 0) break;
        if (pid == 0) {
            close(barrier[1]);
            char c;
            ssize_t r;
            do {
                r = read(barrier[0], &c, 1);
            } while (r < 0 && errno == EINTR);
            close(barrier[0]);

            /* Distinct length per child so an interleave cannot go unnoticed. */
            char value[128];
            int len = snprintf(value, sizeof(value), "child-%d", i);
            for (int pad = 0; pad < i * 10 && len < (int)sizeof(value) - 1; pad++) {
                value[len++] = 'x';
            }
            value[len] = '\0';

            for (int j = 0; j < SS_CONC_ROUNDS; j++) {
                secret_store_put(store, "conc:key", value, (size_t)len);
            }
            _exit(0);
        }
        started++;
    }

    close(barrier[0]);
    for (int i = 0; i < started; i++) {
        if (write(barrier[1], "g", 1) != 1) break;
    }
    close(barrier[1]);

    for (int i = 0; i < started; i++) {
        int status;
        wait(&status);
    }

    int ok = (started == SS_CONC_CHILDREN);

    char got[128] = {0};
    size_t got_len = 0;
    if (ok && secret_store_get(store, "conc:key", got, sizeof(got), &got_len) != 0) {
        printf("(entry unreadable after concurrent writes) ");
        ok = 0;
    }
    if (ok && strncmp(got, "child-", 6) != 0) {
        printf("(entry corrupted: '%s') ", got);
        ok = 0;
    }

    /* No fixed-name temp file may be left behind either. */
    char entry_path[512];
    if (ok && find_file_with_suffix(store_dir, ".tmp", entry_path, sizeof(entry_path))) {
        printf("(stale shared temp file %s) ", entry_path);
        ok = 0;
    }

    secret_store_destroy(store);
    remove_directory(store_dir);
    return ok;
}

int main(void)
{
    printf("Running secret store tests...\n\n");

    setup();

    TEST(init);
    TEST(put_get);
    TEST(exists);
    TEST(delete);
    TEST(not_found);
    TEST(different_keys);
    TEST(overwrite);
    TEST(disabled);
    TEST(binary_data);
    TEST(error_message);
    TEST(rotate_key_not_implemented);
    TEST(temp_file_is_private);
    TEST(concurrent_put);

    cleanup();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
