/*
 * token_cache.c - Token caching for LemonLDAP::NG PAM module
 *
 * Uses file-based cache with SHA256 hashed token names.
 * Supports optional AES-256-GCM encryption derived from machine-id.
 *
 * Copyright (C) 2024 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "token_cache.h"

/* Maximum number of cache entries to prevent DoS */
#define MAX_CACHE_ENTRIES 10000

/* Encryption constants */
#define MACHINE_ID_FILE "/etc/machine-id"
#define KEY_SIZE 32         /* AES-256 */
#define IV_SIZE 12          /* GCM recommended IV size */
#define TAG_SIZE 16         /* GCM authentication tag */
#define SALT_SIZE 16        /* PBKDF2 salt */
#define PBKDF2_ITERATIONS 100000
#define CACHE_MAGIC "LLNGCACHE02"   /* Version 02 = encrypted */
#define CACHE_MAGIC_V01 "LLNGCACHE01"  /* Version 01 = plaintext (for migration) */

/* SHA256 hash for cache keys - cryptographically secure (uses OpenSSL EVP API) */
static void hash_token(const char *token, const char *user, char *out, size_t out_size)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (!ctx) {
        if (out_size > 0) out[0] = '\0';
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, token, strlen(token)) != 1 ||
        EVP_DigestUpdate(ctx, ":", 1) != 1 ||
        EVP_DigestUpdate(ctx, user, strlen(user)) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        if (out_size > 0) out[0] = '\0';
        return;
    }

    EVP_MD_CTX_free(ctx);

    /* Convert to hex string (use first 16 bytes = 32 hex chars) */
    if (out_size >= 33 && hash_len >= 16) {
        for (int i = 0; i < 16; i++) {
            snprintf(out + (i * 2), 3, "%02x", hash[i]);
        }
        out[32] = '\0';
    } else if (out_size > 0) {
        out[0] = '\0';
    }

    /* Clear sensitive data */
    explicit_bzero(hash, sizeof(hash));
}

/* Cache structure */
struct token_cache {
    char *cache_dir;
    int default_ttl;
    bool encrypt;                       /* Enable encryption */
    unsigned char derived_key[KEY_SIZE]; /* AES-256 key derived from machine-id */
    bool key_derived;                    /* True if key was successfully derived */
};

/* Read machine-id */
static int read_machine_id(char *buf, size_t buf_size)
{
    FILE *f = fopen(MACHINE_ID_FILE, "r");
    if (!f) return -1;

    if (!fgets(buf, buf_size, f)) {
        fclose(f);
        return -1;
    }

    fclose(f);

    /* Remove trailing newline */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }

    return 0;
}

/* Derive encryption key from machine-id using PBKDF2 */
static int derive_cache_key(token_cache_t *cache)
{
    char machine_id[64] = {0};

    if (read_machine_id(machine_id, sizeof(machine_id)) != 0) {
        return -1;
    }

    /*
     * Derive a unique salt from machine-id for cache encryption.
     * Different from secret_store salt to use independent keys.
     */
    unsigned char pbkdf_salt[SALT_SIZE];
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    unsigned char salt_hash[EVP_MAX_MD_SIZE];
    unsigned int salt_hash_len = 0;

    if (!md_ctx ||
        EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, "pam_llng_cache_salt:", 20) != 1 ||
        EVP_DigestUpdate(md_ctx, machine_id, strlen(machine_id)) != 1 ||
        EVP_DigestFinal_ex(md_ctx, salt_hash, &salt_hash_len) != 1) {
        if (md_ctx) EVP_MD_CTX_free(md_ctx);
        explicit_bzero(machine_id, sizeof(machine_id));
        return -1;
    }
    EVP_MD_CTX_free(md_ctx);

    /* Use first SALT_SIZE bytes of hash as salt */
    memcpy(pbkdf_salt, salt_hash, SALT_SIZE);
    explicit_bzero(salt_hash, sizeof(salt_hash));

    /* Derive key using PBKDF2 */
    if (PKCS5_PBKDF2_HMAC(machine_id, strlen(machine_id),
                          pbkdf_salt, SALT_SIZE,
                          PBKDF2_ITERATIONS,
                          EVP_sha256(),
                          KEY_SIZE, cache->derived_key) != 1) {
        explicit_bzero(machine_id, sizeof(machine_id));
        explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));
        return -1;
    }

    explicit_bzero(machine_id, sizeof(machine_id));
    explicit_bzero(pbkdf_salt, sizeof(pbkdf_salt));

    cache->key_derived = true;
    return 0;
}

/* Encrypt cache data using AES-256-GCM */
static int encrypt_cache_data(token_cache_t *cache,
                              const unsigned char *plaintext,
                              size_t plaintext_len,
                              unsigned char **out,
                              size_t *out_len)
{
    if (!cache->key_derived) return -1;

    /* Generate random IV */
    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        return -1;
    }

    /* Allocate output: IV + ciphertext + tag */
    size_t out_size = IV_SIZE + plaintext_len + TAG_SIZE + 16;
    *out = malloc(out_size);
    if (!*out) return -1;

    /* Copy IV to output */
    memcpy(*out, iv, IV_SIZE);

    /* Encrypt */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*out);
        *out = NULL;
        return -1;
    }

    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, cache->derived_key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, *out + IV_SIZE, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, *out + IV_SIZE + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }
    ciphertext_len += len;

    /* Get authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE,
                            *out + IV_SIZE + ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    *out_len = IV_SIZE + ciphertext_len + TAG_SIZE;
    return 0;
}

/* Decrypt cache data using AES-256-GCM */
static int decrypt_cache_data(token_cache_t *cache,
                              const unsigned char *encrypted,
                              size_t encrypted_len,
                              unsigned char **out,
                              size_t *out_len)
{
    if (!cache->key_derived) return -1;

    /* Minimum size: IV + tag */
    if (encrypted_len < IV_SIZE + TAG_SIZE) {
        return -1;
    }

    /* Extract IV, ciphertext, and tag */
    const unsigned char *iv = encrypted;
    size_t ciphertext_len = encrypted_len - IV_SIZE - TAG_SIZE;
    const unsigned char *ciphertext = encrypted + IV_SIZE;
    const unsigned char *tag = encrypted + IV_SIZE + ciphertext_len;

    /* Allocate output */
    *out = malloc(ciphertext_len + 1);
    if (!*out) return -1;

    /* Decrypt */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(*out);
        *out = NULL;
        return -1;
    }

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, cache->derived_key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, *out, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }
    plaintext_len = len;

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*out);
        *out = NULL;
        return -1;
    }

    /* Finalize and verify tag */
    int ret = EVP_DecryptFinal_ex(ctx, *out + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        /* Authentication failed - data may be tampered */
        explicit_bzero(*out, ciphertext_len + 1);
        free(*out);
        *out = NULL;
        return -1;
    }

    plaintext_len += len;
    (*out)[plaintext_len] = '\0';
    *out_len = plaintext_len;
    return 0;
}

token_cache_t *cache_init_config(const cache_config_t *config)
{
    if (!config || !config->cache_dir) {
        return NULL;
    }

    token_cache_t *cache = calloc(1, sizeof(token_cache_t));
    if (!cache) {
        return NULL;
    }

    cache->cache_dir = strdup(config->cache_dir);
    cache->default_ttl = config->ttl > 0 ? config->ttl : 300;
    cache->encrypt = config->encrypt;

    /* Create cache directory if it doesn't exist */
    struct stat st;
    if (stat(config->cache_dir, &st) != 0) {
        if (mkdir(config->cache_dir, 0700) != 0 && errno != EEXIST) {
            free(cache->cache_dir);
            free(cache);
            return NULL;
        }
    }

    /* Derive encryption key if encryption is enabled */
    if (cache->encrypt) {
        if (derive_cache_key(cache) != 0) {
            /* Key derivation failed - continue without encryption */
            cache->encrypt = false;
            cache->key_derived = false;
        }
    }

    return cache;
}

token_cache_t *cache_init(const char *cache_dir, int ttl)
{
    /* Legacy init - encryption disabled for backward compatibility */
    cache_config_t config = {
        .cache_dir = cache_dir,
        .ttl = ttl,
        .encrypt = false
    };
    return cache_init_config(&config);
}

void cache_destroy(token_cache_t *cache)
{
    if (!cache) return;
    free(cache->cache_dir);
    /* Securely clear derived key */
    explicit_bzero(cache->derived_key, sizeof(cache->derived_key));
    explicit_bzero(cache, sizeof(*cache));
    free(cache);
}

/* Count entries in cache directory */
static int count_cache_entries(const char *cache_dir)
{
    DIR *dir = opendir(cache_dir);
    if (!dir) return 0;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".cache") != NULL) {
            count++;
        }
    }
    closedir(dir);
    return count;
}

/* Build cache file path */
static void build_cache_path(token_cache_t *cache,
                             const char *token,
                             const char *user,
                             char *path,
                             size_t path_size)
{
    char hash[64];  /* SHA256 truncated to first 16 bytes = 32 hex chars + null */
    hash_token(token, user, hash, sizeof(hash));
    snprintf(path, path_size, "%s/%s.cache", cache->cache_dir, hash);
}

bool cache_lookup(token_cache_t *cache,
                  const char *token,
                  const char *user,
                  cache_entry_t *entry)
{
    if (!cache || !token || !user || !entry) {
        return false;
    }

    memset(entry, 0, sizeof(*entry));

    char path[512];
    build_cache_path(cache, token, user, path, sizeof(path));

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }

    /* Get file size */
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size == 0) {
        close(fd);
        return false;
    }

    /* Read entire file */
    unsigned char *data = malloc(st.st_size + 1);
    if (!data) {
        close(fd);
        return false;
    }

    ssize_t bytes_read = read(fd, data, st.st_size);
    close(fd);

    if (bytes_read != st.st_size) {
        free(data);
        return false;
    }
    data[st.st_size] = '\0';

    char *line = NULL;
    size_t line_len = 0;

    /* Check if encrypted (starts with magic) */
    if (cache->encrypt && cache->key_derived &&
        (size_t)st.st_size > strlen(CACHE_MAGIC) &&
        memcmp(data, CACHE_MAGIC, strlen(CACHE_MAGIC)) == 0) {
        /* Encrypted cache file */
        unsigned char *decrypted = NULL;
        size_t decrypted_len = 0;

        size_t encrypted_offset = strlen(CACHE_MAGIC);
        if (decrypt_cache_data(cache,
                               data + encrypted_offset,
                               st.st_size - encrypted_offset,
                               &decrypted, &decrypted_len) != 0) {
            /* Decryption failed - remove potentially tampered file */
            explicit_bzero(data, st.st_size);
            free(data);
            unlink(path);
            return false;
        }

        explicit_bzero(data, st.st_size);
        free(data);
        line = (char *)decrypted;
        line_len = decrypted_len;
    } else {
        /* Plaintext cache file (legacy or encryption disabled) */
        line = (char *)data;
        line_len = st.st_size;
    }

    time_t expires_at;
    int authorized;
    char cached_user[256];

    if (sscanf(line, "%ld %d %255s", &expires_at, &authorized, cached_user) != 3) {
        /* Invalid format, remove the file */
        explicit_bzero(line, line_len);
        free(line);
        unlink(path);
        return false;
    }

    explicit_bzero(line, line_len);
    free(line);

    /* Check expiration */
    time_t now = time(NULL);
    if (now >= expires_at) {
        /* Expired, remove */
        unlink(path);
        return false;
    }

    /* Verify user matches */
    if (strcmp(cached_user, user) != 0) {
        return false;
    }

    entry->user = strdup(cached_user);
    entry->authorized = authorized != 0;
    entry->expires_at = expires_at;
    entry->cached_at = expires_at - cache->default_ttl;  /* Approximate */

    return true;
}

int cache_store(token_cache_t *cache,
                const char *token,
                const char *user,
                bool authorized,
                int ttl)
{
    if (!cache || !token || !user) {
        return -1;
    }

    /* Rate limiting: check if cache is full */
    int entry_count = count_cache_entries(cache->cache_dir);
    if (entry_count >= MAX_CACHE_ENTRIES) {
        /* Try to clean up expired entries first */
        cache_cleanup(cache);
        entry_count = count_cache_entries(cache->cache_dir);
        if (entry_count >= MAX_CACHE_ENTRIES) {
            /* Still full, refuse to add more entries */
            return -1;
        }
    }

    char path[512];
    build_cache_path(cache, token, user, path, sizeof(path));

    /* Build plaintext cache entry */
    time_t expires_at = time(NULL) + (ttl > 0 ? ttl : cache->default_ttl);
    char plaintext[1024];
    int plaintext_len = snprintf(plaintext, sizeof(plaintext),
                                  "%ld %d %s\n", expires_at, authorized ? 1 : 0, user);
    if (plaintext_len < 0 || plaintext_len >= (int)sizeof(plaintext)) {
        return -1;
    }

    /* Use atomic write: write to temp file then rename */
    char temp_path[520];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }

    int result = 0;

    if (cache->encrypt && cache->key_derived) {
        /* Encrypt the cache data */
        unsigned char *encrypted = NULL;
        size_t encrypted_len = 0;

        if (encrypt_cache_data(cache, (unsigned char *)plaintext, plaintext_len,
                               &encrypted, &encrypted_len) != 0) {
            close(fd);
            unlink(temp_path);
            return -1;
        }

        /* Write magic header + encrypted data */
        ssize_t written = write(fd, CACHE_MAGIC, strlen(CACHE_MAGIC));
        if (written == (ssize_t)strlen(CACHE_MAGIC)) {
            written = write(fd, encrypted, encrypted_len);
            if (written != (ssize_t)encrypted_len) {
                result = -1;
            }
        } else {
            result = -1;
        }

        explicit_bzero(encrypted, encrypted_len);
        free(encrypted);
    } else {
        /* Write plaintext */
        ssize_t written = write(fd, plaintext, plaintext_len);
        if (written != plaintext_len) {
            result = -1;
        }
    }

    close(fd);
    explicit_bzero(plaintext, sizeof(plaintext));

    if (result != 0) {
        unlink(temp_path);
        return -1;
    }

    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        return -1;
    }

    return 0;
}

/*
 * Helper to read and decrypt a cache file.
 * Returns decrypted/plaintext data in *out (caller must free).
 * Returns 0 on success, -1 on failure.
 */
static int read_cache_file(token_cache_t *cache, const char *path,
                           char **out, size_t *out_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size == 0) {
        close(fd);
        return -1;
    }

    unsigned char *data = malloc(st.st_size + 1);
    if (!data) {
        close(fd);
        return -1;
    }

    ssize_t bytes_read = read(fd, data, st.st_size);
    close(fd);

    if (bytes_read != st.st_size) {
        free(data);
        return -1;
    }
    data[st.st_size] = '\0';

    /* Check if encrypted */
    if (cache->encrypt && cache->key_derived &&
        (size_t)st.st_size > strlen(CACHE_MAGIC) &&
        memcmp(data, CACHE_MAGIC, strlen(CACHE_MAGIC)) == 0) {
        /* Decrypt */
        unsigned char *decrypted = NULL;
        size_t decrypted_len = 0;

        size_t encrypted_offset = strlen(CACHE_MAGIC);
        if (decrypt_cache_data(cache,
                               data + encrypted_offset,
                               st.st_size - encrypted_offset,
                               &decrypted, &decrypted_len) != 0) {
            explicit_bzero(data, st.st_size);
            free(data);
            return -1;
        }

        explicit_bzero(data, st.st_size);
        free(data);
        *out = (char *)decrypted;
        *out_len = decrypted_len;
    } else {
        /* Plaintext */
        *out = (char *)data;
        *out_len = st.st_size;
    }

    return 0;
}

void cache_invalidate(token_cache_t *cache, const char *token)
{
    if (!cache || !token) return;

    /* Since we hash with user, we need to scan directory */
    DIR *dir = opendir(cache->cache_dir);
    if (!dir) return;

    /* Hash the token part only for prefix matching isn't practical
     * with our hash scheme. For now, this is a no-op for single token.
     * Use cache_invalidate_user for user-based invalidation. */
    closedir(dir);
}

void cache_invalidate_user(token_cache_t *cache, const char *user)
{
    if (!cache || !user) return;

    DIR *dir = opendir(cache->cache_dir);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".cache") == NULL) {
            continue;
        }

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", cache->cache_dir, entry->d_name);

        char *data = NULL;
        size_t data_len = 0;
        if (read_cache_file(cache, path, &data, &data_len) != 0) {
            continue;
        }

        time_t expires_at;
        int authorized;
        char cached_user[256];

        if (sscanf(data, "%ld %d %255s", &expires_at, &authorized, cached_user) == 3) {
            if (strcmp(cached_user, user) == 0) {
                explicit_bzero(data, data_len);
                free(data);
                unlink(path);
                continue;
            }
        }

        explicit_bzero(data, data_len);
        free(data);
    }

    closedir(dir);
}

int cache_cleanup(token_cache_t *cache)
{
    if (!cache) return 0;

    DIR *dir = opendir(cache->cache_dir);
    if (!dir) return 0;

    int removed = 0;
    time_t now = time(NULL);
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, ".cache") == NULL) {
            continue;
        }

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", cache->cache_dir, entry->d_name);

        char *data = NULL;
        size_t data_len = 0;
        if (read_cache_file(cache, path, &data, &data_len) != 0) {
            /* Cannot read/decrypt - might be corrupted, remove it */
            unlink(path);
            removed++;
            continue;
        }

        time_t expires_at;
        if (sscanf(data, "%ld", &expires_at) == 1) {
            if (now >= expires_at) {
                explicit_bzero(data, data_len);
                free(data);
                unlink(path);
                removed++;
                continue;
            }
        }

        explicit_bzero(data, data_len);
        free(data);
    }

    closedir(dir);
    return removed;
}

void cache_entry_free(cache_entry_t *entry)
{
    if (!entry) return;
    free(entry->token_hash);
    free(entry->user);
    memset(entry, 0, sizeof(*entry));
}
