/*
 * jwt_utils.c - JWT generation utilities for OAuth2 client authentication
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "jwt_utils.h"

/* For unit testing, expose internal functions */
#ifdef JWT_UTILS_TEST
#define STATIC_OR_TEST
#else
#define STATIC_OR_TEST static
#endif

/* Security: Maximum base64 input size to prevent integer overflow (64KB) */
#define MAX_BASE64_INPUT_SIZE (64 * 1024)

/* Base64url encode (RFC 4648 section 5) */
STATIC_OR_TEST char *base64url_encode(const unsigned char *data, size_t len)
{
    /* Security: Validate input parameters */
    if (!data || len == 0) return NULL;

    /* Security: Prevent integer overflow and excessive allocation */
    if (len > MAX_BASE64_INPUT_SIZE) return NULL;

    static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char *out = malloc(out_len);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len; i += 3) {
        unsigned int val = data[i] << 16;
        if (i + 1 < len) val |= data[i + 1] << 8;
        if (i + 2 < len) val |= data[i + 2];

        out[j++] = b64_table[(val >> 18) & 0x3F];
        out[j++] = b64_table[(val >> 12) & 0x3F];
        if (i + 1 < len) out[j++] = b64_table[(val >> 6) & 0x3F];
        if (i + 2 < len) out[j++] = b64_table[val & 0x3F];
    }
    out[j] = '\0';

    return out;
}

/* Generate a UUID v4 for JWT jti claim */
STATIC_OR_TEST char *generate_uuid(void)
{
    unsigned char uuid_bytes[16];
    if (RAND_bytes(uuid_bytes, sizeof(uuid_bytes)) != 1) {
        return NULL;
    }

    /* Set version 4 (random) */
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x40;
    /* Set variant (RFC 4122) */
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;

    char *uuid = malloc(37);
    if (!uuid) return NULL;

    snprintf(uuid, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
             uuid_bytes[4], uuid_bytes[5],
             uuid_bytes[6], uuid_bytes[7],
             uuid_bytes[8], uuid_bytes[9],
             uuid_bytes[10], uuid_bytes[11], uuid_bytes[12], uuid_bytes[13],
             uuid_bytes[14], uuid_bytes[15]);

    return uuid;
}

/*
 * Generate client_secret_jwt assertion (RFC 7523)
 * Returns dynamically allocated JWT string or NULL on error
 * Caller must free the result
 */
char *generate_client_jwt(const char *client_id, const char *client_secret,
                          const char *audience)
{
    if (!client_id || !client_secret || !audience) {
        return NULL;
    }

    /* Generate UUID for jti */
    char *jti = generate_uuid();
    if (!jti) return NULL;

    time_t now = time(NULL);
    time_t exp = now + 300;  /* 5 minute expiry */

    /* Build header: {"alg":"HS256","typ":"JWT"} */
    const char *header_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char *header_b64 = base64url_encode((const unsigned char *)header_json,
                                         strlen(header_json));
    if (!header_b64) {
        free(jti);
        return NULL;
    }

    /* Build payload using json-c to properly escape strings */
    struct json_object *payload_obj = json_object_new_object();
    if (!payload_obj) {
        free(jti);
        free(header_b64);
        return NULL;
    }

    json_object_object_add(payload_obj, "iss", json_object_new_string(client_id));
    json_object_object_add(payload_obj, "sub", json_object_new_string(client_id));
    json_object_object_add(payload_obj, "aud", json_object_new_string(audience));
    json_object_object_add(payload_obj, "exp", json_object_new_int64((int64_t)exp));
    json_object_object_add(payload_obj, "iat", json_object_new_int64((int64_t)now));
    json_object_object_add(payload_obj, "jti", json_object_new_string(jti));

    free(jti);

    const char *payload_json = json_object_to_json_string_ext(payload_obj,
                                                               JSON_C_TO_STRING_PLAIN);
    if (!payload_json) {
        json_object_put(payload_obj);
        free(header_b64);
        return NULL;
    }

    char *payload_b64 = base64url_encode((const unsigned char *)payload_json,
                                          strlen(payload_json));
    json_object_put(payload_obj);

    if (!payload_b64) {
        free(header_b64);
        return NULL;
    }

    /* Build signing input: header.payload */
    size_t signing_input_len = strlen(header_b64) + 1 + strlen(payload_b64) + 1;
    char *signing_input = malloc(signing_input_len);
    if (!signing_input) {
        free(header_b64);
        free(payload_b64);
        return NULL;
    }
    snprintf(signing_input, signing_input_len, "%s.%s", header_b64, payload_b64);

    /* Sign with HMAC-SHA256 */
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;

    unsigned char *result = HMAC(EVP_sha256(),
                                  client_secret, strlen(client_secret),
                                  (const unsigned char *)signing_input, strlen(signing_input),
                                  hmac_result, &hmac_len);

    if (!result) {
        free(header_b64);
        free(payload_b64);
        explicit_bzero(signing_input, signing_input_len);
        free(signing_input);
        return NULL;
    }

    /* Base64url encode signature */
    char *sig_b64 = base64url_encode(hmac_result, hmac_len);
    explicit_bzero(hmac_result, sizeof(hmac_result));

    if (!sig_b64) {
        free(header_b64);
        free(payload_b64);
        explicit_bzero(signing_input, signing_input_len);
        free(signing_input);
        return NULL;
    }

    /* Build final JWT: header.payload.signature */
    size_t jwt_len = strlen(signing_input) + 1 + strlen(sig_b64) + 1;
    char *jwt = malloc(jwt_len);
    if (!jwt) {
        free(header_b64);
        free(payload_b64);
        explicit_bzero(signing_input, signing_input_len);
        free(signing_input);
        free(sig_b64);
        return NULL;
    }
    snprintf(jwt, jwt_len, "%s.%s", signing_input, sig_b64);

    free(header_b64);
    free(payload_b64);
    explicit_bzero(signing_input, signing_input_len);
    free(signing_input);
    free(sig_b64);

    return jwt;
}
