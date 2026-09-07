/*
 * ob-sign-request - print the request-signing headers for a /pam/<endpoint> call
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 *
 * ob-heartbeat and ob-bastion-id are shell, and the portal's
 * pamAccessRequestSigningMode=required covers the endpoints they call (#247).
 * This is how they sign.
 *
 * Why a helper and not `openssl dgst -sha256 -hmac "$secret"`:
 *
 *   - openssl takes the HMAC key on the command line, and there is no form
 *     that takes it from a file or the environment. argv is world-readable
 *     through /proc/<pid>/cmdline, so every ob-heartbeat run -- every few
 *     minutes, forever, on a host whose whole purpose is to give other people
 *     a shell -- would publish the fleet-wide signing secret to anyone who
 *     polls. A secret an attacker can read is a signature an attacker can
 *     forge, which is the entire value of the mechanism.
 *   - the body is signed too, and ob-heartbeat's body carries the host's
 *     refresh_token. Passing it as an argument would leak that as well.
 *
 * So the secret never leaves this process (it is read here, from a file only
 * root can read), the body arrives on stdin, and what goes to stdout is the
 * MAC and its inputs -- which are safe to publish, and are about to be sent
 * over the wire anyway.
 *
 * Usage:
 *     ob-sign-request --method POST --path /pam/heartbeat [--config FILE] < body
 *
 * Exit status:
 *     0  the three headers were printed, one per line
 *     3  no request_signing_secret is configured: nothing to sign, and the
 *        caller should send the request unsigned (the portal's 'off' and
 *        'optional' modes accept it; 'required' will refuse it, which is the
 *        deployment's own choice to make)
 *     1  anything else, with a diagnostic on stderr
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "ob_sign.h"

#define DEFAULT_CONFIG "/etc/open-bastion/openbastion.conf"

/* Bounded so a runaway producer on stdin cannot exhaust memory here. The
 * largest real body is ob-heartbeat's session report, orders below this. */
#define MAX_BODY (1024 * 1024)

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: ob-sign-request --method METHOD --path /pam/... [--config FILE]\n"
        "\n"
        "Reads the request body on stdin and prints the X-Timestamp, X-Nonce\n"
        "and X-Signature-256 headers for it, one per line.\n"
        "Exit 3 means no request_signing_secret is configured.\n");
}

/*
 * The portal signs uc($req->method) and the path with its query string
 * removed. Refusing anything else here keeps a caller from producing a
 * signature the portal can only compute differently -- which would fail as
 * 'bad_signature', indistinguishable from a wrong secret.
 */
static int valid_method(const char *m)
{
    if (!m || !*m || strlen(m) > 16) return 0;
    for (const char *p = m; *p; p++) {
        if (*p < 'A' || *p > 'Z') return 0;
    }
    return 1;
}

static int valid_path(const char *p)
{
    if (!p || *p != '/' || strlen(p) > 512) return 0;
    for (const char *q = p; *q; q++) {
        if (*q == '?' || *q == '#') return 0;          /* not part of the signed path */
        if (isspace((unsigned char)*q)) return 0;
        if ((unsigned char)*q < 32 || (unsigned char)*q == 127) return 0;
    }
    return 1;
}

/* Read all of stdin. Returns NULL on error, sets *len on success. */
static char *read_body(size_t *len)
{
    size_t cap = 8192, used = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;

    for (;;) {
        if (used == cap) {
            if (cap >= MAX_BODY) {
                fprintf(stderr, "ob-sign-request: body larger than %d bytes\n", MAX_BODY);
                free(buf);
                return NULL;
            }
            size_t ncap = cap * 2;
            if (ncap > MAX_BODY) ncap = MAX_BODY;
            char *nbuf = realloc(buf, ncap);
            if (!nbuf) {
                free(buf);
                return NULL;
            }
            buf = nbuf;
            cap = ncap;
        }
        size_t n = fread(buf + used, 1, cap - used, stdin);
        used += n;
        if (n == 0) {
            if (ferror(stdin)) {
                fprintf(stderr, "ob-sign-request: read error on stdin: %s\n",
                        strerror(errno));
                free(buf);
                return NULL;
            }
            break;  /* EOF */
        }
    }

    /*
     * The body is signed as raw bytes, but it reaches us through a shell
     * pipeline. A NUL would already have been lost on the way in, and would
     * truncate the message here; say so instead of signing a prefix.
     */
    if (memchr(buf, '\0', used)) {
        fprintf(stderr, "ob-sign-request: body contains a NUL byte\n");
        free(buf);
        return NULL;
    }

    /* The loop grows the buffer before every fread, so used < cap here and
     * there is always room for the terminator. */
    buf[used] = '\0';
    *len = used;
    return buf;
}

int main(int argc, char **argv)
{
    const char *method = NULL, *path = NULL, *conf = DEFAULT_CONFIG;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--method") == 0 && i + 1 < argc) {
            method = argv[++i];
        } else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            conf = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else {
            fprintf(stderr, "ob-sign-request: unexpected argument '%s'\n", argv[i]);
            usage(stderr);
            return 1;
        }
    }

    if (!valid_method(method)) {
        fprintf(stderr, "ob-sign-request: --method must be an uppercase HTTP method\n");
        return 1;
    }
    if (!valid_path(path)) {
        fprintf(stderr, "ob-sign-request: --path must be an absolute path with no "
                        "query string\n");
        return 1;
    }

    char *secret = NULL;
    int rc = ob_sign_load_secret(conf, &secret);
    if (rc < 0) {
        fprintf(stderr, "ob-sign-request: cannot read the signing secret from %s "
                        "(must be a regular file, owned by root, mode 0600)\n", conf);
        return 1;
    }
    if (rc > 0) {
        return 3;  /* nothing configured: the caller sends the request unsigned */
    }

    size_t body_len = 0;
    char *body = read_body(&body_len);
    if (!body) {
        explicit_bzero(secret, strlen(secret));
        free(secret);
        return 1;
    }

    long timestamp = (long)time(NULL);

    char nonce[OB_SIGN_NONCE_SIZE];
    ob_sign_generate_nonce(nonce, sizeof(nonce));

    char signature[OB_SIGN_SIGNATURE_SIZE];
    ob_sign_compute(secret, timestamp, nonce, method, path, body,
                    signature, sizeof(signature));

    explicit_bzero(secret, strlen(secret));
    free(secret);
    explicit_bzero(body, body_len);
    free(body);

    if (!*nonce || !*signature) {
        fprintf(stderr, "ob-sign-request: signing failed\n");
        return 1;
    }

    printf("X-Timestamp: %ld\n", timestamp);
    printf("X-Nonce: %s\n", nonce);
    printf("X-Signature-256: sha256=%s\n", signature);

    if (fflush(stdout) != 0) {
        fprintf(stderr, "ob-sign-request: cannot write headers: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}
