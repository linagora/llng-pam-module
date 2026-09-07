/*
 * ob-client-jwt - print a client_secret_jwt assertion, with the secret off argv
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 *
 * ob-enroll authenticates to the OIDC token endpoint with a client_secret_jwt
 * assertion (RFC 7523). It used to build that assertion in shell:
 *
 *     openssl dgst -sha256 -hmac "$client_secret" -binary
 *
 * openssl takes the HMAC key as a command-line argument and offers no form
 * that reads it from a file, a descriptor or the environment. argv is
 * world-readable through /proc/<pid>/cmdline, so for the lifetime of that
 * process the host's OIDC client secret was readable by any local user -- the
 * same defect #247 fixed for the /pam/ request-signing secret, and the same
 * reason ob-sign-request exists.
 *
 * It was not a single one-shot exposure. The call sits inside the device-grant
 * polling loop: one assertion every POLL_INTERVAL seconds for up to the
 * device-code lifetime, of the order of sixty times over five minutes --
 * during exactly the interval when a human has been sent to a browser to
 * approve the grant, which is when someone else is most likely to be sitting
 * on that host.
 *
 * Where the secret comes from
 * ---------------------------
 * ob-sign-request reads its secret from openbastion.conf, and that is right
 * for it: the request-signing secret is only ever configured there. This
 * helper deliberately does NOT do that, because ob-enroll may hold the client
 * secret from any of three places -- OB_CLIENT_SECRET in the environment,
 * --client-secret on the command line, or client_secret in a configuration
 * file that on a first enrolment does not exist yet.
 *
 * Re-deriving that here would mean reimplementing ob-enroll's precedence and
 * getting it to agree, forever. So this helper does not decide: ob-enroll
 * already knows which secret it is using, and hands it over on stdin. A pipe
 * has no /proc entry and no name in the filesystem; nothing but the two
 * processes can see it.
 *
 * The signing itself is the C generate_client_jwt() that pam_openbastion
 * already uses (src/jwt_utils.c, via token_manager.c and ob_client.c), so the
 * shell stops carrying a second implementation of the same assertion.
 *
 * Usage:
 *     ob-client-jwt --client-id ID --audience URL < secret
 *
 * --client-id and --audience are public: both are echoed verbatim in the
 * assertion's own payload, which is base64url of plaintext and goes on the
 * wire. Only the key must be kept off argv.
 *
 * Exit status:
 *     0  the assertion was printed on stdout
 *     1  signing failed, or the secret could not be read
 *     2  usage error
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jwt_utils.h"

/*
 * An OIDC client secret is a password-shaped string. This is far above any
 * real one and still bounds a runaway producer on stdin.
 */
#define MAX_SECRET 4096

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: ob-client-jwt --client-id ID --audience URL < secret\n"
        "\n"
        "Reads the OIDC client secret on stdin and prints a client_secret_jwt\n"
        "assertion (RFC 7523) for it on stdout.\n"
        "The secret is never placed on a command line.\n");
}

/*
 * Read the secret from stdin. It is one line: every trailing CR and LF is
 * stripped, so `printf '%s'`, `echo` and a secret read from a CRLF file all
 * produce the same key. Nothing else is stripped -- leading and interior
 * spaces are part of the secret, and some issuers do generate them.
 */
static char *read_secret(size_t *len_out)
{
    char *buf = malloc(MAX_SECRET + 1);
    if (!buf) return NULL;

    size_t used = 0;
    for (;;) {
        ssize_t r = read(STDIN_FILENO, buf + used, MAX_SECRET - used);
        if (r < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "ob-client-jwt: read error on stdin: %s\n", strerror(errno));
            explicit_bzero(buf, MAX_SECRET);
            free(buf);
            return NULL;
        }
        if (r == 0) break;                      /* EOF */
        used += (size_t)r;
        if (used == MAX_SECRET) {
            /* Distinguish "exactly full" from "truncated": one more read. */
            char probe;
            ssize_t extra;
            do {
                extra = read(STDIN_FILENO, &probe, 1);
            } while (extra < 0 && errno == EINTR);
            if (extra > 0) {
                explicit_bzero(&probe, sizeof(probe));
                fprintf(stderr, "ob-client-jwt: secret larger than %d bytes\n", MAX_SECRET);
                explicit_bzero(buf, MAX_SECRET);
                free(buf);
                return NULL;
            }
            break;
        }
    }

    while (used > 0 && (buf[used - 1] == '\n' || buf[used - 1] == '\r')) {
        used--;
    }
    buf[used] = '\0';

    if (used == 0) {
        fprintf(stderr, "ob-client-jwt: empty secret on stdin\n");
        explicit_bzero(buf, MAX_SECRET);
        free(buf);
        return NULL;
    }

    /*
     * generate_client_jwt() keys the HMAC with strlen(), so a NUL would
     * silently shorten the key and produce an assertion the portal computes
     * differently -- a signature failure with no visible cause. Refuse it.
     */
    if (strlen(buf) != used) {
        fprintf(stderr, "ob-client-jwt: secret contains a NUL byte\n");
        explicit_bzero(buf, MAX_SECRET);
        free(buf);
        return NULL;
    }

    *len_out = used;
    return buf;
}

int main(int argc, char **argv)
{
    const char *client_id = NULL, *audience = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--client-id") == 0 && i + 1 < argc) {
            client_id = argv[++i];
        } else if (strcmp(argv[i], "--audience") == 0 && i + 1 < argc) {
            audience = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else {
            fprintf(stderr, "ob-client-jwt: unexpected argument '%s'\n", argv[i]);
            usage(stderr);
            return 2;
        }
    }

    if (!client_id || !*client_id) {
        fprintf(stderr, "ob-client-jwt: --client-id is required\n");
        usage(stderr);
        return 2;
    }
    if (!audience || !*audience) {
        fprintf(stderr, "ob-client-jwt: --audience is required\n");
        usage(stderr);
        return 2;
    }

    size_t secret_len = 0;
    char *secret = read_secret(&secret_len);
    if (!secret) return 1;

    char *jwt = generate_client_jwt(client_id, secret, audience);

    explicit_bzero(secret, MAX_SECRET);
    free(secret);

    if (!jwt) {
        fprintf(stderr, "ob-client-jwt: could not build the assertion\n");
        return 1;
    }

    printf("%s\n", jwt);
    free(jwt);

    if (fflush(stdout) != 0) {
        fprintf(stderr, "ob-client-jwt: cannot write the assertion: %s\n", strerror(errno));
        return 1;
    }

    return 0;
}
