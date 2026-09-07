/*
 * ob-fp-submit - hand an SSH key fingerprint to ob-fp-daemon (#249).
 *
 * The unprivileged half of the fingerprint spool, in the same shape as
 * ob-cert-request is for ob-cert-daemon (#145): the AuthorizedPrincipalsCommand
 * helper runs as nobody and can no longer write the spool itself, so it pipes
 * the fingerprint here and this connects to /run/open-bastion/ssh-fp.sock.
 *
 * There is deliberately nothing to configure and no identity to assert. The
 * daemon takes the depositing uid from SO_PEERCRED and derives the sshd anchor
 * from this process's own /proc ancestry, so a caller cannot name the session
 * it is writing for -- see the header of ob-fp-daemon.c. That is why running
 * this binary is harmless and it needs no setuid bit and no privilege.
 *
 * Usage:  ob-fp-submit  < request
 *   line 1: fingerprint   "SHA256:<base64>"
 *   line 2: key algorithm (sshd's %t, may be empty)
 *   line 3: key blob      (sshd's %k, may be empty)
 *
 * Exit: 0 on "OK", 1 if the daemon refused or is unreachable, 2 on usage or
 * local error. The caller treats every non-zero the same way -- the login
 * proceeds without a fingerprint binding, which pam_openbastion already
 * reports (#192). Losing the binding must never fail an authentication that
 * would otherwise succeed; it only removes an additional check.
 *
 * Copyright (C) 2026 Linagora
 * License: AGPL-3.0
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef OB_FP_SOCKET
#define OB_FP_SOCKET "/run/open-bastion/ssh-fp.sock"
#endif

#define OB_FP_REQ_MAX 20480

int main(int argc, char **argv)
{
    const char *sock_path = OB_FP_SOCKET;

    /*
     * The socket path is overridable for the test suite only. It is not a
     * documented option: on a real host the daemon's socket is the one systemd
     * created, and pointing this elsewhere just means no drop is written.
     */
    const char *env = getenv("OB_FP_SOCKET");
    if (env && *env) sock_path = env;

    if (argc > 1) {
        fprintf(stderr, "usage: %s < request  (three lines on stdin)\n", argv[0]);
        return 2;
    }

    char req[OB_FP_REQ_MAX + 1];
    size_t used = 0;
    for (;;) {
        ssize_t r = read(STDIN_FILENO, req + used, sizeof(req) - 1 - used);
        if (r < 0) {
            fprintf(stderr, "[ob-fp-submit] read: %s\n", strerror(errno));
            return 2;
        }
        if (r == 0) break;
        used += (size_t)r;
        if (used >= sizeof(req) - 1) {
            fprintf(stderr, "[ob-fp-submit] request too large\n");
            return 2;
        }
    }
    if (used == 0) {
        fprintf(stderr, "[ob-fp-submit] empty request\n");
        return 2;
    }

    struct sockaddr_un addr;
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "[ob-fp-submit] socket path too long: %s\n", sock_path);
        return 2;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[ob-fp-submit] socket(): %s\n", strerror(errno));
        return 2;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr,
                "[ob-fp-submit] cannot reach the fingerprint sink at %s: %s\n",
                sock_path, strerror(errno));
        fprintf(stderr,
                "[ob-fp-submit] is ob-fp.socket enabled? (re-run ob-bastion-setup)\n");
        close(fd);
        return 1;
    }

    size_t off = 0;
    while (off < used) {
        ssize_t w = write(fd, req + off, used - off);
        if (w <= 0) {
            fprintf(stderr, "[ob-fp-submit] send: %s\n", strerror(errno));
            close(fd);
            return 1;
        }
        off += (size_t)w;
    }
    /* Half-close so the daemon sees EOF and answers. */
    if (shutdown(fd, SHUT_WR) < 0) {
        fprintf(stderr, "[ob-fp-submit] shutdown(): %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    char resp[256];
    ssize_t n = read(fd, resp, sizeof(resp) - 1);
    close(fd);
    if (n <= 0) {
        fprintf(stderr, "[ob-fp-submit] no answer from the fingerprint sink\n");
        return 1;
    }
    resp[n] = '\0';

    if (strncmp(resp, "OK", 2) == 0) return 0;

    /* Pass the daemon's reason through: it is the only diagnostic the admin
     * gets, and sshd sends this stderr to the auth log. */
    fprintf(stderr, "[ob-fp-submit] %s", resp);
    return 1;
}
