/*
 * sshd_anchor.c - the single implementation of the sshd anchor walk.
 *
 * Copyright (C) 2025 Linagora
 * License: AGPL-3.0
 *
 * See include/sshd_anchor.h for what the anchor is and why writer and reader
 * must agree on it. This file exists so that "must agree" is a property of the
 * program rather than of two comments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "sshd_anchor.h"

/* Longest path we build: <proc_root>/<pid>/status. */
#define ANCHOR_PATH_MAX 512

/* Read the first line of `path` into `out`, newline stripped. 0 on success. */
static int read_first_line(const char *path, char *out, size_t out_sz)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out, (int)out_sz, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
    return 0;
}

/* PPid from <proc_root>/<pid>/status, or 0 when it cannot be read. */
static pid_t read_ppid(const char *proc_root, pid_t pid)
{
    char path[ANCHOR_PATH_MAX], line[256];
    int n = snprintf(path, sizeof(path), "%s/%d/status", proc_root, (int)pid);
    if (n < 0 || n >= (int)sizeof(path)) return 0;

    FILE *f = fopen(path, "r");
    if (!f) return 0;
    pid_t ppid = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            ppid = (pid_t)strtol(line + 5, NULL, 10);
            break;
        }
    }
    fclose(f);
    return ppid;
}

pid_t ob_find_sshd_anchor_in(const char *proc_root, pid_t pid)
{
    pid_t outermost = 0;  /* outermost contiguous sshd-session seen so far */

    /*
     * pid 1 is never an anchor and has no parent worth following, so it also
     * terminates the walk.
     */
    for (int i = 0; i < OB_SSHD_ANCHOR_MAX_DEPTH && pid > 1; i++) {
        char path[ANCHOR_PATH_MAX], comm[256];
        int n = snprintf(path, sizeof(path), "%s/%d/comm", proc_root, (int)pid);
        if (n < 0 || n >= (int)sizeof(path)) return outermost;
        if (read_first_line(path, comm, sizeof(comm)) != 0) return outermost;

        if (strcmp(comm, "sshd-session") == 0) {
            outermost = pid;         /* keep climbing: a parent one outranks it */
        } else if (outermost) {
            return outermost;        /* left the chain: the monitor is behind us */
        } else if (strcmp(comm, "sshd") == 0) {
            return pid;              /* pre-split OpenSSH */
        }

        pid_t ppid = read_ppid(proc_root, pid);
        /*
         * A parent that is its own child cannot happen on a live tree, but a
         * corrupt or synthetic one would loop here until the depth limit; stop
         * on it explicitly so the walk is bounded by the tree, not by luck.
         */
        if (ppid <= 0 || ppid == pid) return outermost;
        pid = ppid;
    }
    return outermost;
}

pid_t ob_find_sshd_anchor(pid_t pid)
{
    return ob_find_sshd_anchor_in("/proc", pid);
}
