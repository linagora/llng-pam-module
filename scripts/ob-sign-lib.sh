# shellcheck shell=bash
#
# ob-sign-lib.sh - request signing for the shell callers of /pam/ endpoints
#
# Copyright (C) 2025 Linagora
# License: AGPL-3.0
#
# Sourced by ob-heartbeat, ob-bastion-id, ob-enroll and ob-session-monitor.
# The portal verifies X-Signature-256 on every /pam/ endpoint it serves, and
# pamAccessRequestSigningMode=required refuses anything unsigned (#247).
#
# The HMAC is computed by ob-sign-request, never here. The obvious one-liner,
#
#     openssl dgst -sha256 -hmac "$secret"
#
# is not usable: openssl takes the key on the command line and offers no form
# that reads it from a file or the environment, /proc/<pid>/cmdline is
# world-readable, and these scripts run as root on a host whose whole purpose
# is to give other people a shell -- ob-heartbeat every few minutes, forever.
# It would publish the fleet-wide signing secret to anyone who polls, and a
# secret an attacker can read is a signature an attacker can forge. Some of the
# signed bodies also carry credentials of their own (ob-heartbeat's carries
# this host's refresh_token), which is why the body goes to the helper on
# stdin rather than in an argument.
#
# Interface:
#
#   ob_sign_request METHOD PATH BODY
#       Sets SIGN_HEADERS to the curl arguments to add ("-H" "X-...": possibly
#       none). Returns 0 when the request may be sent, non-zero when signing
#       was configured and failed -- sending unsigned then would be a silent
#       downgrade, and the portal refuses a partially signed request in every
#       mode. On failure the reason is in OB_SIGN_ERROR.
#
# The caller sets OB_SIGN_CONFIG to the openbastion.conf to read; it defaults
# to the standard path.

SIGN_HEADERS=()
OB_SIGN_ERROR=""
OB_SIGN_NOTE=""

ob_sign_request() {
    local method="$1" path="$2" payload="$3"
    local helper out line rc=0
    local conf="${OB_SIGN_CONFIG:-/etc/open-bastion/openbastion.conf}"

    SIGN_HEADERS=()
    OB_SIGN_ERROR=""
    OB_SIGN_NOTE=""

    helper="${OB_SIGN_REQUEST:-}"
    if [ -z "$helper" ]; then
        helper=$(command -v ob-sign-request 2>/dev/null) \
            || helper="/usr/sbin/ob-sign-request"
    fi
    if [ ! -x "$helper" ]; then
        # Running from a source checkout, where the binary is in the build
        # tree and not on PATH. Not a reason to stop: unsigned is what these
        # scripts did before #247, and a portal in `required` refuses it
        # visibly rather than silently.
        OB_SIGN_NOTE="ob-sign-request not found; sending $path unsigned"
        return 0
    fi

    out=$(printf '%s' "$payload" \
        | "$helper" --method "$method" --path "$path" --config "$conf" 2>&1) || rc=$?
    case "$rc" in
        0) ;;
        3) return 0 ;;   # no request_signing_secret configured: nothing to sign
        *) OB_SIGN_ERROR="cannot sign $path: $out"; return 1 ;;
    esac

    while IFS= read -r line; do
        [ -n "$line" ] && SIGN_HEADERS+=("-H" "$line")
    done <<< "$out"
    return 0
}
