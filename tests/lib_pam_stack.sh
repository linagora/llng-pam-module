#!/bin/bash
# Shared assertions for the PAM stacks Open Bastion generates (issue #180).
#
# The bug: a certificate-mode auth stack whose only line is
#
#   auth       required     pam_permit.so
#
# makes pam_authenticate() return PAM_SUCCESS unconditionally. sshd does not
# call pam_authenticate() on the pubkey/certificate path, but it DOES call it
# for password and keyboard-interactive authentication: on a host where those
# are still enabled (the distro default, and what `apt install open-bastion`
# leaves behind because the postinst never touches sshd_config), any password
# then authenticated any account the account phase approved.
#
# Two shapes replace it, and they are NOT interchangeable:
#
#   1. Deny (sshd, certificate modes) — one line:
#
#        auth       required     pam_deny.so
#
#      pam_authenticate() returns PAM_AUTH_ERR. This is the honest "this stack
#      does not authenticate anybody"; the certificate path is unaffected
#      because sshd never runs it.
#
#   2. Canonical fail-closed permit (sudo in mode-c, where the documented
#      behaviour is passwordless sudo) — three lines:
#
#        auth       [success=1 default=ignore] pam_permit.so
#        auth       required     pam_deny.so
#        auth       required     pam_permit.so
#
#      pam_permit succeeds, success=1 skips exactly one module (pam_deny) and
#      lands on the trailing pam_permit, which records the success. If
#      pam_permit is missing or errors, default=ignore falls through to
#      pam_deny and the stack refuses.
#
# The TRAILING pam_permit is mandatory. Dropping it — leaving just the jump and
# the pam_deny — inverts the meaning: per pam.conf(5) the jump action's side
# effect is *ignore* for pam_authenticate/pam_acct_mgmt/pam_chauthtok/
# pam_open_session, so the jump clears pam_deny, lands past the end of the
# stack with no positive impression recorded, and pam_dispatch returns
# PAM_MUST_FAIL_CODE (PAM_PERM_DENIED). Measured on libpam 1.7.0-8:
# the pair alone -> 6 (Permission denied); the three-line form -> 0 (Success).
# tests/test_ob_pam_runtime.sh proves both by calling pam_authenticate().
#
# These helpers expect the caller to provide pass() and fail() (all the
# tests/test_*.sh harnesses define them).

PAM_ASSERT_ERR=""
PAM_AUTH_LINES=()

# Read a generated stack (or a whole file) on stdin, emit only its normalized
# "auth" lines: Dockerfile "\n\" line continuations and leading whitespace are
# stripped.
pam_auth_lines() {
    sed -e 's/\\n\\[[:space:]]*$//' \
        -e 's/^[[:space:]]*//' | grep -E '^auth[[:space:]]' || true
}

# _pam_read_auth_lines <content> — fills PAM_AUTH_LINES.
_pam_read_auth_lines() {
    local content="$1" line
    PAM_AUTH_LINES=()
    while IFS= read -r line; do
        [ -n "$line" ] && PAM_AUTH_LINES+=("$line")
    done <<<"$(printf '%s\n' "$content" | pam_auth_lines)"
}

_pam_is_permit_jump() {
    case "$1" in auth*"[success=1 default=ignore]"*pam_permit.so*) return 0 ;; esac
    return 1
}

_pam_is_required_deny() {
    case "$1" in auth*required*pam_deny.so*) return 0 ;; esac
    return 1
}

_pam_is_required_permit() {
    case "$1" in auth*required*pam_permit.so*) return 0 ;; esac
    return 1
}

# _pam_check_permit <content> — silent core, sets PAM_ASSERT_ERR on failure.
# Works on a single stack or on a whole file holding several stacks: the ONLY
# way pam_permit may appear on an auth path is as the canonical three-line
# fail-closed permit above. Anything else — a bare "required pam_permit", a
# jump with no trailing permit, a jump whose backstop is not the very next
# line — is rejected.
_pam_check_permit() {
    PAM_ASSERT_ERR=""
    _pam_read_auth_lines "$1"

    if [ "${#PAM_AUTH_LINES[@]}" -eq 0 ]; then
        PAM_ASSERT_ERR="no auth line found in: $1"
        return 1
    fi

    local i n skip=0
    n=${#PAM_AUTH_LINES[@]}
    for ((i = 0; i < n; i++)); do
        if [ "$skip" -gt 0 ]; then
            skip=$((skip - 1))
            continue
        fi
        case "${PAM_AUTH_LINES[i]}" in
            *pam_permit.so*) ;;
            *) continue ;;
        esac
        if ! _pam_is_permit_jump "${PAM_AUTH_LINES[i]}"; then
            PAM_ASSERT_ERR="pam_permit on the auth path is not the canonical [success=1 default=ignore] jump: ${PAM_AUTH_LINES[i]}"
            return 1
        fi
        if ! _pam_is_required_deny "${PAM_AUTH_LINES[i + 1]:-}"; then
            PAM_ASSERT_ERR="success=1 skips exactly one module, so 'auth required pam_deny.so' must be the next auth line, got: ${PAM_AUTH_LINES[i + 1]:-<end of stack>}"
            return 1
        fi
        if ! _pam_is_required_permit "${PAM_AUTH_LINES[i + 2]:-}"; then
            PAM_ASSERT_ERR="the jump lands past pam_deny, so 'auth required pam_permit.so' must follow it or the stack returns PAM_PERM_DENIED; got: ${PAM_AUTH_LINES[i + 2]:-<end of stack>}"
            return 1
        fi
        skip=2
    done
    return 0
}

# assert_no_open_permit <label> <content> — for whole files / multi-stack input.
assert_no_open_permit() {
    if _pam_check_permit "$2"; then
        pass "$1"
        return 0
    fi
    fail "$1" "$PAM_ASSERT_ERR"
    return 1
}

# assert_auth_stack_denies <label> <single stack content>
# The stack must refuse pam_authenticate(): no pam_permit anywhere on the auth
# path, and the last auth line must be a module that actually denies.
assert_auth_stack_denies() {
    _pam_read_auth_lines "$2"
    if [ "${#PAM_AUTH_LINES[@]}" -eq 0 ]; then
        fail "$1" "no auth line found"
        return 1
    fi
    local line
    for line in "${PAM_AUTH_LINES[@]}"; do
        case "$line" in
            *pam_permit.so*)
                fail "$1" "a denying auth stack must not contain pam_permit: $line"
                return 1
                ;;
        esac
    done
    local last="${PAM_AUTH_LINES[${#PAM_AUTH_LINES[@]} - 1]}"
    case "$last" in
        auth*required*|auth*requisite*) ;;
        *)
            fail "$1" "auth stack ends on a non-denying line: $last"
            return 1
            ;;
    esac
    pass "$1"
    return 0
}

# assert_auth_stack_permits <label> <single stack content>
# The stack must succeed on the intended path while still refusing to fall
# through if pam_permit is unavailable: exactly the canonical three-line form.
assert_auth_stack_permits() {
    _pam_read_auth_lines "$2"
    if [ "${#PAM_AUTH_LINES[@]}" -ne 3 ]; then
        fail "$1" "expected the 3-line fail-closed permit, got ${#PAM_AUTH_LINES[@]} auth line(s): ${PAM_AUTH_LINES[*]:-<none>}"
        return 1
    fi
    if _pam_is_permit_jump "${PAM_AUTH_LINES[0]}" &&
        _pam_is_required_deny "${PAM_AUTH_LINES[1]}" &&
        _pam_is_required_permit "${PAM_AUTH_LINES[2]}"; then
        pass "$1"
        return 0
    fi
    fail "$1" "not the canonical fail-closed permit: ${PAM_AUTH_LINES[*]}"
    return 1
}

# assert_auth_stack_fail_closed <label> <single stack content>
# Mode-agnostic: accepts either shape. Use it where a test covers several modes
# at once and only cares that nothing falls off the end of the stack unrefused.
assert_auth_stack_fail_closed() {
    if ! _pam_check_permit "$2"; then
        fail "$1" "$PAM_ASSERT_ERR"
        return 1
    fi
    local last="${PAM_AUTH_LINES[${#PAM_AUTH_LINES[@]} - 1]}"
    case "$last" in
        auth*required*pam_permit.so*)
            # Only legal as the tail of the canonical 3-line permit, which
            # _pam_check_permit has already verified.
            pass "$1"
            return 0
            ;;
        *pam_permit.so*)
            fail "$1" "auth stack ends on an unguarded pam_permit: $last"
            return 1
            ;;
        auth*required*|auth*requisite*)
            pass "$1"
            return 0
            ;;
        *)
            fail "$1" "auth stack ends on a non-denying line: $last"
            return 1
            ;;
    esac
}
