#!/bin/bash
# Shared assertions for the PAM stacks Open Bastion generates (issue #180).
#
# A certificate-mode auth stack whose only line is
#
#   auth       required     pam_permit.so
#
# makes pam_authenticate() return success unconditionally. sshd does not call
# pam_authenticate() on the pubkey/certificate path, but it DOES call it for
# password and keyboard-interactive authentication: on a host where those are
# still enabled (the distro default, and what `apt install open-bastion` leaves
# behind because the postinst never touches sshd_config), any password then
# authenticates any account the account phase approves — silently, since
# pam_permit logs nothing.
#
# The fail-closed shape is:
#
#   auth       [success=1 default=ignore] pam_permit.so
#   auth       required     pam_deny.so
#
# success=1 skips EXACTLY one following module, so the pam_deny backstop must
# be the immediately next auth line: pam_permit's PAM_SUCCESS is recorded, the
# jump lands past pam_deny, and the stack ends successfully on the intended
# path. Any other pam_permit result (module missing, internal error) is ignored
# and falls through to pam_deny, which fails the stack.
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

# _pam_check_permit <content> — silent core, sets PAM_ASSERT_ERR on failure.
# Works on a single stack or on a whole file holding several stacks: no
# pam_permit may sit on an auth path as a plain required/sufficient line, and
# every pam_permit jump must be immediately followed by the pam_deny backstop.
_pam_check_permit() {
    PAM_ASSERT_ERR=""
    _pam_read_auth_lines "$1"

    if [ "${#PAM_AUTH_LINES[@]}" -eq 0 ]; then
        PAM_ASSERT_ERR="no auth line found in: $1"
        return 1
    fi

    local i next
    for ((i = 0; i < ${#PAM_AUTH_LINES[@]}; i++)); do
        case "${PAM_AUTH_LINES[i]}" in
            *pam_permit.so*) ;;
            *) continue ;;
        esac
        case "${PAM_AUTH_LINES[i]}" in
            auth*"[success=1 default=ignore]"*pam_permit.so*) ;;
            *)
                PAM_ASSERT_ERR="pam_permit on the auth path is not [success=1 default=ignore]: ${PAM_AUTH_LINES[i]}"
                return 1
                ;;
        esac
        next="${PAM_AUTH_LINES[i + 1]:-}"
        case "$next" in
            auth*required*pam_deny.so*) ;;
            *)
                PAM_ASSERT_ERR="success=1 skips exactly one module, so 'auth required pam_deny.so' must be the next auth line, got: ${next:-<end of stack>}"
                return 1
                ;;
        esac
    done
    return 0
}

# _pam_check_terminates_closed — silent core, run after _pam_check_permit.
# The stack must end on a line that can actually deny: a required/requisite
# module that is not pam_permit (pam_deny for the certificate stacks,
# "required pam_openbastion.so" for the token stacks). A stack ending on a
# sufficient/optional line falls off the end with nothing left to refuse it.
_pam_check_terminates_closed() {
    local last="${PAM_AUTH_LINES[${#PAM_AUTH_LINES[@]} - 1]}"
    case "$last" in
        *pam_permit.so*)
            PAM_ASSERT_ERR="auth stack ends on pam_permit: $last"
            return 1
            ;;
        auth*required*|auth*requisite*) return 0 ;;
        *)
            PAM_ASSERT_ERR="auth stack ends on a non-denying line: $last"
            return 1
            ;;
    esac
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

# assert_auth_stack_fail_closed <label> <single stack content>
assert_auth_stack_fail_closed() {
    if _pam_check_permit "$2" && _pam_check_terminates_closed; then
        pass "$1"
        return 0
    fi
    fail "$1" "$PAM_ASSERT_ERR"
    return 1
}
