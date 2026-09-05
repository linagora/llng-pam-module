#!/bin/bash
# Regression tests for issue #180: every generated PAM auth stack must be
# fail-closed (no bare "auth required pam_permit.so").
set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
# Some tests assert over several stacks, so the total is counted from the
# pass/fail tallies rather than from the number of test functions.
run_test() { "$@"; }

# shellcheck source=tests/lib_pam_stack.sh
. "$REPO_ROOT/tests/lib_pam_stack.sh"

POSTINST="$REPO_ROOT/debian/open-bastion.postinst"

# Pull one shell function out of the postinst so it can be evaluated without
# running the debconf machinery (the maintainer script sources
# /usr/share/debconf/confmodule at load time).
extract_func() {
    awk -v f="$1" '
        $0 ~ "^"f"\\(\\) \\{" { p = 1 }
        p { print }
        p && /^\}$/ { exit }
    ' "$POSTINST"
}

load_postinst_generators() {
    local body
    body=$(extract_func generate_pam_sshd)$'\n'$(extract_func generate_pam_sudo)
    if ! grep -q "generate_pam_sudo() {" <<<"$body"; then
        return 1
    fi
    eval "$body"
}

# ── Test 1: the postinst generators are still extractable ──
test_postinst_generators_load() {
    if (load_postinst_generators) 2>/dev/null; then
        pass "postinst PAM generators extracted"
    else
        fail "postinst PAM generators extracted" "generate_pam_sshd/generate_pam_sudo not found in $POSTINST"
    fi
}

# ── Test 2: every postinst sshd stack (all modes) is fail-closed ──
test_postinst_sshd_stacks() {
    local mode out
    for mode in mode-a mode-b mode-c mode-d; do
        out=$(load_postinst_generators && generate_pam_sshd "$mode" "grp")
        assert_auth_stack_fail_closed "postinst /etc/pam.d/sshd $mode is fail-closed" "$out"
    done
}

# ── Test 3: every postinst sudo stack (all modes) is fail-closed ──
test_postinst_sudo_stacks() {
    local mode out
    for mode in mode-a mode-b mode-c mode-d; do
        out=$(load_postinst_generators && generate_pam_sudo "$mode" "grp")
        assert_auth_stack_fail_closed "postinst /etc/pam.d/sudo $mode is fail-closed" "$out"
    done
}

# ── Test 4: mode-c (certificate mode) really emits the permit/deny pair ──
# This is the stack an admin gets from `apt install` with pam-mode=mode-c, on a
# host where sshd still has the distro-default PasswordAuthentication yes.
test_postinst_mode_c_pair() {
    local out
    out=$(load_postinst_generators && generate_pam_sshd mode-c "grp" | pam_auth_lines)
    local expected="auth       [success=1 default=ignore] pam_permit.so
auth       required     pam_deny.so"
    if [ "$out" = "$expected" ]; then
        pass "postinst mode-c sshd auth stack is exactly the permit/deny pair"
    else
        fail "postinst mode-c sshd auth stack is exactly the permit/deny pair" "$out"
    fi
}

# ── Test 5: no generated or documented stack keeps a bare pam_permit ──
# Covers the setup scripts, the demo entrypoints/Dockerfiles and the docs an
# admin copy-pastes from.
test_all_generated_stacks() {
    local f files=(
        "debian/open-bastion.postinst"
        "scripts/ob-bastion-setup"
        "scripts/ob-backend-setup"
        "docker-demo-cert/bastion/entrypoint.sh"
        "docker-demo-cert/backend/entrypoint.sh"
        "docker-demo-cert/bastion/Dockerfile"
        "docker-demo-cert/backend/Dockerfile"
        "docker-demo-maxsec/bastion/Dockerfile"
        "docker-demo-maxsec/backend/Dockerfile"
        "docker-demo-maxsec/backend/entrypoint.sh"
        "doc/pam-modes.md"
        "doc/admin-guide.md"
        "doc/presentation.md"
        "docker-demo-cert/README.md"
    )
    for f in "${files[@]}"; do
        if [ ! -f "$REPO_ROOT/$f" ]; then
            fail "$f auth lines are fail-closed" "file not found"
            continue
        fi
        assert_no_open_permit "$f auth lines are fail-closed" "$(cat "$REPO_ROOT/$f")"
    done
}

# ── Test 6: the assertion itself catches the vulnerable stack ──
# Guards against the assertion silently passing everything (the harness strips
# `set -e`, so a broken helper would otherwise look green).
test_assertion_detects_bare_permit() {
    local out
    out=$(assert_auth_stack_fail_closed "canary" "auth       required     pam_permit.so
account    required     pam_openbastion.so" 2>&1)
    # The canary runs in a subshell, so its fail() never reaches our tallies.
    if grep -q "FAIL: canary" <<<"$out"; then
        pass "assertion rejects a bare 'auth required pam_permit.so' stack"
    else
        fail "assertion rejects a bare 'auth required pam_permit.so' stack" "$out"
    fi
}

# ── Test 7: the assertion catches a misplaced backstop ──
# success=1 skips exactly one module: if pam_deny is not the very next auth
# line, the jump lands past it and the stack is open again.
test_assertion_detects_misplaced_deny() {
    local out
    out=$(assert_auth_stack_fail_closed "canary2" "auth       [success=1 default=ignore] pam_permit.so
auth       optional     pam_echo.so
auth       required     pam_deny.so")
    # Subshell again: the canary's fail() does not touch our tallies.
    if grep -q "FAIL: canary2" <<<"$out"; then
        pass "assertion rejects a pam_deny backstop that is not the next auth line"
    else
        fail "assertion rejects a pam_deny backstop that is not the next auth line" "$out"
    fi
}

# ── Run all tests ──
echo "=== Testing generated PAM stacks (#180) ==="
run_test test_postinst_generators_load
run_test test_postinst_sshd_stacks
run_test test_postinst_sudo_stacks
run_test test_postinst_mode_c_pair
run_test test_all_generated_stacks
run_test test_assertion_detects_bare_permit
run_test test_assertion_detects_misplaced_deny

TESTS_RUN=$((TESTS_PASSED + TESTS_FAILED))
echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] && exit 0 || exit 1
