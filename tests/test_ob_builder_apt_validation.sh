#!/bin/bash
#
# Test suite for ob-builder APT repository input validation (issue #190).
#
# apt_url / apt_suite / apt_component end up inside the
#   deb [signed-by=...] <url> <suite> <component>
# line that is interpolated verbatim into templates/shell/installer.sh.in and
# written to /etc/apt/sources.list.d by a script running as root. Because
# render_template() is a literal bash substitution that preserves every
# character, an unvalidated value could execute a command substitution as root
# or inject extra sources.list entries via an embedded newline.
#
# Sources ob-builder the same way as test_ob_builder_service_accounts.sh (with
# `set -euo pipefail` and the `main "$@"` call stripped) and exercises the
# validators plus validate_inputs() with hostile values.
#

# Nearly every variable set here is read by the ob-builder functions sourced
# below, which shellcheck cannot see through.
# shellcheck disable=SC2034

set -u

TESTS_PASSED=0
TESTS_FAILED=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ob-builder defines its own SCRIPT_DIR, and sourcing it below clobbers ours —
# keep the repo root under a distinct name.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDER="$REPO_ROOT/admin-builder/ob-builder"
export OB_BUILDER_LIB_DIR="$REPO_ROOT/admin-builder/lib"
export OB_BUILDER_SHARE="$REPO_ROOT/admin-builder"

TEST_TMPDIR=$(mktemp -d)
trap 'rm -rf "$TEST_TMPDIR"' EXIT

# NOTE: both helpers must return 0 — they are used on the right of `&&` in
# `$ok && test_pass ... || test_fail ...`, and `((x++))` returns 1 when x was 0.
test_pass() { echo -e "${GREEN}✓${NC} $1"; ((TESTS_PASSED++)); return 0; }
test_fail() {
    echo -e "${RED}✗${NC} $1"
    [ -n "${2:-}" ] && echo -e "  ${YELLOW}Details:${NC} $2"
    ((TESTS_FAILED++))
    return 0
}

# shellcheck disable=SC1090
eval "$(sed -e 's/^set -euo pipefail$//' -e '/^main "\$@"$/d' "$BUILDER")"
BUILD_DATE="2026-01-01T00:00:00Z"

# A keyring file must exist for validate_inputs() to reach its final check.
FAKE_KEYRING="$TEST_TMPDIR/keyring.gpg"
printf 'not-a-real-keyring\n' > "$FAKE_KEYRING"

# Run validate_inputs() in a subshell with a minimal-but-valid baseline plus
# the caller's overrides. Prints nothing; returns 0 if accepted, non-zero if
# rejected (die() exits non-zero).
#
# Usage: run_validate VAR=value [VAR=value ...]
run_validate() {
    (
        DEPLOYMENT_SLUG="demo"
        SCENARIO="token-only"
        PORTAL_URL="https://sso.example.com"
        CLIENT_ID="open-bastion"
        CLIENT_ID_POLICY="modifiable"
        CLIENT_SECRET_MODE="prompt"
        EMBEDDED_CLIENT_SECRET=""
        SERVER_GROUP="default"
        SERVER_GROUP_POLICY="modifiable"
        TARGET_ROLE="bastion"
        ALLOWED_BASTIONS=""
        AUTO_ENROLL_SETUP="no"
        SELF_DELETE="no"
        ALLOW_HTTP=0
        APT_URL="https://linagora.github.io/open-bastion"
        APT_SUITE="trixie"
        APT_COMPONENT="main"
        SERVICE_ACCOUNTS_RECORDS=()
        REPO_KEYRING="$FAKE_KEYRING"

        local assignment
        for assignment in "$@"; do
            eval "${assignment%%=*}=\${assignment#*=}"
        done

        validate_inputs
    ) >/dev/null 2>&1
}

# Test 1: syntax check on the two files this suite covers
test_syntax() {
    local ok=true
    bash -n "$BUILDER" || ok=false
    bash -n "$REPO_ROOT/admin-builder/lib/validators.sh" || ok=false
    $ok && test_pass "Syntax check: bash -n passes on ob-builder and validators.sh" \
         || test_fail "Syntax check failed"
}

# Test 2: the suite validator accepts real Debian suites and rejects injection
test_suite_validator() {
    local ok=true
    is_valid_apt_suite "trixie"              || ok=false
    is_valid_apt_suite "bookworm-backports"  || ok=false
    is_valid_apt_suite "stable/updates"      || ok=false
    is_valid_apt_suite "1.0"                 || ok=false

    is_valid_apt_suite ""                            && ok=false   # empty
    is_valid_apt_suite '$(id)'                       && ok=false   # command substitution
    is_valid_apt_suite '`id`'                        && ok=false   # backticks
    is_valid_apt_suite 'trixie main'                 && ok=false   # extra field
    is_valid_apt_suite 'trixie"; id; :"'             && ok=false   # quote break-out
    is_valid_apt_suite $'trixie\ndeb http://evil/ x' && ok=false   # newline injection
    is_valid_apt_suite '-trixie'                     && ok=false   # leading dash

    $ok && test_pass "is_valid_apt_suite: accepts codenames, rejects injection" \
         || test_fail "is_valid_apt_suite returned a wrong result"
}

# Test 3: the component validator
test_component_validator() {
    local ok=true
    is_valid_apt_component "main"                        || ok=false
    is_valid_apt_component "main contrib"                || ok=false
    is_valid_apt_component "main contrib non-free-firmware" || ok=false

    is_valid_apt_component ""                            && ok=false
    is_valid_apt_component '$(touch /tmp/pwned)'         && ok=false
    is_valid_apt_component '`id`'                        && ok=false
    is_valid_apt_component 'main; id'                    && ok=false
    is_valid_apt_component $'main\ndeb http://evil/ x y' && ok=false
    is_valid_apt_component 'main|contrib'                && ok=false

    $ok && test_pass "is_valid_apt_component: accepts component lists, rejects injection" \
         || test_fail "is_valid_apt_component returned a wrong result"
}

# Test 4: validate_inputs() accepts the shipped defaults
test_validate_inputs_accepts_defaults() {
    if run_validate; then
        test_pass "validate_inputs: accepts the default APT repo settings"
    else
        test_fail "validate_inputs rejected the default APT repo settings"
    fi
}

# Test 5: validate_inputs() rejects hostile apt_* values (the #190 regression)
test_validate_inputs_rejects_hostile() {
    local ok=true
    local desc

    # apt_url: command substitution, backticks, quote break-out, newline, non-URL
    run_validate 'APT_URL=https://x/$(touch /tmp/ob-pwned)' && { ok=false; desc="apt_url \$(...)"; }
    run_validate 'APT_URL=https://x/`id`'                   && { ok=false; desc="apt_url backticks"; }
    run_validate 'APT_URL=https://x" ; id ; echo "'         && { ok=false; desc="apt_url quote break-out"; }
    run_validate "APT_URL=$(printf 'https://x\ndeb http://evil/ trixie main')" \
        && { ok=false; desc="apt_url newline"; }
    run_validate 'APT_URL=file:///etc/passwd'               && { ok=false; desc="apt_url non-http scheme"; }
    run_validate 'APT_URL='                                 && { ok=false; desc="apt_url empty"; }

    # apt_suite
    run_validate 'APT_SUITE=$(touch /tmp/ob-pwned)'         && { ok=false; desc="apt_suite \$(...)"; }
    run_validate "APT_SUITE=$(printf 'trixie\ndeb http://evil/ trixie main')" \
        && { ok=false; desc="apt_suite newline"; }
    run_validate 'APT_SUITE=trixie main'                    && { ok=false; desc="apt_suite extra field"; }
    run_validate 'APT_SUITE='                               && { ok=false; desc="apt_suite empty"; }

    # apt_component
    run_validate 'APT_COMPONENT=$(touch /tmp/ob-pwned)'     && { ok=false; desc="apt_component \$(...)"; }
    run_validate "APT_COMPONENT=$(printf 'main\ndeb http://evil/ trixie main')" \
        && { ok=false; desc="apt_component newline"; }
    run_validate 'APT_COMPONENT=main; id'                   && { ok=false; desc="apt_component semicolon"; }
    run_validate 'APT_COMPONENT='                           && { ok=false; desc="apt_component empty"; }

    # None of the payloads above may have run.
    [ -e /tmp/ob-pwned ] && { ok=false; desc="a payload executed (/tmp/ob-pwned exists)"; rm -f /tmp/ob-pwned; }

    $ok && test_pass "validate_inputs: rejects hostile apt_url / apt_suite / apt_component" \
         || test_fail "validate_inputs accepted a hostile value" "${desc:-}"
}

# Test 6: a hostile value supplied through the YAML config path is rejected too
# (the questionnaire path and the YAML path share validate_inputs()).
test_yaml_path_rejected() {
    local cfg="$TEST_TMPDIR/hostile.yml"
    cat > "$cfg" <<'YML'
deployment_slug: demo
scenario: token-only
portal_url: https://sso.example.com
target_role: bastion
apt_url: https://x/$(touch /tmp/ob-pwned-yaml)
apt_suite: trixie
apt_component: main
YML

    local out rc
    out=$("$BUILDER" --config "$cfg" --repo-keyring "$FAKE_KEYRING" \
                     --output-shell "$TEST_TMPDIR/out.sh" --dry-run 2>&1); rc=$?

    if [ $rc -ne 0 ] && grep -qi "invalid apt_url" <<<"$out"; then
        test_pass "YAML config path: hostile apt_url refused by the builder"
    else
        test_fail "YAML config path did not refuse hostile apt_url (rc=$rc)" "$out"
    fi
    rm -f /tmp/ob-pwned-yaml
}

echo "=========================================="
echo "Testing ob-builder APT repo input validation"
echo "=========================================="
echo ""

test_syntax
test_suite_validator
test_component_validator
test_validate_inputs_accepts_defaults
test_validate_inputs_rejects_hostile
test_yaml_path_rejected

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "${RED}Failed:${NC} $TESTS_FAILED"
echo "Total:  $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
