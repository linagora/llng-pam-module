#!/bin/bash
# Test: the postinst warns when a certificate-only PAM mode is installed while
# sshd still accepts passwords (#180).
#
# #220 made the generated mode-c stack deny (auth required pam_deny.so), so a
# password attempt is refused. But the postinst never touches sshd_config, so
# between `apt install` and the first ob-bastion-setup the host still offers
# password authentication -- and with UsePAM no, sshd never consults the stack
# at all. The postinst must say so rather than leave the mismatch silent.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POSTINST="$SCRIPT_DIR/debian/open-bastion.postinst"

passed=0; failed=0
pass() { echo "  PASS: $1"; passed=$((passed+1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "    $2"; failed=$((failed+1)); }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
sed -n '/^warn_if_sshd_accepts_passwords()/,/^}/p' "$POSTINST" > "$WORK/helper.sh"
[ -s "$WORK/helper.sh" ] || { echo "  FAIL: helper not found in postinst"; exit 1; }
mkdir -p "$WORK/fakebin"

# $1 mode, $2 sshd -T lines, $3 description, $4 expect (warn|silent), $5 extra regex
run_case() {
    local mode="$1" cfg="$2" desc="$3" expect="$4" extra="${5:-}" out
    printf '#!/bin/sh\n[ "$1" = "-T" ] || exit 1\nprintf "%%s\\n" %s\n' "$cfg" \
        > "$WORK/fakebin/sshd"
    chmod +x "$WORK/fakebin/sshd"
    out=$(cd "$WORK" && PATH="$WORK/fakebin:$PATH" \
        sh -c ". ./helper.sh; warn_if_sshd_accepts_passwords $mode" 2>&1)

    if [ "$expect" = "silent" ]; then
        [ -z "$out" ] && pass "$desc" || fail "$desc" "expected no output, got: $out"
        return
    fi
    if ! grep -q "WARNING" <<<"$out"; then
        fail "$desc" "expected a warning, got: ${out:-<nothing>}"; return
    fi
    if [ -n "$extra" ] && ! grep -qE "$extra" <<<"$out"; then
        fail "$desc" "warning missing /$extra/: $out"; return
    fi
    pass "$desc"
}

run_case mode-c "'passwordauthentication no' 'kbdinteractiveauthentication no' 'usepam yes'" \
    "mode-c with passwords already off stays silent" silent
run_case mode-c "'passwordauthentication yes' 'kbdinteractiveauthentication no' 'usepam yes'" \
    "mode-c with PasswordAuthentication yes warns" warn "ob-bastion-setup"
run_case mode-c "'passwordauthentication no' 'kbdinteractiveauthentication yes' 'usepam yes'" \
    "mode-c with KbdInteractiveAuthentication yes warns" warn
run_case mode-c "'passwordauthentication yes' 'kbdinteractiveauthentication no' 'usepam no'" \
    "UsePAM no escalates: stack is not consulted" warn "NOT refused"
run_case mode-a "'passwordauthentication yes' 'kbdinteractiveauthentication yes' 'usepam yes'" \
    "password modes are not warned about" silent

# The helper must actually be called, and after the PAM stack is written --
# a helper that exists but is never invoked would pass every case above.
if grep -q '^ *warn_if_sshd_accepts_passwords "\$MODE"' "$POSTINST"; then
    _gen=$(grep -n 'generate_pam_sshd "\$MODE"' "$POSTINST" | head -1 | cut -d: -f1)
    _warn=$(grep -n '^ *warn_if_sshd_accepts_passwords "\$MODE"' "$POSTINST" | head -1 | cut -d: -f1)
    if [ -n "$_gen" ] && [ -n "$_warn" ] && [ "$_warn" -gt "$_gen" ]; then
        pass "postinst calls the helper after writing the PAM stack"
    else
        fail "postinst calls the helper after writing the PAM stack" \
             "generate at line ${_gen:-?}, warn at line ${_warn:-?}"
    fi
else
    fail "postinst calls the helper after writing the PAM stack" "no call found"
fi

# The postinst must not edit sshd_config itself: disabling password auth from a
# package script can lock out an admin on a password session (#220 scope note).
if grep -qE '(>|>>|sed -i|tee).*sshd_config' "$POSTINST"; then
    fail "postinst does not write sshd_config"
else
    pass "postinst does not write sshd_config"
fi

echo
echo "=== Results: $((passed))/$((passed+failed)) passed, $failed failed ==="
[ "$failed" -eq 0 ]
