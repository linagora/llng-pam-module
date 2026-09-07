#!/bin/bash
# test_ob_fp_daemon.sh
#
# Guards the fingerprint spool's trust root (issue #249).
#
# Before #249 the AuthorizedPrincipalsCommand helper wrote
# /run/open-bastion/ssh-fp/<anchor>.fp itself. sshd requires that helper to run
# unprivileged, so the spool was 0700 nobody and the integrity of the
# fingerprint binding rested on a shared, low-trust account. ob-fp-daemon takes
# the deposit over a unix socket instead and writes the spool as root.
#
# The property that actually matters is NOT "a deposit produces a drop" -- it
# is that a client cannot choose WHICH session it deposits for. The daemon
# derives the sshd anchor from the depositing process's own /proc ancestry, so
# these tests run ob-fp-submit under a process renamed "sshd-session" and check
# that the drop lands on that anchor and nowhere else.
#
# Covered:
#   - a deposit under an sshd-session anchor writes <anchor>.fp and <anchor>.key
#   - the .fp drop is byte-for-byte what the pre-#249 helper wrote
#   - drops are 0600 and owned by the user running the daemon
#   - the anchor is derived, not received: extra lines in the request cannot
#     redirect the drop to another PID
#   - a deposit with NO sshd-session ancestor is refused outright
#   - a malformed fingerprint is refused
#   - a malformed algorithm/blob degrades to .fp only, it does not fail
#   - the daemon re-asserts 0700 on the spool directory it is handed
#   - neither shipped helper writes the spool directly any more
#
# The daemon is normally socket-activated by systemd with Accept=yes, which
# hands it the connection on fd 0/1. Here `socat` plays systemd; the test skips
# if it is absent rather than pretending to have run.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

DAEMON=""
for c in "$ROOT_DIR/build/ob-fp-daemon" "$(command -v ob-fp-daemon 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] && { DAEMON="$c"; break; }
done
SUBMIT=""
for c in "$ROOT_DIR/build/ob-fp-submit" "$(command -v ob-fp-submit 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] && { SUBMIT="$c"; break; }
done

if [ -z "$DAEMON" ] || [ -z "$SUBMIT" ]; then
    echo "SKIP: ob-fp-daemon / ob-fp-submit not built (run cmake --build build)"
    exit 0
fi
command -v socat >/dev/null 2>&1 || { echo "SKIP: socat is required to stand in for systemd"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 is required"; exit 0; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; [ -n "${SOCAT_PID:-}" ] && kill "$SOCAT_PID" 2>/dev/null' EXIT

SPOOL="$WORK/ssh-fp"
# Inside the namespace this is the daemon's real, compiled-in path: the test
# exercises the shipped default rather than an override.
SOCK="/run/open-bastion/ssh-fp.sock"
FP="SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHI"
ALG="ssh-ed25519"
BLOB="AAAAC3NzaC1lZDI1NTE5AAAAIExampleBlobForTesting0123456789abcd"

# The daemon hard-codes its spool path at compile time, so the test runs it
# inside a user+mount namespace with a tmpfs on /run: the compiled-in path then
# lands in throwaway storage, and `unshare -r` makes us uid 0 there, which is
# what lets the daemon chown the spool exactly as root does on a real host.
if ! unshare -rm true 2>/dev/null; then
    echo "SKIP: unprivileged mount namespaces unavailable (need unshare -rm)"
    exit 0
fi

# Run one deposit end to end.
#   $1 = name the submitting process runs under ("sshd-session" to look like a
#        real anchor, anything else to look like a stray process)
#   $2 = request body sent to the daemon
#   $3 = mode to pre-create the spool directory with (default 700)
# Sets DEPOSIT_RC, DEPOSIT_ERR, ANCHOR, SPOOL_MODE, and copies the resulting
# drops (with their modes) out of the namespace into $SPOOL.
deposit() {
    local comm="$1" body="$2" premode="${3:-700}"
    local script="$WORK/run.sh"
    printf '%s' "$body" > "$WORK/body"
    rm -rf "$SPOOL"; mkdir -p "$SPOOL"
    : > "$WORK/submit.err"; : > "$WORK/anchor.pid"; : > "$WORK/spoolmode"

    cat > "$script" <<EOF
set -u
# tmpfs on /run: writable in the namespace, and the daemon's compiled-in
# /run/open-bastion/ssh-fp therefore resolves here rather than on the host.
mount -t tmpfs tmpfs /run || exit 90
mkdir -p /run/open-bastion/ssh-fp || exit 91
chmod $premode /run/open-bastion/ssh-fp || exit 92

# systemd's Accept=yes hands the daemon one connection on fd 0 and fd 1.
# ",nofork" is essential: plain EXEC: makes socat RELAY through a pipe, so
# SO_PEERCRED would report socat instead of the depositing process and every
# ancestry check would be measuring the wrong tree. With nofork the child execs
# the daemon directly on the accepted socket, which is what systemd does.
socat UNIX-LISTEN:"$SOCK",fork EXEC:"$DAEMON",nofork 2>"$WORK/daemon.err" &
sp=\$!
for _ in \$(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.05; done

# Rename the submitting process so the daemon's /proc walk sees the anchor we
# want, then submit from a child of it -- exactly the shape sshd produces
# (ob-fp-submit <- ob-ssh-principals <- sshd-session).
python3 - "$comm" "$SUBMIT" "$WORK/body" "$WORK/anchor.pid" "$WORK/submit.err" <<'PY_EOF'
import ctypes, os, subprocess, sys
comm, submit, body_path, anchor_path, err_path = sys.argv[1:6]
libc = ctypes.CDLL("libc.so.6", use_errno=True)
# PR_SET_NAME = 15. This is what makes the process look like an sshd anchor.
libc.prctl(15, comm.encode(), 0, 0, 0)
open(anchor_path, "w").write(str(os.getpid()))
with open(body_path, "rb") as b, open(err_path, "wb") as e:
    r = subprocess.run([submit], stdin=b, stderr=e, stdout=subprocess.DEVNULL)
sys.exit(r.returncode)
PY_EOF
rc=\$?
kill \$sp 2>/dev/null

# Carry the results out: /run is a tmpfs that dies with the namespace.
stat -c '%a' /run/open-bastion/ssh-fp > "$WORK/spoolmode" 2>/dev/null || :
cp -a /run/open-bastion/ssh-fp/. "$SPOOL/" 2>/dev/null || :
exit \$rc
EOF

    unshare -rm sh "$script" >/dev/null 2>&1
    DEPOSIT_RC=$?
    DEPOSIT_ERR=$(cat "$WORK/submit.err" 2>/dev/null)
    # A connect failure is a broken harness, not a refusal. Without this, every
    # "is it refused?" test below would pass by never reaching the daemon.
    case "$DEPOSIT_ERR" in
        *"cannot reach the fingerprint sink"*)
            echo "  HARNESS ERROR: the daemon was never reached: $DEPOSIT_ERR" >&2
            DEPOSIT_RC=99 ;;
    esac
    ANCHOR=$(cat "$WORK/anchor.pid" 2>/dev/null)
    SPOOL_MODE=$(cat "$WORK/spoolmode" 2>/dev/null)
}

# ── 1. The nominal deposit ────────────────────────────────────────────────────
test_nominal() {
    deposit sshd-session "$FP
$ALG
$BLOB
"
    if [ "$DEPOSIT_RC" != "0" ]; then
        fail "a deposit under an sshd-session anchor is accepted" \
             "rc=$DEPOSIT_RC err=$DEPOSIT_ERR"
        return
    fi
    if [ ! -f "$SPOOL/$ANCHOR.fp" ]; then
        fail "the drop lands on the derived anchor" \
             "no $ANCHOR.fp; spool holds: $(ls "$SPOOL" 2>/dev/null | tr '\n' ' ')"
        return
    fi
    pass "a deposit under an sshd-session anchor lands on that anchor"

    # Byte-for-byte the pre-#249 content: an older pam_openbastion reads this
    # file and must not be able to tell that a daemon wrote it.
    if [ "$(cat "$SPOOL/$ANCHOR.fp")" = "$FP" ]; then
        pass "the .fp drop keeps its exact pre-#249 content"
    else
        fail "the .fp drop keeps its exact pre-#249 content" \
             "got '$(cat "$SPOOL/$ANCHOR.fp")'"
    fi

    if [ -f "$SPOOL/$ANCHOR.key" ] \
       && grep -q '^v=1$' "$SPOOL/$ANCHOR.key" \
       && grep -q "^alg=$ALG$" "$SPOOL/$ANCHOR.key" \
       && grep -q "^key=$BLOB$" "$SPOOL/$ANCHOR.key"; then
        pass "the v1 .key drop carries v=1 / alg= / key="
    else
        fail "the v1 .key drop carries v=1 / alg= / key=" \
             "got '$(cat "$SPOOL/$ANCHOR.key" 2>/dev/null | tr '\n' ' ')'"
    fi

    local modes
    modes=$(find "$SPOOL" -type f -printf '%m ' 2>/dev/null)
    if [ "$modes" = "600 600 " ] || [ "$modes" = "600 600" ]; then
        pass "drops are mode 0600"
    else
        fail "drops are mode 0600" "modes: $modes"
    fi
}

# ── 2. The anchor is derived, never received ─────────────────────────────────
# This is the security property. A client that appends a PID of its choosing
# must not be able to steer the drop: the daemon reads only three lines and
# keys the drop on its own view of the peer's ancestry.
test_anchor_is_not_client_controlled() {
    deposit sshd-session "$FP
$ALG
$BLOB
99999
anchor=99999
"
    if [ -f "$SPOOL/99999.fp" ]; then
        fail "a client cannot name the anchor it deposits for" \
             "the request steered the drop to PID 99999"
        return
    fi
    if [ "$DEPOSIT_RC" = "0" ] && [ -f "$SPOOL/$ANCHOR.fp" ]; then
        pass "extra request lines cannot redirect the drop to another PID"
    else
        # Refusing outright is also an acceptable answer here; what must never
        # happen is a drop on the attacker's chosen PID.
        if [ "$DEPOSIT_RC" = "99" ]; then
            fail "extra request lines cannot redirect the drop" "harness never reached the daemon"
        else
            pass "extra request lines cannot redirect the drop (deposit refused)"
        fi
    fi
}

# ── 3. No sshd-session ancestor: refused ─────────────────────────────────────
test_requires_sshd_ancestor() {
    deposit definitely-not-sshd "$FP
$ALG
$BLOB
"
    if [ "$DEPOSIT_RC" != "0" ] && [ "$DEPOSIT_RC" != "99" ] \
       && [ -z "$(ls -A "$SPOOL" 2>/dev/null)" ]; then
        pass "a deposit outside any SSH connection is refused and writes nothing"
    else
        fail "a deposit outside any SSH connection is refused" \
             "rc=$DEPOSIT_RC spool: $(ls -A "$SPOOL" 2>/dev/null | tr '\n' ' ')"
    fi
}

# ── 4. Input validation ──────────────────────────────────────────────────────
test_bad_fingerprint_refused() {
    deposit sshd-session "MD5:not-a-sha256-fingerprint
$ALG
$BLOB
"
    if [ "$DEPOSIT_RC" != "0" ] && [ "$DEPOSIT_RC" != "99" ] \
       && [ -z "$(ls -A "$SPOOL" 2>/dev/null)" ]; then
        pass "a malformed fingerprint is refused and writes nothing"
    else
        fail "a malformed fingerprint is refused" \
             "rc=$DEPOSIT_RC spool: $(ls -A "$SPOOL" 2>/dev/null | tr '\n' ' ')"
    fi
}

test_bad_algorithm_degrades() {
    deposit sshd-session "$FP
not a valid; algorithm
$BLOB
"
    # The fingerprint is what the LLNG binding needs; losing the key metadata
    # must not cost us the binding as well.
    if [ "$DEPOSIT_RC" = "0" ] \
       && [ -f "$SPOOL/$ANCHOR.fp" ] && [ ! -f "$SPOOL/$ANCHOR.key" ]; then
        pass "a malformed algorithm drops .key but keeps the fingerprint"
    else
        fail "a malformed algorithm drops .key but keeps the fingerprint" \
             "rc=$DEPOSIT_RC spool: $(ls -A "$SPOOL" 2>/dev/null | tr '\n' ' ')"
    fi
}

# ── 5. The daemon owns the directory ─────────────────────────────────────────
# An upgraded host still has the pre-#249 0700 *nobody* directory. Leaving it
# would keep the old trust root while looking fixed, so the daemon re-asserts
# ownership and mode on every deposit.
test_daemon_reasserts_spool_mode() {
    deposit sshd-session "$FP
$ALG
$BLOB
" 777
    local mode="$SPOOL_MODE"
    if [ "$mode" = "700" ]; then
        pass "the daemon re-asserts 0700 on a loosened spool directory"
    else
        fail "the daemon re-asserts 0700 on a loosened spool directory" \
             "mode is $mode"
    fi
}

# ── 6. Neither shipped helper writes the spool any more ──────────────────────
# The point of #249 is that the unprivileged principals helper no longer holds
# the trust root. A future edit that reintroduces a direct write would undo it
# silently, so assert it against the shipped scripts.
test_helpers_do_not_write_the_spool() {
    local offenders=""
    for f in scripts/ob-bastion-setup scripts/ob-backend-setup; do
        # Look only inside the PRINCIPALS heredoc, which is the helper itself.
        # Strip comments first: the helper's own header still NAMES the spool
        # path, and matching that would flag documentation as a direct write.
        if awk '/<< .PRINCIPALS./,/^PRINCIPALS$/' "$ROOT_DIR/$f" \
             | sed 's/[[:space:]]*#.*$//' \
             | grep -qE '(mv|cp|tee|mktemp)[^|]*(\$\{?SPOOL_DIR|/run/open-bastion/ssh-fp/)'; then
            offenders="$offenders $f"
        fi
    done
    if [ -z "$offenders" ]; then
        pass "neither principals helper writes the spool directly"
    else
        fail "neither principals helper writes the spool directly" "$offenders"
    fi
}

test_helpers_deposit_via_submit() {
    local missing=""
    for f in scripts/ob-bastion-setup scripts/ob-backend-setup; do
        awk '/<< .PRINCIPALS./,/^PRINCIPALS$/' "$ROOT_DIR/$f" \
            | grep -q 'ob-fp-submit' || missing="$missing $f"
    done
    if [ -z "$missing" ]; then
        pass "both principals helpers deposit through ob-fp-submit"
    else
        fail "both principals helpers deposit through ob-fp-submit" "$missing"
    fi
}

# ── 7. The shipped spool is root-owned ───────────────────────────────────────
test_setup_scripts_own_the_spool_as_root() {
    local bad=""
    for f in scripts/ob-bastion-setup scripts/ob-backend-setup; do
        grep -qE 'chown[[:space:]]+nobody(:[a-z]+)?[[:space:]]+"\$spool_dir"' \
            "$ROOT_DIR/$f" && bad="$bad $f"
        grep -q 'd /run/open-bastion/ssh-fp   0700 root root' "$ROOT_DIR/$f" \
            || bad="$bad $f(tmpfiles)"
    done
    if [ -z "$bad" ]; then
        pass "both setups create the spool 0700 root, in place and at boot"
    else
        fail "both setups create the spool 0700 root" "$bad"
    fi
}

echo "=== ob-fp-daemon (issue #249) ==="
run_test test_nominal
run_test test_anchor_is_not_client_controlled
run_test test_requires_sshd_ancestor
run_test test_bad_fingerprint_refused
run_test test_bad_algorithm_degrades
run_test test_daemon_reasserts_spool_mode
run_test test_helpers_do_not_write_the_spool
run_test test_helpers_deposit_via_submit
run_test test_setup_scripts_own_the_spool_as_root

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
