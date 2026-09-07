#!/bin/bash
# test_ob_systemd_units.sh
#
# Keeps systemd unit files in exactly one place (issue #254).
#
# Units used to exist twice: in systemd/, and again as debian/open-bastion.<unit>
# for dh_installsystemd's package.NAME.socket form. The two drifted. `a9a28d8`
# added hardening to systemd/ob-cert@.service and systemd/ob-record@.service --
# UMask=0077, SystemCallFilter=@system-service, SystemCallErrorNumber=EPERM --
# and the debian/ copies, last touched three months earlier, never got it. The
# copies happened to be the ones nothing installed, so no shipped unit lost the
# hardening; the damage was that two files looked authoritative and one was
# silently wrong. It survived two releases because nothing checked.
#
# So this test does not check the drift that existed. It checks the property
# that makes drift impossible:
#
#   1. no unit content lives anywhere but systemd/;
#   2. every unit dh_installsystemd is told to handle is actually staged into
#      the package by debian/open-bastion.install, since that is now the only
#      thing that puts unit files in the package;
#   3. every unit the RPM lists exists in systemd/ too;
#   4. the hardening directives that went missing are present in the units that
#      are supposed to have them -- the specific regression, pinned.

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

echo "=== systemd unit files (issue #254) ==="

# ── 1. systemd/ is the only home for unit content ────────────────────────────
test_no_duplicate_unit_files() {
    local dupes=""
    local f
    # Anything in debian/ that looks like a unit: the package.NAME.unit form
    # dh_installsystemd accepts, and bare unit files.
    for f in "$ROOT_DIR"/debian/*.service "$ROOT_DIR"/debian/*.socket \
             "$ROOT_DIR"/debian/*.timer "$ROOT_DIR"/debian/*.mount; do
        [ -e "$f" ] || continue
        case "$(basename "$f")" in
            # debian/<package>.service and <package>.timer are the sysv-ish
            # names for the package's own unit, not copies of a systemd/ file.
            open-bastion.service|open-bastion.timer) continue ;;
        esac
        dupes="$dupes $(basename "$f")"
    done
    if [ -z "$dupes" ]; then
        pass "no unit file content under debian/"
    else
        fail "no unit file content under debian/" \
             "these duplicate systemd/ and will drift:$dupes"
    fi
}

# ── 2. Every unit debian/rules names is staged by debian/open-bastion.install ─
# dh_installsystemd no longer carries its own copy, so it can only find a unit
# that .install has already put in the package tree. A unit named in rules but
# missing from .install would produce enable/disable snippets for a file that is
# not there -- the socket would be "enabled" and then fail to start.
test_rules_units_are_installed() {
    local missing="" unit
    # Across every .install file: ob-session-monitor.service belongs to the
    # -desktop binary package, not to open-bastion.
    while read -r unit; do
        [ -n "$unit" ] || continue
        grep -qE "systemd/$unit( |\$)" "$ROOT_DIR"/debian/*.install \
            || missing="$missing $unit"
    done < <(grep -oE '(ob|open)-[a-z-]+\.(socket|timer|service)$' \
                  "$ROOT_DIR/debian/rules" | sort -u)

    if [ -z "$missing" ]; then
        pass "every unit named in debian/rules is staged by .install"
    else
        fail "every unit named in debian/rules is staged by .install" \
             "not installed:$missing"
    fi
}

# ── 3. Every @.service template has its .socket, and both exist in systemd/ ───
test_templates_have_sockets() {
    local bad="" tmpl base
    for tmpl in "$ROOT_DIR"/systemd/*@.service; do
        [ -e "$tmpl" ] || continue
        base="$(basename "$tmpl" '@.service')"
        [ -f "$ROOT_DIR/systemd/$base.socket" ] || bad="$bad $base.socket"
        # A template that is not installed cannot be spawned by its socket.
        grep -q "systemd/$base@.service" \
             "$ROOT_DIR/debian/open-bastion.install" || bad="$bad $base@.service(not-installed)"
    done
    if [ -z "$bad" ]; then
        pass "every @.service template has its .socket and is installed"
    else
        fail "every @.service template has its .socket and is installed" "$bad"
    fi
}

# ── 4. The RPM lists only units that exist ───────────────────────────────────
test_rpm_units_exist() {
    local missing="" unit
    while read -r unit; do
        [ -n "$unit" ] || continue
        [ -f "$ROOT_DIR/systemd/$unit" ] || missing="$missing $unit"
    done < <(grep -oE '%\{_unitdir\}/[^[:space:]]+' "$ROOT_DIR/rpm/open-bastion.spec" \
             | sed 's|%{_unitdir}/||' | sort -u)

    if [ -z "$missing" ]; then
        pass "every unit the RPM lists exists in systemd/"
    else
        fail "every unit the RPM lists exists in systemd/" "missing:$missing"
    fi
}

# ── 5. The hardening that went missing, pinned ───────────────────────────────
# This is the specific regression #254 is about. Every socket-activated
# @.service in this tree runs as root, so these three are not optional dressing.
test_socket_services_are_hardened() {
    local bad="" svc name d
    for svc in "$ROOT_DIR"/systemd/*@.service; do
        [ -e "$svc" ] || continue
        name="$(basename "$svc")"
        for d in NoNewPrivileges=true ProtectSystem=strict PrivateTmp=true \
                 UMask=0077 SystemCallFilter=@system-service \
                 SystemCallErrorNumber=EPERM; do
            grep -qF "$d" "$svc" || bad="$bad $name:${d%%=*}"
        done
    done
    if [ -z "$bad" ]; then
        pass "socket-activated services keep their hardening directives"
    else
        fail "socket-activated services keep their hardening directives" "$bad"
    fi
}

run_test test_no_duplicate_unit_files
run_test test_rules_units_are_installed
run_test test_templates_have_sockets
run_test test_rpm_units_exist
run_test test_socket_services_are_hardened

echo
echo "Tests run: $((TESTS_PASSED + TESTS_FAILED)), passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
