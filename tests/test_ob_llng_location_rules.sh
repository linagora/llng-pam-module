#!/bin/bash
#
# Guards the portal locationRules that are the ONLY authorization on two sets of
# routes (#195):
#
#   /device                        — approve or refuse a host enrolment.
#                                    oidcRPMetaDataOptionsAllowDeviceAuthorization=1
#                                    means "any authenticated user", so the rule
#                                    is the whole control.
#   /ssh/admin, /ssh/certs,        — list every issued certificate and revoke
#   /ssh/revoke                      anyone's. The ssh-ca plugin performs no
#                                    authorization on them at all.
#
# Two ways to get these rules wrong are load-bearing, and both are silent:
#
#   - `^/device$` never matches, because LLNG's grant() matches REQUEST_URI,
#     which carries the query string (`/device?user_code=...`).
#   - `^/ssh/revoke` also matches `/ssh/revoked`, the PUBLIC KRL every backend
#     downloads on a timer. Restricting that route breaks revocation propagation
#     fleet-wide while looking like a hardening step.
#
# So this test checks the shipped configurations carry the rules, and replays
# the regexes against the real route list to prove they separate admin routes
# from user and public ones.
#

set -uo pipefail

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

pass() { TESTS_PASSED=$((TESTS_PASSED + 1)); echo "  PASS: $1"; }
fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "  FAIL: $1${2:+ - $2}"; }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); "$@"; }

# Configurations that enable the ssh-ca plugin and therefore expose the admin
# routes. The token-only demos have no /ssh routes at all.
SSHCA_CONFIGS=(
    "docker-demo-cert/lmConf-1.json"
    "docker-demo-maxsec/lmConf-1.json"
)

# Every shipped portal configuration: all of them expose /device.
ALL_CONFIGS=(
    "docker-demo-cert/lmConf-1.json"
    "docker-demo-maxsec/lmConf-1.json"
    "docker-demo-token/lmConf-1.json"
    "docker-demo-token-svc/lmConf-1.json"
    "quick-start/lmConf-1.json"
)

# ── Test 1: the shipped configs are valid JSON ──
test_configs_are_valid_json() {
    local bad="" c
    for c in "${ALL_CONFIGS[@]}"; do
        python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$ROOT_DIR/$c" 2>/dev/null \
            || bad="$bad $c"
    done
    if [ -z "$bad" ]; then
        pass "shipped lmConf files are valid JSON"
    else
        fail "shipped lmConf files are valid JSON" "bad:$bad"
    fi
}

# ── Test 2: every portal vhost restricts /device ──
test_device_rule_present() {
    local bad="" c
    for c in "${ALL_CONFIGS[@]}"; do
        python3 - "$ROOT_DIR/$c" <<'PY' || bad="$bad $c"
import json, sys
conf = json.load(open(sys.argv[1]))
rules = conf.get("locationRules", {})
if not rules:
    sys.exit(1)
for host, host_rules in rules.items():
    if not any(k.startswith("^/device") for k in host_rules):
        sys.exit(1)
sys.exit(0)
PY
    done
    if [ -z "$bad" ]; then
        pass "every shipped portal vhost carries a ^/device rule"
    else
        fail "every shipped portal vhost carries a ^/device rule" "missing:$bad"
    fi
}

# ── Test 3: no /device rule is anchored with $ ──
# `^/device$` would not match /device?user_code=..., so the rule would never
# fire and the enrolment approval would stay open to every SSO user.
test_device_rule_not_end_anchored() {
    local bad="" c
    for c in "${ALL_CONFIGS[@]}"; do
        python3 - "$ROOT_DIR/$c" <<'PY' || bad="$bad $c"
import json, sys
conf = json.load(open(sys.argv[1]))
for host_rules in conf.get("locationRules", {}).values():
    for k in host_rules:
        if k.startswith("^/device") and k.rstrip().endswith("$") and "|" not in k:
            sys.exit(1)
sys.exit(0)
PY
    done
    if [ -z "$bad" ]; then
        pass "no ^/device rule is end-anchored (REQUEST_URI carries the query)"
    else
        fail "no ^/device rule is end-anchored" "offenders:$bad"
    fi
}

# ── Test 4: ssh-ca configs restrict the admin routes ──
test_ssh_admin_rule_present() {
    local bad="" c
    for c in "${SSHCA_CONFIGS[@]}"; do
        python3 - "$ROOT_DIR/$c" <<'PY' || bad="$bad $c"
import json, sys
conf = json.load(open(sys.argv[1]))
if not conf.get("sshCaActivation"):
    sys.exit(0)   # plugin off: no /ssh routes to protect
for host_rules in conf.get("locationRules", {}).values():
    if not any(k.startswith("^/ssh") for k in host_rules):
        sys.exit(1)
sys.exit(0)
PY
    done
    if [ -z "$bad" ]; then
        pass "ssh-ca configs carry a ^/ssh admin rule on every vhost"
    else
        fail "ssh-ca configs carry a ^/ssh admin rule" "missing:$bad"
    fi
}

# ── Test 5: the /ssh rule matches the admin routes and NOTHING else ──
# This is the one that matters: /ssh/revoked is the public KRL, and /ssh/sign,
# /ssh/mycerts, /ssh/myrevoke are ordinary user operations.
test_ssh_rule_separates_routes() {
    local bad="" c
    for c in "${SSHCA_CONFIGS[@]}"; do
        python3 - "$ROOT_DIR/$c" <<'PY' || bad="$bad $c"
import json, re, sys

MUST_MATCH = ["/ssh/admin", "/ssh/certs", "/ssh/certs?search=x",
              "/ssh/revoke", "/ssh/revoke/42"]
MUST_NOT   = ["/ssh/revoked",          # public KRL, downloaded by every backend
              "/ssh/ca",               # public CA key
              "/ssh/sign",             # the user's own certificate request
              "/ssh/mycerts", "/ssh/myrevoke",
              "/ssh"]                  # the signing interface

conf = json.load(open(sys.argv[1]))
for host, host_rules in conf.get("locationRules", {}).items():
    for pattern in host_rules:
        if not pattern.startswith("^/ssh"):
            continue
        rx = re.compile(pattern)
        for uri in MUST_MATCH:
            if not rx.search(uri):
                print(f"{host}: {pattern} fails to match {uri}", file=sys.stderr)
                sys.exit(1)
        for uri in MUST_NOT:
            if rx.search(uri):
                print(f"{host}: {pattern} wrongly matches {uri}", file=sys.stderr)
                sys.exit(1)
sys.exit(0)
PY
    done
    if [ -z "$bad" ]; then
        pass "^/ssh rule covers admin routes and spares /ssh/revoked, /ssh/ca, user routes"
    else
        fail "^/ssh rule route separation" "wrong in:$bad"
    fi
}

# ── Test 6: the documentation ships the same rules ──
# The production deployment is an operator's own portal, which this repository
# does not configure; the guide is the deliverable, so it must not drift.
test_documented() {
    local doc="$ROOT_DIR/doc/llng-configuration.md" ok=1
    grep -q '\^/device' "$doc" || { ok=0; echo "    (no ^/device rule documented)"; }
    grep -q 'admin|certs|revoke' "$doc" || { ok=0; echo "    (no ^/ssh admin rule documented)"; }
    grep -q '/ssh/revoked' "$doc" || { ok=0; echo "    (the /ssh/revoked trap is not called out)"; }
    if [ "$ok" -eq 1 ]; then
        pass "doc/llng-configuration.md documents both rules and the KRL trap"
    else
        fail "doc/llng-configuration.md documents both rules"
    fi
}

echo "=== LLNG portal locationRules (#195) ==="
run_test test_configs_are_valid_json
run_test test_device_rule_present
run_test test_device_rule_not_end_anchored
run_test test_ssh_admin_rule_present
run_test test_ssh_rule_separates_routes
run_test test_documented

echo ""
echo "Tests run: $TESTS_RUN, passed: $TESTS_PASSED, failed: $TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
