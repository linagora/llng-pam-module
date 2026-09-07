#!/usr/bin/env python3
"""Mock LLNG portal that verifies request signatures the way the real one does.

Usage: mock_portal_signing.py MODE PORT SECRETFILE LOGFILE

MODE mirrors pamAccessRequestSigningMode:
    off       headers ignored
    optional  a signed request must verify; an unsigned one passes
    required  the headers are mandatory

The verification below is a transcription of
Lemonldap::NG::Portal::Plugins::PamAccess::_checkRequestSignature -- same
header names, same regex on the signature, same +/-300 s window, and the same
message

    <timestamp>.<nonce>.<METHOD>.<path>.<body>

hashed with HMAC-SHA256 over the raw secret bytes. The point of reproducing it
rather than trusting the client is that a client-side test which computes the
expected value the same way the client does proves nothing (#247).

Every request is appended to LOGFILE as one JSON object so the test can assert
on what the portal saw, not only on what the client survived.
"""

import hashlib
import hmac
import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = sys.argv[1]
PORT = int(sys.argv[2])
# Read from a file, not argv: this mock exists to prove the client keeps the
# signing secret out of /proc/<pid>/cmdline, and a fixture that puts it there
# would be a poor example to copy.
with open(sys.argv[3]) as _fh:
    SECRET = _fh.read().strip("\n")
LOGFILE = sys.argv[4]

SIG_RE = re.compile(r"\Asha256=([0-9a-f]{64})\Z")
NONCE_RE = re.compile(r"\A[0-9A-Za-z._:-]{1,128}\Z")
TS_RE = re.compile(r"\A[0-9]{1,11}\Z")
WINDOW = 300

SEEN_NONCES = set()


def check(handler, body):
    """Return (ok, reason). Mirrors _checkRequestSignature step for step."""
    ts = handler.headers.get("X-Timestamp")
    nonce = handler.headers.get("X-Nonce")
    sig = handler.headers.get("X-Signature-256")

    if MODE == "off":
        return True, "off"

    signed = any(v for v in (ts, nonce, sig))
    if not signed:
        if MODE == "optional":
            return True, "unsigned_allowed"
        return False, "unsigned"

    m = SIG_RE.match(sig) if sig else None
    if not (ts and TS_RE.match(ts) and nonce and NONCE_RE.match(nonce) and m):
        return False, "malformed_headers"

    if abs(time.time() - int(ts)) > WINDOW:
        return False, "stale_timestamp"

    path = handler.path.split("?", 1)[0]
    message = ".".join([ts, nonce, handler.command.upper(), path, body])
    expected = hmac.new(
        SECRET.encode(), message.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, m.group(1)):
        return False, "bad_signature"

    if nonce in SEEN_NONCES:
        return False, "nonce_replayed"
    SEEN_NONCES.add(nonce)

    return True, "verified"


# What each endpoint answers once the caller is through the gate. Only the
# fields the clients actually read.
BODIES = {
    "/pam/heartbeat": {"access_token": "fresh-access-token", "expires_in": 3600,
                       "next_heartbeat": 300},
    "/pam/whoami": {"server_id": "mock-bastion-1", "bastion_id": "mock-bastion-1"},
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        path = self.path.split("?", 1)[0]

        ok, reason = check(self, body)

        with open(LOGFILE, "a") as fh:
            fh.write(json.dumps({
                "path": path,
                "signed": bool(self.headers.get("X-Signature-256")),
                "ok": ok,
                "reason": reason,
            }) + "\n")

        if not ok:
            payload = json.dumps({"error": "forbidden", "reason": reason})
            self.send_response(403)
        elif path in BODIES:
            payload = json.dumps(BODIES[path])
            self.send_response(200)
        else:
            payload = json.dumps({"error": "not_found"})
            self.send_response(404)

        raw = payload.encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
