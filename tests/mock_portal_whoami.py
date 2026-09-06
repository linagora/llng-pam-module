#!/usr/bin/env python3
"""A LemonLDAP::NG stand-in for tests/test_ob_bastion_id.sh.

Each MODE reproduces one portal shape ob-bastion-id has to survive. The one
that matters most is `catchall`: LemonLDAP::NG serves the portal's own HTML
login page, with a **200**, for any /pam/* path no plugin registered, so the
absence of an endpoint does not look like a 404 -- which is exactly the
assumption that made the first version of this migration fail.

Usage: mock_portal_whoami.py <mode> <port>
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = sys.argv[1]
PORT = int(sys.argv[2])

HTML = b"<!DOCTYPE html>\n<html><body>portal login page</body></html>"


def jwt_with(payload):
    import base64

    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    return "header." + body.decode() + ".signature"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self):
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.send_header("content-length", str(len(HTML)))
        self.end_headers()
        self.wfile.write(HTML)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))

        if MODE == "catchall":
            return self._html()

        if self.path == "/pam/whoami":
            if MODE == "whoami":
                return self._json(200, {
                    "server_id": "9f86d081",
                    "bastion_id": "9f86d081",
                    "client_id": "pam-access",
                    "server_group": "bastion",
                })
            if MODE == "forbidden":
                return self._json(403, {"error": "PAM_CALLER_RP_REFUSED"})
            if MODE in ("catchall-then-probe",):
                return self._html()
            return self._json(404, {"error": "not found"})

        if self.path == "/pam/bastion-token":
            if MODE in ("legacy-id", "catchall-then-probe"):
                return self._json(200, {"bastion_id": "legacy-id-42"})
            if MODE == "legacy-jwt":
                return self._json(200, {"bastion_jwt": jwt_with({"bastion_id": "jwt-id-7"})})
            if MODE == "legacy-badjwt":
                # A JWT whose payload segment is not base64url at all. This used
                # to kill the script at the assignment under `set -e`, with rc=1
                # and no message, instead of reaching its own error path.
                return self._json(200, {"bastion_jwt": "header.!!!not-base64!!!.signature"})
            return self._json(404, {"error": "gone"})

        self._json(404, {"error": "unknown path"})


HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
