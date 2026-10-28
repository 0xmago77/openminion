"""Disposable synthetic authorization fixture; never use as an application."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

CORRECTED = "--corrected" in sys.argv


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond()

    def do_HEAD(self):
        self.respond()

    def respond(self):
        identity = self.headers.get("X-Fixture-Identity", "anonymous")
        authenticated = identity in {"alice", "bob", "admin"}
        status = 200
        body = b"fixture-private-ok"
        if self.path == "/redirect":
            status = 302
        elif not authenticated:
            status = 401
        elif CORRECTED and self.path == "/admin" and identity != "admin":
            status = 403
        elif (
            CORRECTED and self.path == "/users/bob" and identity not in {"bob", "admin"}
        ):
            status = 403
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/redirect":
            self.send_header("Location", "http://off-target.invalid/private")
        if CORRECTED:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.send_header(
                "Set-Cookie", "fixture=synthetic; Secure; HttpOnly; SameSite=Strict"
            )
        else:
            self.send_header("Set-Cookie", "fixture=synthetic")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, *_):
        pass


print("fixture ready", flush=True)
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
