"""One-shot loopback callback for MCP OAuth login."""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import time
from urllib.parse import parse_qs, urlsplit


@dataclass(frozen=True)
class MCPOAuthCallbackResult:
    code: str = ""
    issuer: str = ""
    error: str = ""


class MCPOAuthCallbackServer:
    def __init__(self, redirect_uri: str = "") -> None:
        parsed = urlsplit(redirect_uri or "http://127.0.0.1:0/callback")
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
            raise ValueError("OAuth callback must use http://127.0.0.1")
        if parsed.query or parsed.fragment:
            raise ValueError("OAuth callback URI must not include query or fragment")
        self._path = parsed.path or "/callback"
        self._result: MCPOAuthCallbackResult | None = None
        owner = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                owner._handle(self)

            def log_message(self, _format: str, *args: object) -> None:
                del args

        self._server = HTTPServer(("127.0.0.1", parsed.port or 0), _Handler)

    @property
    def redirect_uri(self) -> str:
        port = self._server.server_address[1]
        return f"http://127.0.0.1:{port}{self._path}"

    def wait(
        self, *, expected_state: str, timeout_seconds: float
    ) -> MCPOAuthCallbackResult:
        self._expected_state = expected_state
        deadline = time.monotonic() + float(timeout_seconds)
        try:
            while self._result is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._server.timeout = remaining
                self._server.handle_request()
        finally:
            self._server.server_close()
        if self._result is None:
            raise TimeoutError("OAuth callback timed out")
        return self._result

    def close(self) -> None:
        self._server.server_close()

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlsplit(handler.path)
        try:
            if parsed.path != self._path:
                raise ValueError("OAuth callback path does not match redirect URI")
            values = parse_qs(parsed.query, keep_blank_values=True)
            states = values.get("state", [])
            codes = values.get("code", [])
            errors = values.get("error", [])
            issuers = values.get("iss", [])
            if states != [self._expected_state]:
                raise ValueError("OAuth callback state is invalid")
            if len(issuers) > 1:
                raise ValueError("OAuth callback issuer is invalid")
            issuer = issuers[0].strip() if issuers else ""
            if len(codes) == 1 and codes[0].strip() and not errors:
                self._result = MCPOAuthCallbackResult(
                    code=codes[0].strip(),
                    issuer=issuer,
                )
            elif len(errors) == 1 and errors[0].strip() and not codes:
                error = errors[0].strip()
                if re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", error) is None:
                    raise ValueError("OAuth callback error is invalid")
                self._result = MCPOAuthCallbackResult(
                    error=error,
                    issuer=issuer,
                )
            else:
                raise ValueError("OAuth callback response shape is invalid")
        except ValueError as exc:
            handler.send_response(400)
            handler.end_headers()
            handler.wfile.write(
                f"OAuth callback rejected: {exc}. Return to OpenMinion.".encode()
            )
            return
        handler.send_response(200)
        handler.end_headers()
        handler.wfile.write(b"OAuth callback received. Return to OpenMinion.")


__all__ = ["MCPOAuthCallbackResult", "MCPOAuthCallbackServer"]
