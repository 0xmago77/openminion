"""Fixed local HTTP checks executed through the approved lab worker."""

from __future__ import annotations

from typing import Any

import argparse
import http.client
import json
import signal
from http.cookies import CookieError, SimpleCookie
from time import monotonic

_CHECKS = {
    "anonymous-denied": ("GET", "/private", "anonymous", 401),
    "user-allowed": ("GET", "/private", "alice", 200),
    "invalid-denied": ("GET", "/private", "invalid", 401),
    "role-denied": ("GET", "/admin", "alice", 403),
    "object-denied": ("GET", "/users/bob", "alice", 403),
    "headers": ("HEAD", "/private", "alice", 200),
    "redirect-contained": ("GET", "/redirect", "alice", 302),
}


def request_timeout(*_: Any) -> None:
    raise TimeoutError("request_deadline")


def observe(check: str, *, timeout: float) -> dict[str, Any]:
    method, path, identity, expected = _CHECKS[check]
    headers = {} if identity == "anonymous" else {"X-Fixture-Identity": identity}
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=timeout)
    previous = signal.signal(signal.SIGALRM, request_timeout)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read(65_537)
        if len(body) > 65_536:
            raise ValueError("response_limit")
        facts: dict[str, Any] = {"http_status": response.status}
        matched = response.status == expected
        if check == "user-allowed":
            facts["marker_matched"] = b"fixture-private-ok" in body
            matched = matched and facts["marker_matched"]
        if check == "headers":
            cookies = SimpleCookie()
            for name, value in response.getheaders():
                if name.lower() == "set-cookie":
                    cookies.load(value)
            content_type = (
                response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            )
            facts.update(
                content_type=content_type
                if content_type in {"application/json", "text/html", "text/plain"}
                else "other",
                nosniff=response.getheader("X-Content-Type-Options", "") == "nosniff",
                content_security_policy_present=bool(
                    response.getheader("Content-Security-Policy")
                ),
                cookie_attributes=[
                    {
                        "secure": bool(item["secure"]),
                        "httponly": bool(item["httponly"]),
                        "samesite": str(item["samesite"]).lower()
                        if str(item["samesite"]).lower() in {"strict", "lax", "none"}
                        else "unspecified",
                    }
                    for item in cookies.values()
                ],
            )
        return {
            "check_id": check,
            "identity_id": identity,
            "status": "completed",
            "observed": facts,
            "expectation_matched": matched,
        }
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        connection.close()


def run_checks(checks: list[str], identity: str | None = None) -> dict[str, Any]:
    if len(checks) != len(set(checks)) or any(check not in _CHECKS for check in checks):
        raise ValueError("Checks must be unique declared IDs")
    if identity is not None and any(_CHECKS[check][2] != identity for check in checks):
        raise ValueError("Identity does not match the fixed check")
    ordered = list(checks)
    if {"role-denied", "object-denied"}.intersection(checks):
        ordered = ["user-allowed", *[item for item in checks if item != "user-allowed"]]
    results = []
    identity_ready = False
    deadline = monotonic() + 60
    for check in ordered:
        result: dict[str, Any] = {
            "check_id": check,
            "identity_id": _CHECKS[check][2],
            "status": "incomplete",
            "observed": {},
            "expectation_matched": None,
        }
        if check in {"role-denied", "object-denied"} and not identity_ready:
            result["error_code"] = "identity_prerequisite_failed"
        elif monotonic() >= deadline:
            result["error_code"] = "deadline"
        else:
            try:
                result = observe(check, timeout=min(5, deadline - monotonic()))
            except (OSError, http.client.HTTPException, ValueError, CookieError):
                result["error_code"] = "request_incomplete"
        if check == "user-allowed":
            identity_ready = result["expectation_matched"] is True
        results.append(result)
    return {
        "schema_version": "local-web-checks/v1",
        "checks": results,
        "status": "completed"
        if all(item["status"] == "completed" for item in results)
        else "partial",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checks", nargs="*")
    parser.add_argument(
        "--identity", choices=("anonymous", "alice", "bob", "admin", "invalid")
    )
    args = parser.parse_args()
    result = run_checks(args.checks or list(_CHECKS), args.identity)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
