from __future__ import annotations

from threading import Thread
import time
from urllib.error import HTTPError
from urllib.request import urlopen

import pytest

from openminion.tools.mcp.oauth_callback import MCPOAuthCallbackServer


def _request(url: str) -> None:
    try:
        with urlopen(url, timeout=2):
            pass
    except HTTPError:
        pass


def _request_sequence(*urls: str) -> None:
    for url in urls:
        _request(url)
        time.sleep(0.02)


def test_loopback_callback_accepts_one_valid_code_response() -> None:
    server = MCPOAuthCallbackServer()
    thread = Thread(
        target=_request,
        args=(f"{server.redirect_uri}?code=abc&state=expected&iss=https://issuer",),
    )
    thread.start()
    result = server.wait(expected_state="expected", timeout_seconds=2)
    thread.join(timeout=2)
    assert result.code == "abc"
    assert result.issuer == "https://issuer"
    assert result.error == ""


def test_loopback_callback_accepts_one_valid_error_response() -> None:
    server = MCPOAuthCallbackServer()
    thread = Thread(
        target=_request,
        args=(f"{server.redirect_uri}?error=access_denied&state=expected",),
    )
    thread.start()
    result = server.wait(expected_state="expected", timeout_seconds=2)
    thread.join(timeout=2)
    assert result.error == "access_denied"
    assert result.code == ""


@pytest.mark.parametrize(
    "query",
    (
        "code=abc&state=wrong",
        "code=abc&code=def&state=expected",
        "code=abc&error=denied&state=expected",
        "error=denied&state=expected&iss=a&iss=b",
        "error=denied%0Ainjected&state=expected",
    ),
)
def test_loopback_callback_ignores_invalid_response_until_valid_callback(
    query: str,
) -> None:
    server = MCPOAuthCallbackServer()
    thread = Thread(
        target=_request_sequence,
        args=(
            f"{server.redirect_uri}?{query}",
            f"{server.redirect_uri}?code=valid&state=expected",
        ),
    )
    thread.start()
    result = server.wait(expected_state="expected", timeout_seconds=2)
    thread.join(timeout=2)
    assert result.code == "valid"
