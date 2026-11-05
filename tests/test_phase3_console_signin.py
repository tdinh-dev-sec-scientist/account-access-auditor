"""Invite-only sign-in in a real browser, with the console's CSP enforced.

Optional integration test: it needs Playwright and a Chromium build, which CI
does not install. Every request is answered by page.route handlers that play
CloudFront, the API (401 without the issued bearer token), and the Cognito
Hosted UI and token endpoint. Nothing leaves the machine.

    pip install playwright && playwright install chromium
    pytest -m integration tests/test_phase3_console_signin.py

Set CHROMIUM_PATH to use a Chromium already on the machine.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from phase3.public_api import public_response
from tests.test_phase3_public_api import Store, _snapshot

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://d111111abcdef8.cloudfront.net"
HOSTED = "https://vorrin-console.auth.us-east-1.amazoncognito.com"
CLIENT = "4ab5c6d7e8f9g0h1i2j3k4l5m6"
ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123"
TYPES = {".html": "text/html", ".js": "text/javascript", ".css": "text/css"}

pytestmark = pytest.mark.integration


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _redirect_page(location: str) -> str:
    # A fulfilled 302 is followed outside the interceptor, so fake pages
    # redirect the way a login page does after the user signs in.
    return f"<script>location.replace({json.dumps(location)})</script>"


class FakeCloud:
    def __init__(self, web: Path, latest: str):
        self.web = web
        self.latest = latest
        self.authorize: dict[str, str] = {}
        self.token_requests: list[dict[str, list[str]]] = []
        self.api: list[tuple[str, str]] = []
        self.issued: str | None = None

    def id_token(self) -> str:
        claims = {
            "sub": "1f2e3d4c-5b6a-4789-8abc-def012345678",
            "aud": CLIENT,
            "iss": ISSUER,
            "token_use": "id",
            "exp": int(time.time()) + 3600,
            "email": "invitee@example.com",
            "nonce": self.authorize["nonce"],
        }
        return ".".join([_b64url(b'{"alg":"RS256"}'), _b64url(json.dumps(claims).encode()), "sig"])

    def handle(self, route):
        request = route.request
        url = urlparse(request.url)
        if request.url.startswith(HOSTED + "/oauth2/authorize"):
            self.authorize = {key: values[0] for key, values in parse_qs(url.query).items()}
            callback = f"{ORIGIN}/?" + urlencode({"code": "test-code", "state": self.authorize["state"]})
            return route.fulfill(status=200, content_type="text/html", body=_redirect_page(callback))
        if request.url == HOSTED + "/oauth2/token":
            body = parse_qs(request.post_data)
            self.token_requests.append(body)
            verifier = body.get("code_verifier", [""])[0]
            valid = (
                _b64url(hashlib.sha256(verifier.encode()).digest()) == self.authorize.get("code_challenge")
                and body.get("code") == ["test-code"]
                and "client_secret" not in body
            )
            cors = {"Access-Control-Allow-Origin": ORIGIN}
            if not valid:
                return route.fulfill(status=400, headers=cors, body='{"error":"invalid_grant"}')
            self.issued = self.id_token()
            return route.fulfill(
                status=200,
                headers=cors,
                content_type="application/json",
                body=json.dumps({"id_token": self.issued}),
            )
        if request.url.startswith(HOSTED + "/logout"):
            return route.fulfill(status=200, content_type="text/html", body=_redirect_page(f"{ORIGIN}/"))
        if url.netloc != urlparse(ORIGIN).netloc:
            return route.abort()
        if url.path == "/auth-config.json":
            config = {
                "mode": "invite_only",
                "clientId": CLIENT,
                "hostedUiUrl": HOSTED,
                "redirectUri": f"{ORIGIN}/",
                "scopes": ["openid", "email"],
            }
            return route.fulfill(status=200, content_type="application/json", body=json.dumps(config))
        if url.path.startswith("/api/"):
            header = request.headers.get("authorization", "")
            self.api.append((url.path, header))
            if not self.issued or header != f"Bearer {self.issued}":
                return route.fulfill(
                    status=401, content_type="application/json", body='{"error":"UNAUTHENTICATED"}'
                )
            return route.fulfill(status=200, content_type="application/json", body=self.latest)
        path = self.web / ("index.html" if url.path in ("", "/") else url.path.lstrip("/"))
        if path.is_file():
            return route.fulfill(
                status=200, content_type=TYPES.get(path.suffix, "text/plain"), body=path.read_bytes()
            )
        return route.fulfill(status=404, body="not found")


@pytest.fixture(scope="module")
def browser():
    playwright_api = pytest.importorskip("playwright.sync_api")
    with playwright_api.sync_playwright() as playwright:
        try:
            launched = playwright.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or None)
        except Exception as exc:  # pragma: no cover - depends on the local browser install
            pytest.skip(f"Chromium is not available: {exc}")
        yield launched
        launched.close()


@pytest.fixture
def cloud(tmp_path):
    web = tmp_path / "web"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/build_phase3_web.py"),
            "--output",
            str(web),
            "--auth-origin",
            HOSTED,
        ],
        check=True,
        cwd=ROOT,
        capture_output=True,
    )
    snapshot = _snapshot(datetime.now(UTC).isoformat())
    latest = public_response({"httpMethod": "GET", "path": "/api/latest"}, store=Store(snapshot))["body"]
    return FakeCloud(web, latest)


def _page(browser, cloud):
    from playwright.sync_api import expect

    context = browser.new_context()
    context.route("**/*", cloud.handle)
    page = context.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    return page, expect, errors


def test_anonymous_visitors_see_fixtures_and_send_no_api_request(browser, cloud):
    page, expect, errors = _page(browser, cloud)

    page.goto(f"{ORIGIN}/")

    expect(page.locator("#auth-label")).to_have_text("Sign in", timeout=15000)
    expect(page.locator("#source-label")).to_have_text("Sign in for live data")
    assert cloud.api == []
    assert errors == []


def test_sign_in_uses_pkce_and_loads_live_data_with_the_bearer_token(browser, cloud):
    page, expect, errors = _page(browser, cloud)
    page.goto(f"{ORIGIN}/")
    expect(page.locator("#auth-label")).to_have_text("Sign in", timeout=15000)

    page.click("#auth-button")

    expect(page.locator("#auth-label")).to_have_text("Sign out", timeout=15000)
    expect(page.locator("#scope-select")).to_have_value("live", timeout=15000)
    assert cloud.authorize["code_challenge_method"] == "S256"
    assert len(cloud.authorize["state"]) >= 32 and len(cloud.authorize["nonce"]) >= 32
    assert len(cloud.token_requests) == 1
    assert page.url == f"{ORIGIN}/"
    assert ("/api/latest", f"Bearer {cloud.issued}") in cloud.api
    assert "invitee@example.com" in (page.get_attribute("#auth-button", "title") or "")

    page.reload()
    expect(page.locator("#scope-select")).to_have_value("live", timeout=15000)
    assert len(cloud.token_requests) == 1

    cloud.issued = "revoked"
    page.reload()
    expect(page.locator("#auth-label")).to_have_text("Sign in", timeout=15000)
    expect(page.locator("#source-label")).to_have_text("Sign in for live data")
    assert page.evaluate("sessionStorage.getItem('vorrin-console-session')") is None
    assert errors == []


def test_a_forged_callback_is_rejected_without_a_token_request(browser, cloud):
    page, expect, errors = _page(browser, cloud)

    page.goto(f"{ORIGIN}/?code=stolen-code&state=forged-state")

    expect(page.locator("#source-label")).to_have_text("Sign-in did not complete", timeout=15000)
    assert cloud.token_requests == []
    assert page.url == f"{ORIGIN}/"
    assert errors == []
