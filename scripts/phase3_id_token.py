#!/usr/bin/env python3
"""Sign in through the Cognito Hosted UI and save an ID token for API tests.

    python3 scripts/phase3_id_token.py --profile vorrin-admin --bucket-prefix vorrin \\
        --domain-prefix <PHASE3_COGNITO_DOMAIN_PREFIX> \\
        --redirect-uri https://tdinh-dev-sec-scientist.github.io/Vorrin/

The redirect URI must be one of the user pool client's callback URLs (set
PHASE3_AUTH_EXTRA_CALLBACK_URLS before the console exists). The script prints
a sign-in link that uses the authorization-code flow with PKCE. After you sign
in, the browser lands on the redirect page with ``?code=...`` in the address
bar: paste that whole address back here. The code is single use and worthless
without the verifier, which never leaves this process.

The ID token is written to build/phase3/id-token (mode 0600, gitignored) and
never printed. It expires after 60 minutes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "build/phase3/id-token"


class TokenError(RuntimeError):
    pass


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def hosted_ui(domain_prefix: str, region: str) -> str:
    return f"https://{domain_prefix}.auth.{region}.amazoncognito.com"


def authorize_url(base: str, client_id: str, redirect_uri: str, challenge: str, state: str) -> str:
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid email",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
    )
    return f"{base}/oauth2/authorize?{query}"


def code_from_redirect(pasted: str, redirect_uri: str, state: str) -> str:
    parsed = urllib.parse.urlsplit(pasted.strip())
    expected = urllib.parse.urlsplit(redirect_uri)
    if (parsed.scheme, parsed.netloc, parsed.path) != (expected.scheme, expected.netloc, expected.path):
        raise TokenError("the pasted address is not the configured redirect page")
    params = urllib.parse.parse_qs(parsed.query)
    if "error" in params:
        raise TokenError(f"sign-in failed: {params['error'][0]}")
    if params.get("state") != [state]:
        raise TokenError("the sign-in state does not match; start again")
    codes = params.get("code") or []
    if len(codes) != 1 or not codes[0]:
        raise TokenError("the pasted address has no authorization code")
    return codes[0]


def exchange(base: str, client_id: str, redirect_uri: str, code: str, verifier: str, opener=None) -> str:
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        }
    ).encode("ascii")
    request = urllib.request.Request(
        f"{base}/oauth2/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with (opener or urllib.request.urlopen)(request, timeout=30) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise TokenError(f"token exchange failed with HTTP {exc.code}; sign in again") from None
    token = payload.get("id_token")
    if not isinstance(token, str) or token.count(".") != 2:
        raise TokenError("the token response has no ID token")
    return token


def save(token: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(token)
    path.chmod(0o600)


def discover_client_id(profile: str, region: str, bucket_prefix: str) -> str:
    import boto3

    client = boto3.session.Session(profile_name=profile, region_name=region).client("cognito-idp")
    pools = [
        pool["Id"]
        for page in client.get_paginator("list_user_pools").paginate(MaxResults=60)
        for pool in page["UserPools"]
        if pool["Name"] == f"{bucket_prefix}-p3-console-users"
    ]
    if len(pools) != 1:
        raise TokenError("expected exactly one console user pool; is Stage 2 applied?")
    clients = [
        item["ClientId"]
        for page in client.get_paginator("list_user_pool_clients").paginate(
            UserPoolId=pools[0], MaxResults=60
        )
        for item in page["UserPoolClients"]
        if item["ClientName"] == f"{bucket_prefix}-p3-console"
    ]
    if len(clients) != 1:
        raise TokenError("expected exactly one console app client")
    return clients[0]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--bucket-prefix", required=True)
    parser.add_argument("--domain-prefix", required=True)
    parser.add_argument("--redirect-uri", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    try:
        client_id = discover_client_id(args.profile, args.region, args.bucket_prefix)
        base = hosted_ui(args.domain_prefix, args.region)
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(24)
        print("Open this link, sign in, then copy the full address of the page you land on:\n")
        print(authorize_url(base, client_id, args.redirect_uri, challenge, state))
        pasted = input("\nPaste the address here: ")
        code = code_from_redirect(pasted, args.redirect_uri, state)
        token = exchange(base, client_id, args.redirect_uri, code, verifier)
    except TokenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    save(token, args.output)
    print(f"Saved the ID token to {args.output} (valid for 60 minutes).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
