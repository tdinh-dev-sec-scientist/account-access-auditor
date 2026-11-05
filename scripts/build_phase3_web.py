#!/usr/bin/env python3
"""Build the Phase 3 deployable static console without raw report artifacts."""

from __future__ import annotations

import argparse
import json
import re
import secrets
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phase3.web_bundle import safe_fixture_profile  # noqa: E402

DEFAULT_OUTPUT = ROOT / "build" / "phase3" / "web"
PROFILE_SOURCES = (
    ("misconfigured", "Misconfigured Moto fixture", "aws_audit_results.json"),
    ("no-trail", "No CloudTrail Moto fixture", "aws_audit_results_no-trail.json"),
)


# Only a Cognito Hosted UI origin may be added to the console's connect-src, and
# only for invite-only sign-in: the browser must POST to its /oauth2/token.
_COGNITO_HOSTED_UI = re.compile(
    r"^https://[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])\.auth\.[a-z0-9-]+\.amazoncognito\.com$"
)
_META_CONNECT_SRC = "connect-src 'self';"


def build_web_bundle(output: Path = DEFAULT_OUTPUT, *, auth_origin: str | None = None) -> Path:
    if auth_origin is not None and not _COGNITO_HOSTED_UI.fullmatch(auth_origin):
        raise ValueError(
            "auth origin must be a Cognito Hosted UI origin such as https://<prefix>.auth.<region>.amazoncognito.com"
        )
    fixture_key = secrets.token_bytes(32)
    profiles = {}
    for key, label, filename in PROFILE_SOURCES:
        report_path = ROOT / "results" / filename
        if not report_path.is_file():
            raise FileNotFoundError(f"required local fixture is missing: results/{filename}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        profiles[key] = safe_fixture_profile(report, key=key, label=label, pseudonym_key=fixture_key)

    output.mkdir(parents=True, exist_ok=True)
    template = (ROOT / "scripts" / "console" / "index.html").read_text(encoding="utf-8")
    data = json.dumps({"profiles": profiles}, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    data = data.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    html = template.replace("{{CONSOLE_DATA}}", data)
    if auth_origin is not None:
        if html.count(_META_CONNECT_SRC) != 1:
            raise ValueError("console template must contain exactly one connect-src 'self' directive")
        html = html.replace(_META_CONNECT_SRC, f"connect-src 'self' {auth_origin};")
    html = html.replace('href="../"', 'href="/"')
    html = html.replace('href="../report.html"', 'href="/api/latest"')
    html = html.replace('href="../aws_audit_results.json"', 'href="/api/latest"')
    html = html.replace("Source report", "Public snapshot")
    html = html.replace("View JSON evidence", "View public snapshot")
    (output / "index.html").write_text(html, encoding="utf-8")
    for name in ("console.css", "console.js", "status.js", "knowledge.js", "auth.js"):
        shutil.copy2(ROOT / "scripts" / "console" / name, output / name)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--auth-origin",
        help="Cognito Hosted UI origin to allow in connect-src for invite-only sign-in.",
    )
    args = parser.parse_args()
    try:
        result = build_web_bundle(args.output.resolve(), auth_origin=args.auth_origin)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"Built sanitized Phase 3 static console at {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
