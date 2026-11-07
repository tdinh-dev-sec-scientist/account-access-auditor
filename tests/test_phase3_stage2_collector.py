import hashlib
import json
import urllib.parse

import pytest

from phase3.stage_evidence import validate_stage_evidence
from scripts import collect_phase3_stage2_evidence as stage2
from scripts import phase3_id_token as token_tool

REVIEWED_AT = "2026-11-06T19:00:00-05:00"
CATEGORIES = sorted(
    ["account_id", "arn", "ip_address", "email", "access_key", "unknown_field", "stable_pseudonym"]
)


def _documents(**overrides):
    values = {
        "reviewer": "Reviewer",
        "reviewed_at": REVIEWED_AT,
        "test_suite_sha256": "a" * 64,
        "passed_categories": CATEGORIES,
        "failed_case_ids": [],
        "leaks": {},
        "unapproved_fields": 0,
        "previous_sha256": "b" * 64,
        "after_sha256": "b" * 64,
        "methods": stage2.method_results(lambda method: 200 if method in {"GET", "HEAD"} else 403),
    }
    values.update(overrides)
    return stage2.build_documents(**values)


def test_generated_evidence_passes_the_stage2_validator(tmp_path):
    files = _documents()
    for path, body in files.items():
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_bytes(body)
    manifest = {"stages": {}}
    stage2.update_manifest(manifest, files, "Reviewer", REVIEWED_AT)
    validate_stage_evidence("stage2", manifest["stages"]["stage2"], evidence_root=tmp_path)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"failed_case_ids": ["test_case_arn"]}, "redaction cases failed"),
        ({"leaks": {"arn": 1}}, "private identifiers"),
        ({"unapproved_fields": 1}, "closed public schema"),
        ({"after_sha256": "c" * 64}, "snapshot changed"),
        ({"methods": stage2.method_results(lambda method: 200)}, "API method results"),
    ],
)
def test_any_failed_check_blocks_the_evidence(overrides, message):
    with pytest.raises(stage2.CollectError, match=message):
        _documents(**overrides)


def test_method_results_treat_refused_connections_as_rejected_and_require_200():
    results = stage2.method_results(
        lambda method: {"GET": 200, "HEAD": 500, "CONNECT": None}.get(method, 405)
    )
    assert results["GET"] == "served"
    assert results["HEAD"] == "failed:500"
    assert results["CONNECT"] == "rejected"
    assert set(results) == {"GET", "HEAD", *stage2.REJECTED_METHODS}


def test_case_results_map_test_names_to_categories():
    xml = (
        '<testsuites><testsuite><testcase name="test_case_arn"/>'
        '<testcase name="test_case_email"><failure message="x"/></testcase>'
        '<testcase name="test_case_ip_address"><skipped/></testcase>'
        '<testcase name="test_helper"/></testsuite></testsuites>'
    )
    assert stage2.case_results(xml) == (["arn"], ["test_case_email", "test_case_ip_address"])


def test_the_real_case_suite_covers_every_required_category():
    passed, failed = stage2.run_case_tests()
    assert failed == []
    assert passed == CATEGORIES


def test_leak_scan_finds_private_values_and_generic_identifiers():
    clean = json.dumps({"scan": {"completed_at": "2026-11-06T18:00:00+00:00"}, "version": "1.0.0"}).encode()
    assert stage2.count_leaks([clean], ["123456789012"]) == {}
    dirty = b'{"a":"123456789012","b":"arn:aws:iam::x","c":"10.0.0.1","d":"me@example.com"}'
    found = stage2.count_leaks([dirty], ["123456789012"])
    assert set(found) == {"value:1234…", "arn", "ip_address", "email"}


class FakeSecrets:
    def __init__(self):
        self.stages = {"v-original": ["AWSCURRENT"]}
        self.moves = []

    def describe_secret(self, SecretId):
        return {"VersionIdsToStages": {k: list(v) for k, v in self.stages.items()}}

    def put_secret_value(self, SecretId, SecretString):
        assert SecretString == stage2.INVALID_KEY
        for stages in self.stages.values():
            stages.remove("AWSCURRENT") if "AWSCURRENT" in stages else None
        self.stages["v-original"].append("AWSPREVIOUS")
        self.stages["v-injected"] = ["AWSCURRENT"]
        return {"VersionId": "v-injected"}

    def update_secret_version_stage(self, SecretId, VersionStage, MoveToVersionId, RemoveFromVersionId):
        self.stages[RemoveFromVersionId].remove(VersionStage)
        self.stages[MoveToVersionId].append(VersionStage)
        self.moves.append((MoveToVersionId, RemoveFromVersionId))


class FakeSfn:
    def __init__(self, final, error=None, fail_start=False):
        self.calls = 0
        self.final, self.error, self.fail_start = final, error, fail_start

    def start_execution(self, stateMachineArn):
        if self.fail_start:
            raise RuntimeError("start failed")
        return {"executionArn": f"{stateMachineArn}:exec-1"}

    def describe_execution(self, executionArn):
        self.calls += 1
        if self.calls < 3:
            return {"status": "RUNNING"}
        return {"status": self.final, **({"error": self.error} if self.error else {})}


def test_publisher_failure_injection_restores_the_original_key():
    secrets = FakeSecrets()
    execution = stage2.inject_publisher_failure(
        secrets, FakeSfn("FAILED", "Phase3PublicationPaused"), "s", "arn:sm", wait=lambda _: None
    )
    assert execution.endswith(":exec-1")
    assert secrets.moves == [("v-original", "v-injected")]
    assert "AWSCURRENT" in secrets.stages["v-original"]


def test_injection_restores_the_key_even_when_the_scan_cannot_start():
    secrets = FakeSecrets()
    with pytest.raises(RuntimeError, match="start failed"):
        stage2.inject_publisher_failure(secrets, FakeSfn("FAILED", fail_start=True), "s", "arn:sm")
    assert "AWSCURRENT" in secrets.stages["v-original"]


def test_injection_rejects_a_scan_that_published_anyway():
    secrets = FakeSecrets()
    with pytest.raises(stage2.CollectError, match="Phase3PublicationPaused"):
        stage2.inject_publisher_failure(secrets, FakeSfn("SUCCEEDED"), "s", "arn:sm", wait=lambda _: None)
    assert "AWSCURRENT" in secrets.stages["v-original"]


def test_injection_requires_a_stored_key():
    secrets = FakeSecrets()
    secrets.stages = {}
    with pytest.raises(stage2.CollectError, match="store the pseudonym key"):
        stage2.inject_publisher_failure(secrets, FakeSfn("FAILED"), "s", "arn:sm")


# -- ID token helper --------------------------------------------------------------


def test_pkce_challenge_is_the_s256_of_the_verifier():
    verifier, challenge = token_tool.pkce_pair()
    assert 43 <= len(verifier) <= 128
    import base64

    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == expected


def test_authorize_url_and_redirect_parsing():
    redirect = "https://owner.github.io/Vorrin/"
    url = token_tool.authorize_url("https://p.auth.us-east-1.amazoncognito.com", "cid", redirect, "ch", "st")
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert query["code_challenge_method"] == ["S256"] and query["redirect_uri"] == [redirect]
    assert token_tool.code_from_redirect(f"{redirect}?code=abc&state=st", redirect, "st") == "abc"
    with pytest.raises(token_tool.TokenError, match="state"):
        token_tool.code_from_redirect(f"{redirect}?code=abc&state=other", redirect, "st")
    with pytest.raises(token_tool.TokenError, match="redirect page"):
        token_tool.code_from_redirect("https://evil.example/Vorrin/?code=abc&state=st", redirect, "st")
    with pytest.raises(token_tool.TokenError, match="access_denied"):
        token_tool.code_from_redirect(f"{redirect}?error=access_denied&state=st", redirect, "st")


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def test_exchange_posts_the_verifier_and_returns_the_id_token(tmp_path):
    seen = {}

    def opener(request, timeout):
        seen["body"] = urllib.parse.parse_qs(request.data.decode())
        seen["url"] = request.full_url
        return _Response({"id_token": "h.p.s", "access_token": "x"})

    token = token_tool.exchange("https://base", "cid", "https://r/", "code1", "ver1", opener=opener)
    assert token == "h.p.s"
    assert seen["url"] == "https://base/oauth2/token"
    assert seen["body"]["code_verifier"] == ["ver1"] and "client_secret" not in seen["body"]
    path = tmp_path / "t" / "id-token"
    token_tool.save(token, path)
    assert path.read_text() == "h.p.s" and (path.stat().st_mode & 0o777) == 0o600
    with pytest.raises(token_tool.TokenError, match="no ID token"):
        token_tool.exchange("https://base", "c", "r", "c", "v", opener=lambda r, timeout: _Response({}))


# -- main() against fake AWS and HTTP ---------------------------------------------

import io  # noqa: E402
import sys  # noqa: E402
import types  # noqa: E402

from phase3.redaction import redact_snapshot  # noqa: E402
from tests.test_phase3_redaction import HMAC_KEY, _report  # noqa: E402


def _fake_boto3(secrets, sfn, public_body):
    def session(profile_name, region_name):
        account = "210987654321" if profile_name == "admin" else "123456789012"

        def client(name):
            if name == "secretsmanager":
                return secrets
            if name == "stepfunctions":
                return sfn
            c = types.SimpleNamespace()
            c.get_caller_identity = lambda: {"Account": account}
            c.get_paginator = lambda op: types.SimpleNamespace(
                paginate=lambda: [{"items": [{"id": "api123", "name": "vorrin-p3-public-api"}]}]
            )
            c.get_item = lambda **kwargs: {"Item": {"snapshot_key": {"S": "snapshots/s1.json"}}}
            c.get_object = lambda Bucket, Key: {"Body": io.BytesIO(public_body)}
            return c

        return types.SimpleNamespace(client=client)

    return types.SimpleNamespace(session=types.SimpleNamespace(Session=session))


def _run_main(monkeypatch, tmp_path, *extra, public=None):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    manifest = evidence / "phase3-stage-acceptance.json"
    manifest.write_text(json.dumps({"schema_version": 3, "stages": {"stage2": {}}}))
    token = tmp_path / "id-token"
    token.write_text("h.p.s")
    body = public or json.dumps(redact_snapshot(_report(), HMAC_KEY)).encode()
    secrets = FakeSecrets()
    fake = _fake_boto3(secrets, FakeSfn("FAILED", "Phase3PublicationPaused"), body)
    monkeypatch.setitem(sys.modules, "boto3", fake)
    monkeypatch.setattr(stage2, "EVIDENCE", evidence)
    monkeypatch.setattr(stage2, "MANIFEST", manifest)
    monkeypatch.setattr(stage2, "fetch", lambda host, path, tok: (200, b'{"status":"ok"}'))
    monkeypatch.setattr(
        stage2, "https_requester", lambda host, path, tok: lambda m: 200 if m in {"GET", "HEAD"} else 403
    )
    monkeypatch.setattr(stage2.time, "sleep", lambda _: None)
    argv = ["collect", "--profile", "admin", "--demo-profile", "demo", "--bucket-prefix", "vorrin",
            "--id-token-file", str(token), "--reviewer", "Reviewer", *extra]  # fmt: skip
    monkeypatch.setattr(sys, "argv", argv)
    return stage2.main(), evidence, manifest, secrets


def test_main_dry_run_skips_the_injection_and_writes_nothing(monkeypatch, tmp_path, capsys):
    code, evidence, _, secrets = _run_main(monkeypatch, tmp_path)
    assert code == 0, capsys.readouterr().err
    assert "Dry run" in capsys.readouterr().out
    assert not (evidence / "stage2").exists() and "v-injected" not in secrets.stages


def test_main_confirmed_writes_valid_evidence_and_restores_the_key(monkeypatch, tmp_path, capsys):
    code, evidence, manifest, secrets = _run_main(monkeypatch, tmp_path, "--confirm-reviewed")
    assert code == 0, capsys.readouterr().err
    assert json.loads(manifest.read_text())["stages"]["stage2"]["status"] == "passed"
    assert "AWSCURRENT" in secrets.stages["v-original"]


def test_main_blocks_a_published_snapshot_with_a_leak(monkeypatch, tmp_path, capsys):
    leaky = json.dumps({"note": "arn:aws:iam::210987654321:role/x"}).encode()
    code, evidence, _, _ = _run_main(monkeypatch, tmp_path, "--confirm-reviewed", public=leaky)
    assert code == 1
    assert "private identifiers" in capsys.readouterr().err
    assert not (evidence / "stage2").exists()


# -- TLS on python.org macOS builds --------------------------------------------------


def test_tls_context_loads_ca_certificates_without_a_system_store(tmp_path, monkeypatch):
    import ssl
    import subprocess
    import sys

    empty = tmp_path / "empty.pem"
    empty.write_text("")
    # A process whose OpenSSL finds no system CA store, like python.org builds on macOS.
    env = {**__import__("os").environ, "SSL_CERT_FILE": str(empty), "SSL_CERT_DIR": str(tmp_path)}
    probe = (
        "import ssl, sys; sys.path.insert(0, '.');"
        "from scripts.phase3_id_token import tls_context as a;"
        "from scripts.collect_phase3_stage2_evidence import tls_context as b;"
        "print(ssl.create_default_context().cert_store_stats()['x509_ca'],"
        " a().cert_store_stats()['x509_ca'], b().cert_store_stats()['x509_ca'],"
        " a().verify_mode == ssl.CERT_REQUIRED and a().check_hostname)"
    )
    out = subprocess.run([sys.executable, "-c", probe], env=env, capture_output=True, text=True, check=True)
    default, token_cas, collector_cas, verifying = out.stdout.split()
    assert int(default) == 0
    assert int(token_cas) > 100 and int(collector_cas) > 100
    assert verifying == "True"
    assert ssl.CERT_REQUIRED


def test_exchange_uses_the_verifying_context_and_reports_network_errors(monkeypatch):
    import urllib.error

    seen = {}

    def fake_urlopen(request, timeout, context):
        seen["context"] = context
        raise urllib.error.URLError("certificate verify failed")

    monkeypatch.setattr(token_tool.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(token_tool.TokenError, match="could not reach the sign-in service"):
        token_tool.exchange("https://base", "c", "https://r/", "code", "verifier")
    assert seen["context"].check_hostname is True
