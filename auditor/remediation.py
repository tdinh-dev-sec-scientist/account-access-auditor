"""Review-bound IaC remediation previews and local-only sandbox rescans."""

from __future__ import annotations

import base64
import difflib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, urlsplit

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from .redaction import ACCESS_KEY_PATTERN
from .severity import Severity
from .utils.process import credential_safe_environment

SCHEMA_VERSION = "1.0.0"
MAX_PLAN_BYTES = 1_048_576
MAX_OPERATIONS = 25
MAX_EDIT_CHARS = 16_384
MAX_FILE_BYTES = 2_097_152
MAX_SOURCE_BYTES = 1_073_741_824
_FINGERPRINT = re.compile(r"^[a-f0-9]{16}$")
_REVIEWER = re.compile(r"^[A-Za-z0-9-]{1,39}$")
_REVIEW_URL = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)$")
_PRIVATE_TEXT = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})\b"
)
_SENSITIVE_ASSIGNMENT_KEY = (
    r"[\w-]*(?:authorization|password|passwd|passphrase|credential(?:s)?|private[_-]?key|"
    r"secret(?:[_-]?access[_-]?key|[_-]?key)?|"
    r"access[_-]?key|api[_-]?key|token|client[_-]?secret)[\w-]*"
)
_LITERAL_SECRET = re.compile(
    r"(?ix)['\"]?" + _SENSITIVE_ASSIGNMENT_KEY + r"['\"]?\s*[:=]\s*"
    r"(?:(['\"])[^'\"\r\n]{12,}\1|[^\s,#}\]]{12,})"
)
_SENSITIVE_KEY = re.compile(r"(?i)^(?:" + _SENSITIVE_ASSIGNMENT_KEY + r")$")
_SENSITIVE_PATH_PARTS = {
    ".aws",
    ".ssh",
    ".kube",
    ".docker",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "reports",
}
_SENSITIVE_FILENAMES = {
    "credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "AGENTS.md",
    "CLAUDE.md",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}
_SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".p8", ".jks", ".docx")
_IAC_SUFFIXES = {".tf", ".yaml", ".yml", ".json"}


class RemediationError(ValueError):
    """A remediation plan is unsafe, invalid, or cannot be applied exactly."""

    def __init__(self, message: str, *, code: str = "InvalidRemediation") -> None:
        super().__init__(message)
        self.code = code


def _contains_credential_material(value: str) -> bool:
    return bool(
        ACCESS_KEY_PATTERN.search(value) or _PRIVATE_TEXT.search(value) or _LITERAL_SECRET.search(value)
    )


def _contains_sensitive_yaml_block(value: str) -> bool:
    """Detect block scalars below sensitive keys without constructing YAML values."""
    try:
        documents = yaml.compose_all(value, Loader=yaml.BaseLoader)
        roots = list(documents)
    except yaml.YAMLError:
        raise RemediationError(
            "remediation YAML target cannot be checked for sensitive material",
            code="SensitiveRemediationBlocked",
        ) from None

    pending: list[tuple[Any, bool]] = [(root, False) for root in roots if root is not None]
    visited: set[tuple[int, bool]] = set()
    while pending:
        node, sensitive_context = pending.pop()
        state = (id(node), sensitive_context)
        if state in visited:
            continue
        visited.add(state)

        if isinstance(node, ScalarNode):
            is_multiline = node.end_mark.line > node.start_mark.line
            if sensitive_context and (node.style in {"|", ">"} or is_multiline):
                return True
        elif isinstance(node, MappingNode):
            for key_node, value_node in node.value:
                key_is_sensitive = isinstance(key_node, ScalarNode) and bool(
                    _SENSITIVE_KEY.fullmatch(key_node.value)
                )
                pending.append((key_node, sensitive_context))
                pending.append((value_node, sensitive_context or key_is_sensitive))
        elif isinstance(node, SequenceNode):
            pending.extend((child, sensitive_context) for child in node.value)
    return False


def _contains_file_credential_material(value: str, path: str) -> bool:
    return _contains_credential_material(value) or (
        Path(path).suffix.lower() in {".yaml", ".yml"} and _contains_sensitive_yaml_block(value)
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RemediationError("remediation plan contains duplicate JSON keys")
        result[key] = value
    return result


def _load_plan(plan: dict[str, Any] | str | Path) -> dict[str, Any]:
    if isinstance(plan, dict):
        document = plan
    else:
        path = Path(plan)
        if path.is_symlink() or not path.is_file():
            raise RemediationError("remediation plan must be a regular JSON file")
        if path.stat().st_size > MAX_PLAN_BYTES:
            raise RemediationError("remediation plan exceeds the 1 MiB size limit")
        try:
            document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
        except RemediationError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise RemediationError("remediation plan is not valid UTF-8 JSON") from None
    _validate_plan(document, require_approval=False)
    return document


def _validate_plan(document: Any, *, require_approval: bool) -> None:
    required = {"schema_version", "target", "review", "target_fingerprints", "operations"}
    if not isinstance(document, dict) or set(document) != required:
        raise RemediationError("remediation plan has missing or unsupported fields")
    if document["schema_version"] != SCHEMA_VERSION:
        raise RemediationError("unsupported remediation plan schema version")
    if document["target"] == "production":
        raise RemediationError(
            "production remediation is never applied by the auditor", code="ProductionApplyBlocked"
        )
    if document["target"] != "sandbox":
        raise RemediationError("target must be the isolated local sandbox")

    review = document["review"]
    if (
        not isinstance(review, dict)
        or not isinstance(review.get("status"), str)
        or review["status"]
        not in {
            "PENDING",
            "APPROVED",
        }
    ):
        raise RemediationError("review must be PENDING or APPROVED")
    if review["status"] == "PENDING":
        if set(review) != {"status"}:
            raise RemediationError("pending review cannot carry approval metadata")
        if require_approval:
            raise RemediationError(
                "sandbox apply requires an approved pull request review", code="ReviewRequired"
            )
    else:
        if set(review) != {"status", "reviewer", "reference", "preview_sha256"}:
            raise RemediationError(
                "approved review must identify its reviewer, pull request, and preview digest"
            )
        reviewer = review["reviewer"]
        reference = review["reference"]
        digest = review["preview_sha256"]
        if not isinstance(reviewer, str) or not _REVIEWER.fullmatch(reviewer):
            raise RemediationError("reviewer must be a GitHub login")
        if not isinstance(reference, str) or not _REVIEW_URL.fullmatch(reference):
            raise RemediationError("review reference must be an HTTPS pull request URL")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise RemediationError("approved review must bind to a 64-character preview SHA-256")

    fingerprints = document["target_fingerprints"]
    if (
        not isinstance(fingerprints, list)
        or not fingerprints
        or len(fingerprints) > 100
        or any(not isinstance(item, str) or not _FINGERPRINT.fullmatch(item) for item in fingerprints)
        or len(set(fingerprints)) != len(fingerprints)
    ):
        raise RemediationError("target_fingerprints must be a unique list of exact finding fingerprints")

    operations = document["operations"]
    if not isinstance(operations, list) or not operations or len(operations) > MAX_OPERATIONS:
        raise RemediationError(f"operations must contain 1 to {MAX_OPERATIONS} edits")
    for operation in operations:
        if not isinstance(operation, dict) or set(operation) != {"op", "path", "before", "after"}:
            raise RemediationError("each operation must contain only op, path, before, and after")
        if operation["op"] != "replace_text":
            raise RemediationError("only exact replace_text operations are supported")
        _validate_relative_iac_path(operation["path"])
        before, after = operation["before"], operation["after"]
        if (
            not isinstance(before, str)
            or not isinstance(after, str)
            or not before
            or not after
            or len(before) > MAX_EDIT_CHARS
            or len(after) > MAX_EDIT_CHARS
            or before == after
            or "\x00" in before
            or "\x00" in after
        ):
            raise RemediationError("replace_text requires distinct, bounded UTF-8 text values")
        if _contains_credential_material(before) or _contains_credential_material(after):
            raise RemediationError(
                "remediation preview cannot contain credential or private-key material",
                code="SensitiveRemediationBlocked",
            )


def _validate_relative_iac_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise RemediationError("remediation path must be a relative POSIX IaC path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or any(char in value for char in "*?[]:")
        or path.suffix.lower() not in _IAC_SUFFIXES
    ):
        raise RemediationError("remediation path must be an exact relative .tf, .yaml, .yml, or .json file")
    return path


def _is_sensitive(relative: Path) -> bool:
    parts = relative.parts
    name = relative.name
    return (
        any(part in _SENSITIVE_PATH_PARTS for part in parts)
        or any(part == ".env" or part.startswith(".env.") for part in parts)
        or name in _SENSITIVE_FILENAMES
        or name.endswith(_SENSITIVE_SUFFIXES)
        or (name == "coverage.json" and "results" in parts)
        or name == ".coverage"
    )


def _source_digest(root: Path) -> str:
    digest = hashlib.sha256()
    total_bytes = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in directories + files:
            if (current_path / name).is_symlink():
                raise RemediationError("source sandbox refuses symbolic links", code="SymlinkBlocked")
        directories[:] = sorted(
            name for name in directories if not _is_sensitive((current_path / name).relative_to(root))
        )
        for name in sorted(files):
            path = current_path / name
            relative = path.relative_to(root)
            if _is_sensitive(relative):
                continue
            size = path.stat().st_size
            total_bytes += size
            if total_bytes > MAX_SOURCE_BYTES:
                raise RemediationError("source exceeds the 1 GiB sandbox size limit")
            digest.update(b"F\0" + relative.as_posix().encode("utf-8") + b"\0")
            file_digest = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    file_digest.update(block)
            digest.update(file_digest.hexdigest().encode("ascii"))
            digest.update(b"\0")
    return digest.hexdigest()


def _read_changes(source: Path, plan: dict[str, Any]) -> tuple[dict[str, tuple[str, str]], str]:
    changes: dict[str, tuple[str, str]] = {}
    for operation in plan["operations"]:
        relative = _validate_relative_iac_path(operation["path"])
        if _is_sensitive(Path(*relative.parts)):
            raise RemediationError(
                "sensitive source paths cannot be used in remediation previews",
                code="SensitiveRemediationBlocked",
            )
        target = source.joinpath(*relative.parts)
        if (
            target.is_symlink()
            or not target.is_file()
            or not target.resolve().is_relative_to(source.resolve())
        ):
            raise RemediationError("remediation target must be a regular file inside the source tree")
        if target.stat().st_size > MAX_FILE_BYTES:
            raise RemediationError("remediation target exceeds the 2 MiB size limit")
        key = relative.as_posix()
        if key not in changes:
            try:
                original = target.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                raise RemediationError("remediation target must be readable UTF-8 text") from None
            if _contains_file_credential_material(original, key):
                raise RemediationError(
                    "remediation preview cannot expose credential or private-key material",
                    code="SensitiveRemediationBlocked",
                )
            changes[key] = (original, original)
        original, current = changes[key]
        before = operation["before"]
        if current.count(before) != 1:
            raise RemediationError("each exact remediation edit must match exactly once", code="EditMismatch")
        changes[key] = (original, current.replace(before, operation["after"], 1))

    for relative, (_, after) in changes.items():
        if _contains_file_credential_material(after, relative):
            raise RemediationError(
                "remediation preview cannot expose credential or private-key material",
                code="SensitiveRemediationBlocked",
            )

    patches: list[str] = []
    for relative, (before, after) in sorted(changes.items()):
        patches.extend(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
                n=0,
            )
        )
    patch_text = "".join(patches)
    if _contains_credential_material(patch_text):
        raise RemediationError(
            "remediation preview cannot expose credential or private-key material",
            code="SensitiveRemediationBlocked",
        )
    return changes, patch_text


def create_remediation_preview(
    *, source_dir: str | Path, plan: dict[str, Any] | str | Path
) -> dict[str, Any]:
    """Render a deterministic patch preview without modifying source files."""
    source = Path(source_dir)
    if source.is_symlink() or not source.is_dir():
        raise RemediationError("source must be an existing directory")
    source = source.resolve()
    document = _load_plan(plan)
    changes, patch_text = _read_changes(source, document)
    source_sha256 = _source_digest(source)
    changed_files = [
        {
            "path": relative,
            "before_sha256": hashlib.sha256(before.encode("utf-8")).hexdigest(),
            "after_sha256": hashlib.sha256(after.encode("utf-8")).hexdigest(),
        }
        for relative, (before, after) in sorted(changes.items())
    ]
    identity = {
        "source_sha256": source_sha256,
        "target": document["target"],
        "target_fingerprints": document["target_fingerprints"],
        "changed_files": changed_files,
        "patch": patch_text,
    }
    preview_sha256 = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "PREVIEW",
        "target": "sandbox",
        "review": document["review"],
        "source_sha256": source_sha256,
        "target_fingerprints": document["target_fingerprints"],
        "changed_files": changed_files,
        "patch": patch_text,
        "preview_sha256": preview_sha256,
    }


def _copy_sandbox(source: Path, destination: Path) -> None:
    for current, directories, files in os.walk(source, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in directories + files:
            if (current_path / name).is_symlink():
                raise RemediationError("source sandbox refuses symbolic links", code="SymlinkBlocked")
        directories[:] = sorted(
            name for name in directories if not _is_sensitive((current_path / name).relative_to(source))
        )
        relative_directory = current_path.relative_to(source)
        target_directory = destination / relative_directory
        target_directory.mkdir(parents=True, exist_ok=True)
        for name in sorted(files):
            source_file = current_path / name
            relative = source_file.relative_to(source)
            if _is_sensitive(relative):
                continue
            target_file = destination / relative
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target_file)


def _apply_changes(sandbox: Path, changes: dict[str, tuple[str, str]]) -> None:
    for relative, (_before, after) in changes.items():
        destination = sandbox.joinpath(*PurePosixPath(relative).parts)
        if (
            destination.is_symlink()
            or not destination.is_file()
            or not destination.resolve().is_relative_to(sandbox.resolve())
        ):
            raise RemediationError("sandbox target is not a regular in-tree file")
        destination.chmod(destination.stat().st_mode | stat.S_IWUSR)
        destination.write_text(after, encoding="utf-8")


def _scan(sandbox: Path, *, fail_on: str) -> dict[str, Any]:
    from .iac.scanning import scan_paths

    return scan_paths([sandbox], root=sandbox, fail_on=fail_on)


def _github_source_context(source_dir: Path) -> tuple[str, str, str]:
    """Return the GitHub origin and repository-relative source directory."""
    environment = credential_safe_environment()
    try:
        root_result = subprocess.run(
            ["git", "-C", str(source_dir), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL,
            env=environment,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        raise RemediationError(
            "source GitHub origin could not be verified", code="ReviewVerificationUnavailable"
        ) from None
    if root_result.returncode:
        raise RemediationError(
            "source GitHub origin could not be verified", code="ReviewVerificationUnavailable"
        )
    repository_root = Path(root_result.stdout.strip()).resolve()
    source = source_dir.resolve()
    if not source.is_relative_to(repository_root):
        raise RemediationError(
            "source directory is outside its Git repository", code="ReviewVerificationUnavailable"
        )

    try:
        remote_result = subprocess.run(
            ["git", "-C", str(repository_root), "remote", "get-url", "origin"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL,
            env=environment,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        raise RemediationError(
            "source GitHub origin could not be verified", code="ReviewVerificationUnavailable"
        ) from None
    if remote_result.returncode:
        raise RemediationError(
            "source GitHub origin could not be verified", code="ReviewVerificationUnavailable"
        )

    remote = remote_result.stdout.strip()
    scp_match = re.fullmatch(r"git@github\.com:([^/]+)/([^/]+?)(?:\.git)?", remote)
    if scp_match:
        owner, repository = scp_match.groups()
    else:
        parsed = urlsplit(remote)
        if (
            parsed.scheme not in {"https", "ssh"}
            or parsed.hostname is None
            or parsed.hostname.casefold() != "github.com"
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or (parsed.scheme == "https" and parsed.username is not None)
            or (parsed.scheme == "ssh" and parsed.username not in {None, "git"})
        ):
            raise RemediationError(
                "source origin must be a GitHub repository", code="ReviewVerificationUnavailable"
            )
        origin_parts = parsed.path.strip("/").split("/")
        if len(origin_parts) != 2:
            raise RemediationError(
                "source origin must be a GitHub repository", code="ReviewVerificationUnavailable"
            )
        owner, repository = origin_parts
        if repository.endswith(".git"):
            repository = repository[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repository):
        raise RemediationError(
            "source origin must be a GitHub repository", code="ReviewVerificationUnavailable"
        )
    prefix = source.relative_to(repository_root).as_posix()
    return owner, repository, "" if prefix == "." else prefix


def _flatten_github_pages(value: Any) -> list[Any] | None:
    if not isinstance(value, list) or any(not isinstance(page, list) for page in value):
        return None
    return [item for page in value for item in page]


def _verify_preview_files(
    *,
    files_pages: Any,
    preview: dict[str, Any],
    source_prefix: str,
    owner: str,
    repository: str,
    head_sha: str,
    environment: dict[str, str],
) -> bool:
    """Require the PR's complete changed-file set and content to match the preview."""
    files = _flatten_github_pages(files_pages)
    changed_files = preview.get("changed_files")
    if files is None or not isinstance(changed_files, list) or not changed_files:
        return False

    expected: dict[str, str] = {}
    for item in changed_files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            return False
        try:
            relative = _validate_relative_iac_path(item["path"]).as_posix()
        except RemediationError:
            return False
        expected_path = f"{source_prefix}/{relative}" if source_prefix else relative
        after_sha256 = item.get("after_sha256")
        if (
            expected_path in expected
            or not isinstance(after_sha256, str)
            or not re.fullmatch(r"[a-f0-9]{64}", after_sha256)
        ):
            return False
        expected[expected_path] = after_sha256

    actual: dict[str, str] = {}
    for item in files:
        if not isinstance(item, dict):
            return False
        filename = item.get("filename")
        blob_sha = item.get("sha")
        if (
            not isinstance(filename, str)
            or item.get("status") != "modified"
            or not isinstance(blob_sha, str)
            or not re.fullmatch(r"[a-f0-9]{40,64}", blob_sha)
            or filename in actual
        ):
            return False
        actual[filename] = blob_sha
    if set(actual) != set(expected):
        return False

    for filename, blob_sha in actual.items():
        try:
            encoded_filename = quote(filename, safe="/")
            file_result = subprocess.run(
                [
                    "gh",
                    "api",
                    f"repos/{owner}/{repository}/contents/{encoded_filename}",
                    "-F",
                    f"ref={head_sha}",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
                stdin=subprocess.DEVNULL,
                env=environment,
            )
        except FileNotFoundError:
            raise RemediationError(
                "GitHub CLI is unavailable for review verification", code="ReviewVerificationUnavailable"
            ) from None
        except subprocess.TimeoutExpired:
            raise RemediationError(
                "GitHub pull request review verification timed out", code="ReviewVerificationUnavailable"
            ) from None
        if file_result.returncode:
            raise RemediationError(
                "GitHub pull request file content could not be verified",
                code="ReviewVerificationUnavailable",
            )
        try:
            file_document = json.loads(file_result.stdout)
        except (json.JSONDecodeError, TypeError):
            raise RemediationError(
                "GitHub pull request file content returned invalid JSON",
                code="ReviewVerificationUnavailable",
            ) from None
        if not isinstance(file_document, dict) or file_document.get("sha") != blob_sha:
            return False

        try:
            blob_result = subprocess.run(
                ["gh", "api", f"repos/{owner}/{repository}/git/blobs/{blob_sha}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
                stdin=subprocess.DEVNULL,
                env=environment,
            )
        except FileNotFoundError:
            raise RemediationError(
                "GitHub CLI is unavailable for review verification", code="ReviewVerificationUnavailable"
            ) from None
        except subprocess.TimeoutExpired:
            raise RemediationError(
                "GitHub pull request review verification timed out", code="ReviewVerificationUnavailable"
            ) from None
        if blob_result.returncode:
            raise RemediationError(
                "GitHub pull request file content could not be verified",
                code="ReviewVerificationUnavailable",
            )
        try:
            blob = json.loads(blob_result.stdout)
            content_value = blob.get("content") if isinstance(blob, dict) else None
            if (
                not isinstance(blob, dict)
                or blob.get("encoding") != "base64"
                or not isinstance(content_value, str)
            ):
                return False
            content = base64.b64decode("".join(content_value.split()), validate=True)
        except (json.JSONDecodeError, TypeError, ValueError):
            raise RemediationError(
                "GitHub pull request file content returned invalid JSON",
                code="ReviewVerificationUnavailable",
            ) from None
        if hashlib.sha256(content).hexdigest() != expected[filename]:
            return False
    return True


def _verify_github_review(review: dict[str, Any], preview: dict[str, Any], source_dir: Path) -> bool:
    """Confirm the PR approval and changed file contents match the local preview."""
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RemediationError(
            "set a read-only GH_TOKEN to verify pull request approval",
            code="ReviewVerificationUnavailable",
        )
    environment = credential_safe_environment()
    environment["GH_TOKEN"] = token
    environment["GH_HOST"] = "github.com"
    match = _REVIEW_URL.fullmatch(review.get("reference", ""))
    if match is None:
        return False
    owner, repository, number = match.groups()
    source_owner, source_repository, source_prefix = _github_source_context(source_dir)
    if (owner.casefold(), repository.casefold()) != (
        source_owner.casefold(),
        source_repository.casefold(),
    ):
        return False
    preview_sha256 = preview.get("preview_sha256")
    if not isinstance(preview_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", preview_sha256):
        return False
    api_reviews = f"repos/{owner}/{repository}/pulls/{number}/reviews"
    try:
        pull_result = subprocess.run(
            [
                "gh",
                "pr",
                "view",
                review["reference"],
                "--json",
                "body,reviewDecision,state,headRefOid",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            stdin=subprocess.DEVNULL,
            env=environment,
        )
        reviews_result = subprocess.run(
            ["gh", "api", "--paginate", "--slurp", api_reviews, "-F", "per_page=100"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            stdin=subprocess.DEVNULL,
            env=environment,
        )
    except FileNotFoundError:
        raise RemediationError(
            "GitHub CLI is unavailable for review verification", code="ReviewVerificationUnavailable"
        ) from None
    except subprocess.TimeoutExpired:
        raise RemediationError(
            "GitHub pull request review verification timed out", code="ReviewVerificationUnavailable"
        ) from None
    if pull_result.returncode or reviews_result.returncode:
        raise RemediationError(
            "GitHub pull request review could not be verified", code="ReviewVerificationUnavailable"
        )
    try:
        document = json.loads(pull_result.stdout)
        review_pages = json.loads(reviews_result.stdout)
    except (json.JSONDecodeError, TypeError):
        raise RemediationError(
            "GitHub pull request review returned invalid JSON", code="ReviewVerificationUnavailable"
        ) from None
    if (
        not isinstance(document, dict)
        or document.get("state") != "OPEN"
        or document.get("reviewDecision") != "APPROVED"
        or not isinstance(document.get("headRefOid"), str)
        or not re.fullmatch(r"[a-f0-9]{40,64}", document["headRefOid"])
    ):
        return False
    expected_marker = f"Remediation Preview SHA-256: {preview_sha256}"
    body = document.get("body")
    if not isinstance(body, str) or expected_marker not in body:
        return False
    if not isinstance(review_pages, list) or any(not isinstance(page, list) for page in review_pages):
        return False
    reviews = [item for page in review_pages for item in page]
    reviewer = review["reviewer"].casefold()
    matching = [
        item
        for item in reviews
        if isinstance(item, dict)
        and isinstance(item.get("user"), dict)
        and str(item["user"].get("login", "")).casefold() == reviewer
        and isinstance(item.get("submitted_at"), str)
    ]
    if not matching:
        return False
    latest_time = max(item["submitted_at"] for item in matching)
    latest_reviews = [item for item in matching if item["submitted_at"] == latest_time]
    approved = all(
        item.get("state") == "APPROVED" and item.get("commit_id") == document["headRefOid"]
        for item in latest_reviews
    )
    if not approved:
        return False
    api_files = f"repos/{owner}/{repository}/pulls/{number}/files"
    try:
        files_result = subprocess.run(
            ["gh", "api", "--paginate", "--slurp", api_files, "-F", "per_page=100"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            stdin=subprocess.DEVNULL,
            env=environment,
        )
    except FileNotFoundError:
        raise RemediationError(
            "GitHub CLI is unavailable for review verification", code="ReviewVerificationUnavailable"
        ) from None
    except subprocess.TimeoutExpired:
        raise RemediationError(
            "GitHub pull request review verification timed out", code="ReviewVerificationUnavailable"
        ) from None
    if files_result.returncode:
        raise RemediationError(
            "GitHub pull request files could not be verified", code="ReviewVerificationUnavailable"
        )
    try:
        files_pages = json.loads(files_result.stdout)
    except (json.JSONDecodeError, TypeError):
        raise RemediationError(
            "GitHub pull request files returned invalid JSON", code="ReviewVerificationUnavailable"
        ) from None
    files_match = _verify_preview_files(
        files_pages=files_pages,
        preview=preview,
        source_prefix=source_prefix,
        owner=owner,
        repository=repository,
        head_sha=document["headRefOid"],
        environment=environment,
    )
    if not files_match:
        return False
    try:
        current_result = subprocess.run(
            [
                "gh",
                "pr",
                "view",
                review["reference"],
                "--json",
                "body,reviewDecision,state,headRefOid",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            stdin=subprocess.DEVNULL,
            env=environment,
        )
    except FileNotFoundError:
        raise RemediationError(
            "GitHub CLI is unavailable for review verification", code="ReviewVerificationUnavailable"
        ) from None
    except subprocess.TimeoutExpired:
        raise RemediationError(
            "GitHub pull request review verification timed out", code="ReviewVerificationUnavailable"
        ) from None
    if current_result.returncode:
        raise RemediationError(
            "GitHub pull request review could not be verified", code="ReviewVerificationUnavailable"
        )
    try:
        current = json.loads(current_result.stdout)
    except (json.JSONDecodeError, TypeError):
        raise RemediationError(
            "GitHub pull request review returned invalid JSON", code="ReviewVerificationUnavailable"
        ) from None
    return (
        isinstance(current, dict)
        and current.get("state") == "OPEN"
        and current.get("reviewDecision") == "APPROVED"
        and current.get("headRefOid") == document["headRefOid"]
        and isinstance(current.get("body"), str)
        and expected_marker in current["body"]
    )


def rescan_local_patch_proposal(
    *,
    source_dir: str | Path,
    target_fingerprint: str,
    operations: list[dict[str, Any]],
    fail_on: str = "HIGH",
    rescan: Callable[[Path, str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate a proposed IaC patch only on a temporary copy, then rescan it."""
    threshold = Severity.from_string(fail_on).value
    source_argument = Path(source_dir)
    if source_argument.is_symlink() or not source_argument.is_dir():
        raise RemediationError("source must be an existing directory")
    source = source_argument.resolve()
    plan = {
        "schema_version": SCHEMA_VERSION,
        "target": "sandbox",
        "review": {"status": "PENDING"},
        "target_fingerprints": [target_fingerprint],
        "operations": operations,
    }
    _validate_plan(plan, require_approval=False)
    preview = create_remediation_preview(source_dir=source, plan=plan)
    scan = rescan or (lambda sandbox, selected: _scan(sandbox, fail_on=selected))

    def blocked(reason_code: str, message: str) -> dict[str, Any]:
        return {"status": "BLOCKED", "reason_code": reason_code, "message": message}

    try:
        with tempfile.TemporaryDirectory(prefix="auditor-ai-proposal-") as temporary:
            sandbox = Path(temporary) / "source"
            sandbox.mkdir()
            _copy_sandbox(source, sandbox)
            changes, patch_text = _read_changes(sandbox, plan)
            _apply_changes(sandbox, changes)
            try:
                report = scan(sandbox, threshold)
            except Exception:
                return blocked("RescanFailed", "mandatory proposal rescan failed")
            if not isinstance(report, dict):
                return blocked("InvalidRescanOutput", "proposal rescan returned an invalid report")
            summary = report.get("summary")
            metadata = report.get("metadata")
            contract = report.get("contract")
            if (
                not isinstance(summary, dict)
                or not isinstance(metadata, dict)
                or not isinstance(contract, dict)
            ):
                return blocked("InvalidRescanOutput", "proposal rescan returned an invalid report")
            findings = report.get("findings")
            contract_findings = contract.get("findings")
            scan_run = contract.get("scan_run")
            if (
                not isinstance(findings, list)
                or not isinstance(contract_findings, list)
                or not isinstance(scan_run, dict)
            ):
                return blocked("InvalidRescanOutput", "proposal rescan returned an invalid report")
            if metadata.get("scan_source") != "local-iac" or metadata.get("aws_accessed") is not False:
                return blocked("UnsafeRescanSource", "proposal rescan must be local IaC-only")
            if any(
                isinstance(item, dict) and item.get("fingerprint") == target_fingerprint
                for item in findings + contract_findings
            ):
                return blocked("TargetFindingRemains", "target finding remains after proposal rescan")
            if (
                summary.get("status") != scan_run.get("status")
                or summary.get("gate_status") != scan_run.get("gate_status")
                or summary.get("status") != "PASS"
                or summary.get("gate_status") != "PASS"
            ):
                return blocked("RescanDidNotPass", "proposal rescan did not complete with a passing gate")
            if _source_digest(source) != preview["source_sha256"]:
                return blocked("SourceChangedDuringRescan", "source changed while the proposal was rescanned")
            return {
                "status": "RESCANNED",
                "patch": patch_text,
                "patch_sha256": hashlib.sha256(patch_text.encode("utf-8")).hexdigest(),
                "preview_sha256": preview["preview_sha256"],
                "source_sha256": preview["source_sha256"],
                "changed_files": preview["changed_files"],
                "rescan_status": summary["status"],
                "rescan_gate_status": summary["gate_status"],
            }
    except RemediationError as exc:
        return blocked(exc.code, str(exc))


def _write_new(path: Path, document: dict[str, Any] | str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    payload = document if isinstance(document, str) else json.dumps(document, indent=2, sort_keys=True) + "\n"
    created = False
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    except FileExistsError:
        raise RemediationError(f"refusing to overwrite existing remediation output: {path.name}") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            temporary.unlink(missing_ok=True)


def _prepare_output(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix" and stat.S_IMODE(output.stat().st_mode) & 0o077:
        raise RemediationError("remediation output directory must deny group and other access")


def _result_blocked(
    *,
    output: Path,
    preview: dict[str, Any],
    reason_code: str,
    message: str,
    rescan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary = rescan.get("summary") if isinstance(rescan, dict) else None
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "BLOCKED",
        "reason_code": reason_code,
        "message": message,
        "target": "sandbox",
        "review": preview["review"],
        "preview_sha256": preview["preview_sha256"],
        "source_sha256": preview["source_sha256"],
        "rescan_status": summary.get("status") if isinstance(summary, dict) else None,
        "patch_sha256": None,
    }
    if isinstance(rescan, dict):
        _write_new(output / "rescan-report.json", rescan)
    _write_new(output / "remediation-result.json", result)
    return result


def run_sandbox_remediation(
    *,
    source_dir: str | Path,
    plan: dict[str, Any] | str | Path,
    output_dir: str | Path,
    fail_on: str = "HIGH",
    rescan: Callable[[Path, str], dict[str, Any]] | None = None,
    review_verifier: Callable[[dict[str, Any], str], bool] | None = None,
) -> dict[str, Any]:
    """Apply an approved exact-text plan to a temporary copy and require a clean rescan.

    This sandbox is local-only. It does not load AWS credentials, create AWS
    sessions, run IaC apply commands, or modify the original source directory.
    """
    threshold = Severity.from_string(fail_on).value
    source = Path(source_dir)
    if source.is_symlink() or not source.is_dir():
        raise RemediationError("source must be an existing directory")
    source = source.resolve()
    document = _load_plan(plan)
    _validate_plan(document, require_approval=True)
    output_argument = Path(output_dir)
    if output_argument.is_symlink():
        raise RemediationError("output directory must not be a symbolic link")
    output = output_argument.resolve()
    if output.is_relative_to(source):
        raise RemediationError("remediation output must be outside the source directory")
    names = {"remediation.patch", "rescan-report.json", "remediation-result.json"}
    if any((output / name).exists() for name in names):
        raise RemediationError("remediation output already contains result files")
    preview = create_remediation_preview(source_dir=source, plan=document)
    if document["review"]["preview_sha256"] != preview["preview_sha256"]:
        _prepare_output(output)
        return _result_blocked(
            output=output,
            preview=preview,
            reason_code="ReviewDigestMismatch",
            message="source or proposed edits changed after the pull request review",
        )

    _prepare_output(output)
    try:
        if review_verifier is None:
            approved = _verify_github_review(document["review"], preview, source)
        else:
            approved = review_verifier(document["review"], preview["preview_sha256"])
    except RemediationError as exc:
        return _result_blocked(
            output=output,
            preview=preview,
            reason_code=exc.code,
            message=str(exc),
        )
    except Exception:
        return _result_blocked(
            output=output,
            preview=preview,
            reason_code="ReviewVerificationUnavailable",
            message="GitHub pull request review could not be verified",
        )
    if not approved:
        return _result_blocked(
            output=output,
            preview=preview,
            reason_code="ReviewNotApproved",
            message="the exact remediation preview does not have the required pull request approval",
        )
    scan = rescan or (lambda sandbox, threshold: _scan(sandbox, fail_on=threshold))
    with tempfile.TemporaryDirectory(prefix="auditor-remediation-sandbox-") as temporary:
        sandbox = Path(temporary) / "source"
        sandbox.mkdir()
        _copy_sandbox(source, sandbox)
        changes, patch_text = _read_changes(sandbox, document)
        _apply_changes(sandbox, changes)
        try:
            report = scan(sandbox, threshold)
        except Exception:
            return _result_blocked(
                output=output,
                preview=preview,
                reason_code="RescanFailed",
                message="mandatory post-remediation IaC rescan failed",
            )
        if not isinstance(report, dict):
            report = {}
        summary = report.get("summary") if isinstance(report.get("summary"), dict) else None
        metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
        top_findings = report.get("findings")
        contract = report.get("contract") if isinstance(report.get("contract"), dict) else {}
        contract_findings = contract.get("findings")
        contract_scan = contract.get("scan_run")
        if (
            summary is None
            or not isinstance(top_findings, list)
            or not isinstance(contract_findings, list)
            or not isinstance(contract_scan, dict)
        ):
            return _result_blocked(
                output=output,
                preview=preview,
                reason_code="InvalidRescanOutput",
                message="post-remediation IaC rescan returned an invalid report",
                rescan=report,
            )
        if metadata.get("aws_accessed") is not False or metadata.get("scan_source") != "local-iac":
            return _result_blocked(
                output=output,
                preview=preview,
                reason_code="UnsafeRescanSource",
                message="post-remediation rescan must be local IaC-only",
                rescan=report,
            )
        remaining_targets = {
            item.get("fingerprint")
            for item in top_findings + contract_findings
            if isinstance(item, dict) and item.get("fingerprint") in document["target_fingerprints"]
        }
        if remaining_targets:
            return _result_blocked(
                output=output,
                preview=preview,
                reason_code="TargetFindingRemains",
                message="one or more targeted findings remain after rescan",
                rescan=report,
            )
        if (
            summary.get("status") != contract_scan.get("status")
            or summary.get("gate_status") != contract_scan.get("gate_status")
            or summary.get("status") != "PASS"
            or summary.get("gate_status") != "PASS"
        ):
            return _result_blocked(
                output=output,
                preview=preview,
                reason_code="RescanDidNotPass",
                message="post-remediation IaC rescan did not complete with a passing gate",
                rescan=report,
            )

        if _source_digest(source) != preview["source_sha256"]:
            return _result_blocked(
                output=output,
                preview=preview,
                reason_code="SourceChangedDuringSandbox",
                message="original source changed while the sandbox remediation was running",
                rescan=report,
            )
        patch_sha256 = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "PASS",
            "target": "sandbox",
            "review": document["review"],
            "preview_sha256": preview["preview_sha256"],
            "patch_sha256": patch_sha256,
            "source_sha256": preview["source_sha256"],
            "rescan_status": summary["status"],
            "rescan_gate_status": summary["gate_status"],
            "target_fingerprints": document["target_fingerprints"],
            "changed_files": preview["changed_files"],
        }
        _write_new(output / "remediation.patch", patch_text)
        _write_new(output / "rescan-report.json", report)
        _write_new(output / "remediation-result.json", result)
        return result
