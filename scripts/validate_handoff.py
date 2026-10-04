#!/usr/bin/env python3
"""Local handoff validation. Only --write-manifest writes after checks pass.

Only read-only Git queries; no configuration collection or network access.
Hashes detect changes, not authenticity or readiness. Requires Python 3.10+.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

COMMON_REQUIRED = (
    "README.md",
    "工作交接/任务交接.md",
    "工作交接/文件导航.md",
    "工作交接/环境与验证.md",
    "工作交接/归档索引.md",
    "工作交接/接收回执.md",
    "配置交接/README.md",
)
MANIFEST = "校验清单.json"
RECEIPT = "工作交接/接收回执.md"
MUTABLE_FILES = {MANIFEST, RECEIPT}
LOCAL_CONFIG = "配置交接/.codex"
LOCAL_MANIFEST = "文件清单.json"
PUBLIC_EXCLUDES = MUTABLE_FILES | {LOCAL_CONFIG + "/"}
FORBIDDEN_PRIVATE_DIRS = {"sessions", "logs", "cache", "history", "plugins", "browser"}
OAUTH_FIELD = re.compile(r"(?i)[\"']?(?:refresh_token|id_token|access_token)[\"']?\s*[:=]")
DIGEST = re.compile(r"[0-9a-f]{64}")
SECRET_PATTERNS = {
    "credential_assignment": re.compile(
        r"""(?i)(?:[\w-]*(?:api[_-]?key|secret[_-]?key|(?:access|refresh|id)[_-]?token|password))"""
        r"""['"]?\s*[:=]\s*['"]?([A-Za-z0-9_.+/=-]{16,})"""
    ),
    "bearer": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{16,}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}
USER_PATH = re.compile(r"/(?:Users|home)/[^\s/]+|[A-Za-z]:\\Users\\")
LOCAL_LINK = re.compile(r"!?\[[^\]]*\]\((<[^>]*>|[^)\n]+)\)")
PLACEHOLDER = re.compile(r"(?im)^\s*(?:TODO|FIXME)(?::|\s|$)|<REPLACE(?:_[A-Z]+)?>")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative(value: object) -> bool:
    """Require canonical portable relative paths; never resolve untrusted input."""
    return (
        isinstance(value, str)
        and bool(value)
        and "\0" not in value
        and "\\" not in value
        and ":" not in value
        and not value.startswith(("~", "/"))
        and all(part not in ("", ".", "..") for part in value.split("/"))
        and PurePosixPath(value).as_posix() == value
    )


def inventory(root: Path, excluded_tree: str | None = None) -> tuple[dict[str, Path], list[str]]:
    files: dict[str, Path] = {}
    errors: list[str] = []

    def on_error(exc: OSError) -> None:
        errors.append(f"cannot enumerate package: {type(exc).__name__}")

    for current, directories, filenames in os.walk(root, followlinks=False, onerror=on_error):
        for name in list(directories):
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                errors.append(f"symlink is not allowed: {relative}")
                directories.remove(name)
            elif relative == excluded_tree:
                directories.remove(name)
            elif name in {".git", "__pycache__", "node_modules"}:
                errors.append(f"runtime/repository directory is not portable: {relative}")
                directories.remove(name)
        for name in filenames:
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                errors.append(f"symlink is not allowed: {relative}")
            elif relative == excluded_tree:
                errors.append(f"private configuration root must be a directory: {relative}")
            elif not path.is_file():
                errors.append(f"unsupported file type: {relative}")
            elif not safe_relative(relative):
                errors.append(f"nonportable package path: {relative}")
            elif name in {".DS_Store", ".git"} or path.suffix == ".pyc":
                errors.append(f"system/repository artifact is not portable: {relative}")
            else:
                files[relative] = path
    return dict(sorted(files.items())), errors


def check_private_git_boundary(root: Path, private_files: dict[str, Path]) -> list[str]:
    """Ignore rules alone do not protect a file already in the index."""
    private_root = root / LOCAL_CONFIG
    repository_found = False
    try:
        result = subprocess.run(
            ["git", "-C", str(root.parent), "rev-parse", "--show-toplevel"],
            capture_output=True, timeout=10, check=False,
        )
        if result.returncode:
            return ["private configuration requires a Git repository with verified ignore rules"] if private_root.exists() else []
        repository = Path(os.fsdecode(result.stdout.rstrip(b"\r\n"))).resolve()
        repository_found = True
        prefix = private_root.relative_to(repository).as_posix()
        tracked = subprocess.run(
            ["git", "-C", str(repository), "ls-files", "--cached", "-z", "--", ":(literal)" + prefix],
            capture_output=True, timeout=10, check=False,
        )
        if tracked.returncode:
            return ["cannot verify private configuration Git tracking status"]
        if tracked.stdout:
            return ["private configuration is tracked or staged; stop before upload"]
        if not private_root.exists():
            return []
        candidates = [prefix + "/.handoff-ignore-probe"]
        candidates.extend(prefix + "/" + relative for relative in private_files)
        expected = {os.fsencode(path) for path in candidates}
        ignored = subprocess.run(
            ["git", "-C", str(repository), "check-ignore", "--no-index", "--stdin", "-z"],
            input=b"\0".join(sorted(expected)) + b"\0",
            capture_output=True, timeout=10, check=False,
        )
        if ignored.returncode not in (0, 1):
            return ["cannot verify private configuration Git ignore rules"]
        if set(ignored.stdout.split(b"\0")) - {b""} != expected:
            return ["private configuration is not fully Git-ignored; set ignore rules before collection"]
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return ["cannot verify private configuration Git boundary"] if private_root.exists() or repository_found else []
    return []


def check_private_content(files: dict[str, Path]) -> list[str]:
    errors: list[str] = []
    for required in ("config.toml", "README.md", "skills/hand-off/SKILL.md"):
        if required not in files:
            errors.append(f"missing private configuration file: {required}")
    for relative, path in files.items():
        if set(PurePosixPath(relative).parts[:-1]) & FORBIDDEN_PRIVATE_DIRS:
            errors.append(f"runtime/login data is not allowed in private configuration: {relative}")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            errors.append(f"private configuration must be UTF-8 for review: {relative}")
            continue
        if not text.strip():
            errors.append(f"private configuration file is empty: {relative}")
        credential_file = (
            "/" not in relative and relative != LOCAL_MANIFEST
            and (path.name == ".env" or path.suffix in {".toml", ".json", ".env", ".sh", ".ps1"})
        )
        for name, pattern in SECRET_PATTERNS.items():
            if credential_file and name in {"credential_assignment", "bearer"}:
                continue
            if pattern.search(text):
                errors.append(f"possible {name} in private metadata/unsupported credential: {relative}")
        if credential_file and OAUTH_FIELD.search(text):
            errors.append(f"OAuth login state is not allowed in private configuration: {relative}")
    if "auth.json" in files:
        data, auth_errors = read_json(files["auth.json"], "private API-key authentication")
        errors.extend(auth_errors)
        if not auth_errors and (
            not isinstance(data, dict)
            or set(data) - {"OPENAI_API_KEY", "auth_mode"}
            or not isinstance(data.get("OPENAI_API_KEY"), str)
            or not data["OPENAI_API_KEY"].strip()
            or ("auth_mode" in data and data["auth_mode"] != "apikey")
        ):
            errors.append("private auth.json must contain only API-key authentication, not login state")
    return errors


def read_json(path: Path, label: str) -> tuple[object, list[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except (OSError, UnicodeError, ValueError) as exc:
        # Do not print source values: a malformed file might contain a secret.
        return None, [f"invalid {label}: {type(exc).__name__}"]


def check_readme_links(root: Path, text: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    text = re.sub(r"(?ms)^\x60{3}.*?^\x60{3}[^\n]*$", "", text)
    for raw in LOCAL_LINK.findall(text):
        target = raw[1:-1] if raw.startswith("<") else re.split(r'\s+["\']', raw)[0]
        try:
            parsed = urlsplit(target)
        except ValueError:
            errors.append("README contains an invalid link")
            continue
        if not target or target.startswith("#") or parsed.scheme in {"http", "https", "mailto"}:
            continue
        if parsed.scheme or parsed.netloc or target.startswith(("~", "/", "\\")):
            warnings.append("README contains an absolute or special link; review portability")
            continue
        local = unquote(parsed.path)
        if "\0" in local or "\\" in local:
            errors.append("README contains an invalid local path")
            continue
        try:
            resolved = (root / local).resolve()
            resolved.relative_to(root.parent)
        except (ValueError, RuntimeError, OSError):
            errors.append("README link escapes project root or cannot be resolved")
            continue
        if not resolved.exists():
            errors.append(f"README link target does not exist: {local}")
    return errors, warnings


def check_config_manifest(files: dict[str, Path]) -> list[str]:
    key = "配置交接/文件清单.json"
    data, errors = read_json(files[key], "configuration manifest")
    if errors:
        return errors
    if not isinstance(data, dict) or not isinstance(data.get("files"), list):
        return ["configuration manifest must contain a 'files' list"]
    seen: set[str] = set()
    for index, entry in enumerate(data["files"]):
        if not isinstance(entry, dict) or not safe_relative(entry.get("path")):
            errors.append(f"configuration manifest entry {index}: unsafe or missing path")
            continue
        relative = entry["path"]
        if relative in seen:
            errors.append(f"duplicate configuration path: {relative}")
        seen.add(relative)
        if not isinstance(entry.get("included"), bool):
            errors.append(f"configuration manifest requires included=true/false: {relative}")
            continue
        package_path = "配置交接/" + relative
        if relative == ".codex" or relative.startswith(".codex/"):
            if entry["included"] or entry.get("transport") != "local_only" or "sha256" in entry:
                errors.append(f"private configuration must be excluded with transport=local_only and no cloud hash: {relative}")
        if entry["included"]:
            if package_path not in files:
                errors.append(f"included configuration file is missing or unsafe: {relative}")
            elif not isinstance(entry.get("sha256"), str) or not DIGEST.fullmatch(entry["sha256"]):
                errors.append(f"included configuration file requires SHA-256: {relative}")
            elif sha256(files[package_path]) != entry["sha256"]:
                errors.append(f"configuration hash mismatch: {relative}")
        else:
            if not entry.get("reason"):
                errors.append(f"excluded configuration has no reason: {relative}")
            if package_path in files:
                errors.append(f"excluded configuration unexpectedly present: {relative}")
    return errors


def build_manifest(scene: str, files: dict[str, Path]) -> dict:
    return {
        "format": 2,
        "scene": scene,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "excludes": sorted(PUBLIC_EXCLUDES),
        "files": [
            {"path": relative, "size": path.stat().st_size, "sha256": sha256(path)}
            for relative, path in files.items() if relative not in MUTABLE_FILES
        ],
    }


def build_private_manifest(files: dict[str, Path]) -> dict:
    return {
        "format": 1,
        "transport": "local_only",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "excludes": [LOCAL_MANIFEST],
        "files": [
            {"path": relative, "size": path.stat().st_size, "sha256": sha256(path)}
            for relative, path in files.items() if relative != LOCAL_MANIFEST
        ],
    }


def check_manifest(scene: str, files: dict[str, Path], private: bool = False) -> list[str]:
    name = LOCAL_MANIFEST if private else MANIFEST
    label = "private validation manifest" if private else "validation manifest"
    if name not in files:
        return [f"missing required file: {name}"]
    data, errors = read_json(files[name], label)
    if errors:
        return errors
    if not isinstance(data, dict) or not isinstance(data.get("files"), list):
        return [f"invalid {label} format or files"]
    if private:
        excludes = {LOCAL_MANIFEST}
        valid = data.get("format") == 1 and data.get("transport") == "local_only"
    else:
        excludes = MUTABLE_FILES if data.get("format") == 1 else PUBLIC_EXCLUDES
        valid = data.get("format") in (1, 2) and data.get("scene") == scene
    if not valid or data.get("excludes") != sorted(excludes):
        return [f"invalid {label} format, scene, exclusions or files"]
    recorded: dict[str, dict] = {}
    for index, entry in enumerate(data["files"]):
        if (
            not isinstance(entry, dict)
            or not safe_relative(entry.get("path"))
            or not isinstance(entry.get("sha256"), str)
            or not DIGEST.fullmatch(entry["sha256"])
            or type(entry.get("size")) is not int
            or entry["size"] < 0
        ):
            errors.append(f"invalid validation manifest entry: {index}")
            continue
        relative = entry["path"]
        if relative in excludes or relative in recorded or (not private and relative.startswith(LOCAL_CONFIG + "/")):
            errors.append(f"duplicate or excluded manifest entry: {relative}")
        recorded[relative] = entry
    actual = {key: value for key, value in files.items() if key not in excludes}
    for relative in sorted(set(recorded) - set(actual)):
        errors.append(f"file removed since manifest: {relative}")
    for relative in sorted(set(actual) - set(recorded)):
        errors.append(f"file added since manifest: {relative}")
    for relative in sorted(set(actual) & set(recorded)):
        if sha256(actual[relative]) != recorded[relative]["sha256"]:
            errors.append(f"sha256 mismatch: {relative}")
        if actual[relative].stat().st_size != recorded[relative]["size"]:
            errors.append(f"size mismatch: {relative}")
    return errors


def validate(
    root: Path, scene: str, write_manifest: bool = False, private_config: bool = False,
) -> tuple[list[str], list[str]]:
    if private_config and scene != "device":
        return ["--private-config is only supported for device handoff"], []
    if root.is_symlink() or not root.is_dir():
        return ["package root must be an existing directory, not a symlink"], []
    root = root.resolve()
    files, errors = inventory(root, excluded_tree=LOCAL_CONFIG)
    warnings: list[str] = []
    private_root = root / LOCAL_CONFIG
    private_files: dict[str, Path] = {}
    safe_private_root = not any(path.is_symlink() for path in (private_root.parent, private_root))
    if safe_private_root and private_root.is_dir():
        private_files, private_errors = inventory(private_root)
        errors.extend("private configuration: " + error for error in private_errors)
        if private_config:
            errors.extend(check_private_content(private_files))
        else:
            warnings.append("local private configuration excluded from cloud validation; use --private-config to verify its content and hashes")
    elif private_config:
        errors.append("private configuration directory is missing or unsafe")
    errors.extend(check_private_git_boundary(root, private_files))
    required = COMMON_REQUIRED + (("配置交接/文件清单.json",) if scene == "device" else ())
    for relative in required:
        if relative not in files:
            errors.append(f"missing required file: {relative}")

    texts: dict[str, str] = {}
    for relative, path in files.items():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            warnings.append(f"non-UTF-8 content not secret-scanned; manual review required: {relative}")
            if relative in required:
                errors.append(f"required text file is not UTF-8: {relative}")
            continue
        texts[relative] = text
        if relative in required and not text.strip():
            errors.append(f"required file is empty: {relative}")
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                errors.append(f"possible {name} in: {relative}")
        if USER_PATH.search(text):
            warnings.append(f"absolute source path needs portability review: {relative}")
        if relative in COMMON_REQUIRED and PLACEHOLDER.search(text):
            errors.append(f"unfinished placeholder in active handoff file: {relative}")

    if "README.md" in texts:
        link_errors, link_warnings = check_readme_links(root, texts["README.md"])
        errors.extend(link_errors)
        warnings.extend(link_warnings)
    if "配置交接/文件清单.json" in files:
        errors.extend(check_config_manifest(files))

    if write_manifest:
        destinations = [(root / MANIFEST, build_manifest(scene, files))] if not errors else []
        if private_config and not errors:
            destinations.append((private_root / LOCAL_MANIFEST, build_private_manifest(private_files)))
        for destination, _ in destinations:
            temporary = destination.with_name("." + destination.name + ".tmp")
            if temporary.exists() or temporary.is_symlink():
                errors.append("temporary manifest path already exists; leave it untouched")
        if not errors:
            for destination, data in destinations:
                temporary = destination.with_name("." + destination.name + ".tmp")
                with temporary.open("x", encoding="utf-8") as handle:
                    if destination.parent == private_root and os.name == "posix":
                        os.chmod(temporary, 0o600)
                    handle.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
                temporary.replace(destination)
    else:
        errors.extend(check_manifest(scene, files))
        if private_config:
            errors.extend(check_manifest(scene, private_files, private=True))
    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a local Codex handoff package")
    parser.add_argument("root", type=Path)
    parser.add_argument("--scene", choices=("device", "conversation"), default="device")
    parser.add_argument("--write-manifest", action="store_true", help="outgoing only; never use on receipt")
    parser.add_argument("--private-config", action="store_true", help="also verify the local-only API-key recovery bundle")
    args = parser.parse_args()
    try:
        errors, warnings = validate(args.root.expanduser(), args.scene, args.write_manifest, args.private_config)
    except OSError as exc:
        print(f"FAIL: filesystem operation failed ({type(exc).__name__})", file=sys.stderr)
        return 2
    for warning in warnings:
        print(f"WARN: {warning}")
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        print(f"handoff validation failed ({len(errors)} issue(s))")
        return 1
    suffix = "; manifest written" if args.write_manifest else ""
    print(f"mechanical validation passed ({args.scene}{suffix}); review warnings and task evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
