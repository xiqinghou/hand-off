#!/usr/bin/env python3
"""Local handoff validation. Only --write-manifest writes after checks pass.

No Git commands, configuration collection, or network access. Hashes detect
changes, not authenticity or business readiness. Requires Python 3.10+.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
DIGEST = re.compile(r"[0-9a-f]{64}")
SECRET_PATTERNS = {
    "credential_assignment": re.compile(
        r"""(?i)(?:[\w-]*(?:api[_-]?key|secret[_-]?key|access[_-]?token|password))"""
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


def inventory(root: Path) -> tuple[dict[str, Path], list[str]]:
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
            elif name in {".git", "__pycache__", "node_modules"}:
                errors.append(f"runtime/repository directory is not portable: {relative}")
                directories.remove(name)
        for name in filenames:
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                errors.append(f"symlink is not allowed: {relative}")
            elif not path.is_file():
                errors.append(f"unsupported file type: {relative}")
            elif not safe_relative(relative):
                errors.append(f"nonportable package path: {relative}")
            elif name in {".DS_Store", ".git"} or path.suffix == ".pyc":
                errors.append(f"system/repository artifact is not portable: {relative}")
            else:
                files[relative] = path
    return dict(sorted(files.items())), errors


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
        "format": 1,
        "scene": scene,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "excludes": sorted(MUTABLE_FILES),
        "files": [
            {"path": relative, "size": path.stat().st_size, "sha256": sha256(path)}
            for relative, path in files.items() if relative not in MUTABLE_FILES
        ],
    }


def check_manifest(scene: str, files: dict[str, Path]) -> list[str]:
    if MANIFEST not in files:
        return [f"missing required file: {MANIFEST}"]
    data, errors = read_json(files[MANIFEST], "validation manifest")
    if errors:
        return errors
    if (
        not isinstance(data, dict)
        or data.get("format") != 1
        or data.get("scene") != scene
        or data.get("excludes") != sorted(MUTABLE_FILES)
        or not isinstance(data.get("files"), list)
    ):
        return ["invalid validation manifest format, scene, exclusions or files"]
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
        if relative in MUTABLE_FILES or relative in recorded:
            errors.append(f"duplicate or excluded manifest entry: {relative}")
        recorded[relative] = entry
    actual = {key: value for key, value in files.items() if key not in MUTABLE_FILES}
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


def validate(root: Path, scene: str, write_manifest: bool = False) -> tuple[list[str], list[str]]:
    if root.is_symlink() or not root.is_dir():
        return ["package root must be an existing directory, not a symlink"], []
    root = root.resolve()
    files, errors = inventory(root)
    warnings: list[str] = []
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
        if not errors:
            destination = root / MANIFEST
            temporary = root / ".校验清单.json.tmp"
            if temporary.exists() or temporary.is_symlink():
                errors.append("temporary manifest path already exists; leave it untouched")
            else:
                temporary.write_text(
                    json.dumps(build_manifest(scene, files), ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                temporary.replace(destination)
    else:
        errors.extend(check_manifest(scene, files))
    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a local Codex handoff package")
    parser.add_argument("root", type=Path)
    parser.add_argument("--scene", choices=("device", "conversation"), default="device")
    parser.add_argument("--write-manifest", action="store_true", help="outgoing only; never use on receipt")
    args = parser.parse_args()
    try:
        errors, warnings = validate(args.root.expanduser(), args.scene, args.write_manifest)
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
