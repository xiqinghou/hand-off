#!/usr/bin/env python3
"""Regression cases use disposable packages/Git repos, never real credentials."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from validate_handoff import LOCAL_CONFIG, LOCAL_MANIFEST, MANIFEST, MUTABLE_FILES, RECEIPT, validate

SKILL_ROOT = Path(__file__).resolve().parents[1]


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_package(base: Path, scene: str) -> Path:
    root = base / "project" / "交接"
    write(root.parent / "docs/README.md", "# Project rules\n")
    docs = {
        "README.md": "# 交接\n[任务](工作交接/任务交接.md)\n[规范](../docs/README.md)\n",
        "工作交接/任务交接.md": "# 当前任务\n状态：进行中。\n",
        "工作交接/文件导航.md": "# 导航\n先读项目入口。\n",
        "工作交接/环境与验证.md": "# 环境\n来源路径：/Users/example/project。\n",
        "工作交接/归档索引.md": "# 归档\n本批次无退役文件。\n",
        RECEIPT: "# 回执\n尚未接收。\n",
        "配置交接/README.md": "# 配置\n仅携带脱敏内容。\n",
    }
    for relative, text in docs.items():
        write(root / relative, text)
    if scene == "device":
        config = root / "配置交接/codex/config.toml"
        write(config, 'model = "example-model"\n')
        write(root / "配置交接/文件清单.json", json.dumps({"files": [
            {"path": "codex/config.toml", "included": True,
             "sha256": hashlib.sha256(config.read_bytes()).hexdigest()},
            {"path": "codex/auth.json", "included": False, "reason": "manual login"},
        ]}))
    return root


class HandoffValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="codex-handoff-test-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = make_package(self.base, "device")

    def generate(self, scene="device"):
        errors, warnings = validate(self.root, scene, write_manifest=True)
        self.assertEqual(errors, [])
        self.assertTrue(warnings)  # Absolute source paths are warnings.
        self.assertEqual(validate(self.root, scene)[0], [])

    def assert_error(self, substring, scene="device", write_manifest=False):
        errors, _ = validate(self.root, scene, write_manifest)
        self.assertTrue(any(substring in item for item in errors), errors)

    def git(self, *arguments):
        return subprocess.run(
            ["git", "-C", str(self.root.parent), *arguments],
            capture_output=True, check=True,
        )

    def make_private_package(self):
        self.git("init", "-q")
        write(self.root.parent / ".gitignore", "/交接/配置交接/.codex/\n")
        private = self.root / LOCAL_CONFIG
        write(private / "config.toml", 'api_key = "' + "x" * 24 + '"\n')
        write(private / "auth.json", json.dumps({"OPENAI_API_KEY": "x" * 24}))
        write(private / "README.md", "# Local recovery\nCopy listed files after backup.\n")
        write(private / "skills/hand-off/SKILL.md", "# hand-off\nPortable skill.\n")
        manifest = self.root / "配置交接/文件清单.json"
        data = json.loads(manifest.read_text())
        data["files"].append({"path": ".codex/config.toml", "included": False,
                              "transport": "local_only", "reason": "USB only"})
        write(manifest, json.dumps(data))
        return private

    def generate_private(self):
        errors, _ = validate(self.root, "device", True, True)
        self.assertEqual(errors, [])
        self.assertEqual(validate(self.root, "device", private_config=True)[0], [])

    def test_device_including_portable_skill(self):
        shutil.copytree(
            SKILL_ROOT, self.root / "配置交接/skills/hand-off",
            ignore=shutil.ignore_patterns(".DS_Store", "__pycache__", "*.pyc", ".git"),
        )
        self.generate()

    def test_conversation_without_user_configuration(self):
        self.root = make_package(self.base / "conversation", "conversation")
        self.generate("conversation")

    def test_legacy_manifest_still_valid(self):
        self.generate()
        path = self.root / MANIFEST
        data = json.loads(path.read_text())
        data["format"] = 1
        data["excludes"] = sorted(MUTABLE_FILES)
        write(path, json.dumps(data))
        self.assertEqual(validate(self.root, "device")[0], [])

    def test_private_key_bundle_and_cloud_only_receipt(self):
        private = self.make_private_package()
        self.generate_private()
        data = json.loads((self.root / MANIFEST).read_text())
        self.assertEqual(data["format"], 2)
        self.assertFalse(any(entry["path"].startswith(LOCAL_CONFIG) for entry in data["files"]))
        self.assertNotIn(hashlib.sha256((private / "config.toml").read_bytes()).hexdigest(),
                         (self.root / MANIFEST).read_text())
        shutil.rmtree(private)
        self.assertEqual(validate(self.root, "device")[0], [])
        errors, _ = validate(self.root, "device", private_config=True)
        self.assertTrue(any("directory is missing" in error for error in errors))

    def test_private_including_portable_skill(self):
        private = self.make_private_package()
        shutil.copytree(
            SKILL_ROOT, private / "skills/hand-off", dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(".DS_Store", "__pycache__", "*.pyc", ".git"),
        )
        self.generate_private()

    def test_private_hash_detects_change_without_invalidating_cloud(self):
        private = self.make_private_package()
        self.generate_private()
        write(private / "config.toml", 'api_key = "' + "y" * 24 + '"\n')
        self.assertEqual(validate(self.root, "device")[0], [])
        errors, _ = validate(self.root, "device", private_config=True)
        self.assertTrue(any("sha256 mismatch" in error for error in errors), errors)

    def test_private_git_ignore_required(self):
        self.make_private_package()
        (self.root.parent / ".gitignore").unlink()
        self.assert_error("not fully Git-ignored", write_manifest=True)
        self.assertFalse((self.root / MANIFEST).exists())

    def test_private_git_ignore_negation_is_checked_per_file(self):
        self.make_private_package()
        write(self.root.parent / ".gitignore",
              "/交接/配置交接/.codex/*\n!/交接/配置交接/.codex/auth.json\n")
        self.assert_error("not fully Git-ignored", write_manifest=True)

    def test_tracked_private_config_blocked_even_if_deleted(self):
        private = self.make_private_package()
        self.git("add", "-f", "--", "交接/配置交接/.codex/auth.json")
        self.assert_error("tracked or staged", write_manifest=True)
        shutil.rmtree(private)
        self.assert_error("tracked or staged", write_manifest=True)

    def test_private_config_requires_git_boundary(self):
        self.make_private_package()
        shutil.rmtree(self.root.parent / ".git")
        self.assert_error("requires a Git repository", write_manifest=True)

    def test_private_metadata_and_skill_must_not_contain_secrets(self):
        private = self.make_private_package()
        self.generate_private()
        before = (self.root / MANIFEST).read_bytes(), (private / LOCAL_MANIFEST).read_bytes()
        for relative in ("README.md", "skills/hand-off/SKILL.md", LOCAL_MANIFEST):
            path = private / relative
            original = path.read_bytes()
            write(path, 'api_key = "' + "x" * 24 + '"\n')
            errors, _ = validate(self.root, "device", True, True)
            self.assertTrue(any("private metadata" in error for error in errors), errors)
            self.assertEqual(before[0], (self.root / MANIFEST).read_bytes())
            if relative != LOCAL_MANIFEST:
                self.assertEqual(before[1], (private / LOCAL_MANIFEST).read_bytes())
            path.write_bytes(original)

    def test_private_oauth_login_data_and_runtime_are_rejected(self):
        private = self.make_private_package()
        write(private / "auth.json", json.dumps({"OPENAI_API_KEY": "x" * 24,
                                                 "tokens": {"refresh_token": "y" * 24}}))
        write(private / "sessions/session.json", "{}")
        errors, _ = validate(self.root, "device", True, True)
        self.assertTrue(any("OAuth login state" in error for error in errors), errors)
        self.assertTrue(any("runtime/login data" in error for error in errors), errors)
        self.assertTrue(any("only API-key authentication" in error for error in errors), errors)
        self.assertFalse((private / LOCAL_MANIFEST).exists())

    def test_private_files_cannot_be_marked_for_cloud_upload(self):
        self.make_private_package()
        path = self.root / "配置交接/文件清单.json"
        data = json.loads(path.read_text())
        data["files"][-1]["included"] = True
        write(path, json.dumps(data))
        self.assert_error("must be excluded", write_manifest=True)

    def test_private_archive_outside_exact_directory_is_scanned(self):
        private = self.make_private_package()
        shutil.copytree(private, self.root / "工作交接/归档/old/.codex")
        self.assert_error("possible credential_assignment", write_manifest=True)

    def test_private_root_symlink_is_not_read(self):
        private = self.make_private_package()
        external = self.base / "external-private"
        shutil.move(str(private), external)
        private.symlink_to(external, target_is_directory=True)
        self.assert_error("symlink is not allowed", write_manifest=True)

    def test_private_parent_symlink_is_not_read(self):
        private = self.make_private_package()
        write(private / "auth.json", json.dumps({"refresh_token": "x" * 24}))
        external = self.base / "external-config"
        shutil.move(str(private.parent), external)
        private.parent.symlink_to(external, target_is_directory=True)
        errors, _ = validate(self.root, "device", True, True)
        self.assertTrue(any("symlink is not allowed" in error for error in errors), errors)
        self.assertFalse(any("OAuth login state" in error for error in errors), errors)

    def test_private_flag_not_allowed_in_conversation(self):
        errors, _ = validate(self.root, "conversation", True, True)
        self.assertEqual(errors, ["--private-config is only supported for device handoff"])

    def test_private_manifest_not_regenerated_on_receipt(self):
        private = self.make_private_package()
        self.generate_private()
        path = private / LOCAL_MANIFEST
        write(path, "{")
        before = path.read_bytes()
        errors, _ = validate(self.root, "device", private_config=True)
        self.assertTrue(any("invalid private validation manifest" in error for error in errors), errors)
        self.assertEqual(path.read_bytes(), before)

    def test_mutable_receipt_does_not_invalidate_manifest(self):
        self.generate()
        write(self.root / RECEIPT, "# 回执\n目标机已核对。\n")
        self.assertEqual(validate(self.root, "device")[0], [])

    def test_receipt_is_still_scanned(self):
        self.generate()
        write(self.root / RECEIPT, "api_key = " + "x" * 24)
        self.assert_error("possible credential_assignment")

    def test_changed_file(self):
        self.generate()
        write(self.root / "工作交接/任务交接.md", "# 已改动\n")
        self.assert_error("sha256 mismatch")

    def test_added_file(self):
        self.generate()
        write(self.root / "额外文件.md", "new")
        self.assert_error("file added since manifest")

    def test_removed_file(self):
        write(self.root / "旧文件.md", "old")
        self.generate()
        (self.root / "旧文件.md").unlink()
        self.assert_error("file removed since manifest")

    def test_missing_readme_no_crash_no_manifest(self):
        (self.root / "README.md").unlink()
        self.assert_error("missing required file: README.md", write_manifest=True)
        self.assertFalse((self.root / MANIFEST).exists())

    def test_whitespace_required_file(self):
        write(self.root / "工作交接/任务交接.md", " \n\t ")
        self.assert_error("required file is empty", write_manifest=True)

    def test_failures_do_not_replace_existing_manifest(self):
        self.generate()
        before = (self.root / MANIFEST).read_bytes()
        write(self.root / "README.md", "api_key = " + "x" * 24)
        self.assert_error("possible credential_assignment", write_manifest=True)
        self.assertEqual(before, (self.root / MANIFEST).read_bytes())

    def test_symlink_file_and_directory_are_not_read(self):
        outside = self.base / "external"
        outside.mkdir()
        write(outside / "secret.txt", "api_key = " + "x" * 24)
        (self.root / "外部目录").symlink_to(outside, target_is_directory=True)
        (self.root / "外部文件.md").symlink_to(outside / "secret.txt")
        errors, _ = validate(self.root, "device", True)
        self.assertEqual(sum("symlink is not allowed" in error for error in errors), 2)
        self.assertFalse(any("possible credential" in error for error in errors))
        self.assertFalse((self.root / MANIFEST).exists())

    def test_configuration_paths_reject_traversal_and_windows_absolute(self):
        for relative in ("../../outside", "/tmp/external", "C:\\Users\\x\\file", "a/../b"):
            with self.subTest(relative=relative):
                write(self.root / "配置交接/文件清单.json", json.dumps({
                    "files": [{"path": relative, "included": True}]
                }))
                self.assert_error("unsafe or missing path", write_manifest=True)

    def test_configuration_requires_hash_and_rejects_excluded_present(self):
        manifest = self.root / "配置交接/文件清单.json"
        data = json.loads(manifest.read_text())
        del data["files"][0]["sha256"]
        write(manifest, json.dumps(data))
        self.assert_error("requires SHA-256", write_manifest=True)
        write(self.root / "配置交接/codex/auth.json", "{}")
        self.assert_error("excluded configuration unexpectedly present", write_manifest=True)

    def test_malformed_manifests(self):
        for value in ("[]", "{", '{"files": null}'):
            with self.subTest(value=value):
                write(self.root / "配置交接/文件清单.json", value)
                self.assert_error("configuration manifest", write_manifest=True)
        self.root = make_package(self.base / "fresh", "conversation")
        for value in ("[]", "{", '{"files": null}'):
            with self.subTest(value=value):
                write(self.root / MANIFEST, value)
                self.assert_error("validation manifest", scene="conversation")

    def test_manifest_scene_and_entries(self):
        self.generate()
        path = self.root / MANIFEST
        data = json.loads(path.read_text())
        data["files"].append(data["files"][0])
        write(path, json.dumps(data))
        self.assert_error("duplicate")
        data["scene"] = "conversation"
        write(path, json.dumps(data))
        self.assert_error("invalid validation manifest")

    def test_readme_links_spaces_and_boundaries(self):
        write(self.root.parent / "docs/name with spaces.md", "# Target\n")
        write(self.root / "README.md", "[目标](<../docs/name with spaces.md>)\n")
        self.generate()
        write(self.root / "README.md", "[越界](../../outside)\n")
        self.assert_error("escapes project", write_manifest=True)
        write(self.root / "README.md", "[失效](missing.md)\n")
        self.assert_error("target does not exist", write_manifest=True)

    def test_active_placeholder_blocked(self):
        write(self.root / "工作交接/任务交接.md", "TODO: finish\n")
        self.assert_error("unfinished placeholder", write_manifest=True)

    def test_non_utf8_gets_manual_review_warning(self):
        (self.root / "image.bin").write_bytes(bytes([0xff, 0xfe, 0x00]))
        errors, warnings = validate(self.root, "device", True)
        self.assertEqual(errors, [])
        self.assertTrue(any("manual review required" in warning for warning in warnings))

    def test_cli_reports_failure_without_traceback(self):
        (self.root / "README.md").unlink()
        result = subprocess.run(
            [sys.executable, "-B", str(SKILL_ROOT / "scripts/validate_handoff.py"),
             str(self.root), "--scene", "device"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing required file", result.stdout)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
