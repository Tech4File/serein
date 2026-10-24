#!/usr/bin/env python3
"""Fail fast when product version sources disagree or a tag is unsafe."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
match = re.fullmatch(
    r"(?P<base>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))"
    r"(?:-(?P<pre>(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
    version,
)
if not match:
    sys.exit(f"VERSION is not valid SemVer: {version!r}")
base_version = match.group("base")
is_prerelease = match.group("pre") is not None

product_manifests = (
    "backend/Cargo.toml",
    "crates/serein-core/Cargo.toml",
    "crates/serein-moq-engine/Cargo.toml",
    "media-transport-spike/Cargo.toml",
)
for relpath in product_manifests:
    manifest = tomllib.loads((ROOT / relpath).read_text(encoding="utf-8"))
    package_version = manifest.get("package", {}).get("version")
    if package_version != version:
        sys.exit(f"{relpath}: package.version={package_version!r}; expected VERSION={version!r}")
web_config = (ROOT / "frontend/web/config.js").read_text(encoding="utf-8")
web_version = re.search(r"version\s*:\s*[\"']([^\"']+)[\"']", web_config)
if not web_version or web_version.group(1) != version:
    sys.exit(f"frontend/web/config.js version must match VERSION={version!r}")

core_src = (ROOT / "crates/serein-core/src/lib.rs").read_text(encoding="utf-8")
if 'concat!(env!("CARGO_PKG_VERSION"), "\\0")' not in core_src:
    sys.exit("Shared core C ABI version must be derived from CARGO_PKG_VERSION, not hard-coded")

android = (ROOT / "apps/android/app/build.gradle").read_text(encoding="utf-8")
if "file('../../../VERSION').text.trim()" not in android or "versionName repoVersion" not in android:
    sys.exit("Android versionName must be sourced from the root VERSION file")
if not re.search(r"\bminSdk\s+26\b", android):
    sys.exit("Android minimum API floor drifted from API 26")

ios_project = (ROOT / "apps/ios/SereinChat.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
marketing_versions = re.findall(r"MARKETING_VERSION\s*=\s*([^;]+);", ios_project)
if not marketing_versions or any(v.strip() != base_version for v in marketing_versions):
    sys.exit(
        "iOS project MARKETING_VERSION must match the numeric X.Y.Z part of VERSION "
        f"({base_version}); found {marketing_versions!r}"
    )
ios_whats_new_versions = re.findall(r"INFOPLIST_KEY_SereinVersion\s*=\s*[\"']?([^;\"']+)", ios_project)
if not ios_whats_new_versions or any(v.strip() != version for v in ios_whats_new_versions):
    sys.exit(f"iOS What's New version must match VERSION={version!r}; found {ios_whats_new_versions!r}")
ios_build_numbers = re.findall(r"CURRENT_PROJECT_VERSION\s*=\s*([^;]+);", ios_project)
if not ios_build_numbers or len(set(v.strip() for v in ios_build_numbers)) != 1:
    sys.exit(f"iOS Debug/Release build numbers must be present and match; found {ios_build_numbers!r}")
ios_floors = re.findall(r"IPHONEOS_DEPLOYMENT_TARGET\s*=\s*([^;]+);", ios_project)
if not ios_floors or any(v.strip() != "15.0" for v in ios_floors):
    sys.exit(f"iOS deployment target must remain 15.0; found {ios_floors!r}")

ref = os.environ.get("GITHUB_REF", "")
if ref.startswith("refs/tags/") and not ref.startswith("refs/tags/v"):
    sys.exit(f"Release tags must use the vX.Y.Z form; received {ref!r}")
if ref.startswith("refs/tags/v"):
    if is_prerelease or "+" in version:
        sys.exit(f"Release tags are stable-only; VERSION is {version!r}")
    if ref != f"refs/tags/v{version}":
        sys.exit(f"Pushed tag {ref!r} does not exactly match stable VERSION v{version}")
    tags = subprocess.run(
        ["git", "tag", "--list", "v[0-9]*"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    stable = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
    prior_versions = []
    for tag in tags:
        tag_match = stable.fullmatch(tag)
        if tag != ref.removeprefix("refs/tags/") and tag_match:
            prior_versions.append(tuple(map(int, tag_match.groups())))
    current_version = tuple(map(int, base_version.split(".")))
    if prior_versions and current_version <= max(prior_versions):
        sys.exit(
            f"Release VERSION {version} must be greater than the highest existing stable tag "
            f"{max(prior_versions)}"
        )

print(
    f"Version check passed: {version}; Cargo, web, Android, and iOS version metadata are aligned; "
    "platform floors are Android API 26 / iOS 15.0."
)
if ref.startswith("refs/tags/"):
    print(f"Release tag check passed: {ref}")
