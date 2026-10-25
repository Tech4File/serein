#!/usr/bin/env python3
"""Regenerate all build-metadata version mirrors from the root VERSION file.

Edit VERSION only. This script is idempotent and runs before CI checks/builds so
platform metadata cannot silently drift or require hand-editing in several files.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "VERSION"
VERSION_RE = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def write(path: Path, content: str) -> bool:
    if path.read_text(encoding="utf-8") == content:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def set_workspace_version(cargo: str, version: str) -> str:
    marker = "[workspace.package]"
    if marker not in cargo:
        cargo = cargo.rstrip() + f"\n\n{marker}\nversion = \"{version}\"\n"
        return cargo
    start = cargo.index(marker) + len(marker)
    next_section = re.search(r"(?m)^\[", cargo[start:])
    end = start + next_section.start() if next_section else len(cargo)
    section = cargo[start:end]
    version_line = re.compile(r'(?m)^version[ \t]*=[ \t]*"[^"]*"[ \t]*$')
    if version_line.search(section):
        section = version_line.sub(f'version = "{version}"', section, count=1)
    else:
        section = "\nversion = \"" + version + "\"" + section
    return cargo[:start] + section + cargo[end:]


def inherit_workspace_version(path: Path) -> str:
    cargo = path.read_text(encoding="utf-8")
    if re.search(r"(?m)^version\.workspace\s*=\s*true\s*$", cargo):
        return cargo
    version_line = re.compile(r'(?m)^version[ \t]*=[ \t]*"[^"]*"[ \t]*$')
    updated, count = version_line.subn("version.workspace = true", cargo, count=1)
    if count != 1:
        raise ValueError(f"Could not find package version in {path.relative_to(ROOT)}")
    return updated


def update_lockfile(path: Path, package_names: set[str], version: str) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8")
    # Repair the separator too if a previous generator version ever swallowed it.
    text = re.sub(r'(?<=")\[\[package\]\]', "\n\n[[package]]", text)
    blocks = re.split(r"(?m)(?=^\[\[package\]\]$)", text)
    updated = []
    for block in blocks:
        name = re.search(r'(?m)^name\s*=\s*"([^"]+)"\s*$', block)
        if name and name.group(1) in package_names:
            block, count = re.subn(r'(?m)^version[ \t]*=[ \t]*"[^"]+"[ \t]*$', f'version = "{version}"', block, count=1)
            if count != 1:
                raise ValueError(f"Could not update Cargo.lock package {name.group(1)}")
        updated.append(block)
    return "".join(updated)


def main() -> int:
    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    if not VERSION_RE.fullmatch(version):
        print(f"VERSION is not valid SemVer: {version!r}", file=sys.stderr)
        return 2
    base = version.split("-", 1)[0].split("+", 1)[0]
    package_names = {"serein-api", "serein-core", "serein-moq-engine"}
    changed: list[str] = []

    root_cargo = ROOT / "Cargo.toml"
    if write(root_cargo, set_workspace_version(root_cargo.read_text(encoding="utf-8"), version)):
        changed.append("Cargo.toml [workspace.package]")
    for relative in (
        "backend/Cargo.toml",
        "crates/serein-core/Cargo.toml",
        "crates/serein-moq-engine/Cargo.toml",
    ):
        path = ROOT / relative
        if write(path, inherit_workspace_version(path)):
            changed.append(relative)

    lock = ROOT / "Cargo.lock"
    if lock.exists() and write(lock, update_lockfile(lock, package_names, version)):
        changed.append("Cargo.lock workspace package versions")

    web_config = ROOT / "frontend/web/config.js"
    web_text = web_config.read_text(encoding="utf-8")
    web_updated, count = re.subn(
        r'(?m)(\bversion\s*:\s*)["\'][^"\']*["\']',
        lambda m: m.group(1) + '"' + version + '"',
        web_text,
        count=1,
    )
    if count != 1:
        raise ValueError("Could not find frontend web version metadata")
    if write(web_config, web_updated):
        changed.append("frontend/web/config.js")

    ios_project = ROOT / "apps/ios/SereinChat.xcodeproj/project.pbxproj"
    ios_text = ios_project.read_text(encoding="utf-8")
    ios_updated, full_count = re.subn(
        r'(INFOPLIST_KEY_SereinVersion\s*=\s*)["\'][^"\']*["\'](;)',
        lambda m: m.group(1) + '"' + version + '"' + m.group(2),
        ios_text,
    )
    ios_updated, base_count = re.subn(
        r'(MARKETING_VERSION\s*=\s*)[^;]+(;)',
        lambda m: m.group(1) + base + m.group(2),
        ios_updated,
    )
    if full_count == 0 or base_count == 0:
        raise ValueError("Could not find both iOS version metadata settings")
    if write(ios_project, ios_updated):
        changed.append("apps/ios/SereinChat.xcodeproj/project.pbxproj")

    if changed:
        print(f"Synced build versions from VERSION={version}: " + ", ".join(changed))
    else:
        print(f"Build-version mirrors already match VERSION={version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
