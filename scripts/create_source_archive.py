#!/usr/bin/env python3
"""Create a safe source ZIP that includes Git-ignored Markdown documentation."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_COMPONENTS = {
    ".arena", ".build", ".cache", ".dSYM", ".git", ".gradle", ".idea", ".local",
    ".mypy_cache", ".next", ".nox", ".npm", ".nuxt", ".output", ".parcel-cache",
    ".playwright-cli", ".pytest_cache", ".ruff_cache", ".svelte-kit", ".swiftpm", ".tox",
    ".turbo", ".venv", ".vite", ".xcarchive", "Carthage", "DerivedData", "Pods",
    "__pycache__", "build", "coverage", "dist", "node_modules", "out", "target",
    "xcuserdata", ".aws", ".azure", ".docker", ".ssh",
}
EXCLUDED_NAMES = {".netrc", ".git-credentials", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa"}
EXCLUDED_SUFFIXES = {
    ".a", ".aab", ".apk", ".bak", ".cer", ".class", ".crt", ".db", ".der", ".dylib",
    ".ipa", ".jks", ".keystore", ".log", ".mobileprovision", ".o", ".orig", ".p12",
    ".pfx", ".pem", ".pyc", ".key", ".sqlite", ".sqlite3", ".realm", ".so", ".swp",
    ".tar", ".tmp", ".zip",
}


def included(path: Path, output: Path) -> bool:
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        return False
    if path == output or path.is_symlink() or not path.is_file():
        return False
    if any(part in EXCLUDED_COMPONENTS for part in relative.parts):
        return False
    if path.suffix.lower() in EXCLUDED_SUFFIXES:
        return False
    if relative.name in EXCLUDED_NAMES:
        return False
    if relative.name == ".env" or (relative.name.startswith(".env.") and relative.name != ".env.example"):
        return False
    if relative.name == ".DS_Store":
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", help="ZIP path (default: repository-root/serein-source.zip)")
    args = parser.parse_args()

    output = Path(args.output).expanduser() if args.output else ROOT / "serein-source.zip"
    if not output.is_absolute():
        output = (Path.cwd() / output).resolve()
    else:
        output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    try:
        listed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            check=True, capture_output=True,
        ).stdout.split(b"\0")
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"Could not list repository source files: {error}", file=sys.stderr)
        return 2

    candidates = {ROOT / os.fsdecode(item) for item in listed if item}
    # The WASM runtime is generated and ignored by Git, but the static web app
    # cannot run the shared Rust core without this matching deployable asset.
    wasm_runtime = ROOT / "frontend/web/serein_core.wasm"
    if wasm_runtime.is_file():
        candidates.add(wasm_runtime)
    # Markdown is broadly Git-ignored in this project, so explicitly include
    # every safe Markdown file, not only the central docs/ directory.
    candidates.update(ROOT.rglob("*.md"))
    files = sorted(path for path in candidates if included(path, output))
    if not files:
        print("No source files found; refusing to create an empty archive.", file=sys.stderr)
        return 2

    archive_root = ROOT.name
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=8) as archive:
        for path in files:
            relative = path.relative_to(ROOT)
            info = zipfile.ZipInfo(f"{archive_root}/{relative.as_posix()}")
            info.from_file(path, info.filename)
            info.compress_type = zipfile.ZIP_DEFLATED
            with path.open("rb") as source:
                archive.writestr(info, source.read(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=8)

    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        omitted_docs = [path.relative_to(ROOT).as_posix() for path in ROOT.rglob("*.md")
                        if included(path, output) and f"{archive_root}/{path.relative_to(ROOT).as_posix()}" not in names]
    if omitted_docs:
        output.unlink(missing_ok=True)
        print(f"Archive safety check failed; Markdown files were omitted: {omitted_docs}", file=sys.stderr)
        return 2
    print(f"Created {output} with {len(files)} files, including ignored Markdown documentation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
