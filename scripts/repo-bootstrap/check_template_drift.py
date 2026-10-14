#!/usr/bin/env python3
"""Template drift check for the pith suite (backlog D-3 / B1).

The 19 pith-* repositories each carry a copy of the same CI/CD and tooling
files. This repository (`pith-hash/pith-hash`, the curator) holds the
canonical copy. The script compares every file in TEMPLATE_FILES in every
suite repository against the canonical copy and exits 1 when any of them
differs or is missing, so a template change that was not rolled out to all
repositories is reported instead of going unnoticed.

Two modes, both stdlib only:

  python scripts/repo-bootstrap/check_template_drift.py
      Reads each repository's main branch from raw.githubusercontent.com
      (the repositories are public, so no token is needed).

  python scripts/repo-bootstrap/check_template_drift.py --repos-root DIR
      Reads DIR/pith-<name>/<file> from local checkouts; no network.
"""
from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path

ORG = "pith-hash"
BRANCH = "main"

# The 19 suite libraries; the curator (pith-hash) is the 19th repository.
REPOS = [
    "pith-digest", "pith-cdc", "pith-file", "pith-inflate", "pith-zip",
    "pith-png", "pith-jpeg", "pith-image", "pith-pdf", "pith-text",
    "pith-unicode", "pith-math", "pith-audio", "pith-flac", "pith-mp3",
    "pith-mp4", "pith-h264", "pith-video", "pith-hash",
]

# Files that must be byte-identical across the suite. LICENSE, .gitignore,
# .gitattributes, .skret.yaml and SECURITY.md are per-repository on purpose.
TEMPLATE_FILES = [
    ".github/workflows/ci.yml",
    ".github/workflows/cd.yml",
    ".mise.toml",
    ".pre-commit-config.yaml",
    "CODE_OF_CONDUCT.md",
    "deny.toml",
    "renovate.json",
    "semantic-release.toml",
    "scripts/check-zero-deps.py",
    "scripts/check-package-contents.py",
    "scripts/test_check_package_contents.py",
    "scripts/stamp-release.py",
    "scripts/test_stamp_release.py",
    "scripts/enforce-commit.sh",
    "scripts/repo-bootstrap/_lib.py",
    "scripts/repo-bootstrap/verify_readme_sync.py",
]


def read_local(repos_root: Path, repo: str, rel: str) -> bytes | None:
    path = repos_root / repo / rel
    return path.read_bytes() if path.is_file() else None


def read_remote(repo: str, rel: str) -> bytes | None:
    url = f"https://raw.githubusercontent.com/{ORG}/{repo}/{BRANCH}/{rel}"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return None
        raise


def compare(canonical_root: Path, read) -> dict[str, list[str]]:
    """Return {file: [repo: reason, ...]} for every file that drifted."""
    drift: dict[str, list[str]] = {}
    for rel in TEMPLATE_FILES:
        canonical = (canonical_root / rel).read_bytes()
        for repo in REPOS:
            theirs = read(repo, rel)
            if theirs is None:
                drift.setdefault(rel, []).append(f"{repo}: missing")
            elif theirs != canonical:
                drift.setdefault(rel, []).append(f"{repo}: differs")
    return drift


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--repos-root",
        type=Path,
        help="directory holding local checkouts named pith-<name> (no network)",
    )
    parser.add_argument(
        "--canonical-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="checkout of the curator repository (default: this repository)",
    )
    args = parser.parse_args(argv)

    if args.repos_root:
        def read(repo: str, rel: str) -> bytes | None:
            return read_local(args.repos_root, repo, rel)
    else:
        read = read_remote

    drift = compare(args.canonical_root, read)
    if drift:
        total = sum(len(v) for v in drift.values())
        print(f"FAIL: template drift, {total} file(s) out of sync:")
        for rel, entries in drift.items():
            print(f"  {rel}")
            for entry in entries:
                print(f"    - {entry}")
        return 1

    print(
        f"template drift OK: {len(TEMPLATE_FILES)} file(s) identical "
        f"across {len(REPOS)} repositories"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
