# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""Build backend glue for the pith-hash ctypes wheel.

The wheel carries the Rust cdylib built by ``cargo build --release``:
``PITH_CDYLIB_DIR`` (default ``target/release`` at the repository root)
is scanned for the cdylib and copied into the wheel by a ``build_py``
hook. ``BinaryDistribution`` marks the distribution non-pure so the
wheel is tagged per platform — the CD matrix builds one wheel per OS
and publish-pypi uploads the three together.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from setuptools import Distribution, setup
from setuptools.command.build_py import build_py

#: Every cdylib file name cargo may drop into the build directory, per
#: platform (windows / linux / macOS).
CDYLIB_NAMES = ("pith_hash.dll", "libpith_hash.so", "libpith_hash.dylib")


class BinaryDistribution(Distribution):
    """A distribution that always carries a binary, so wheels get a
    platform tag instead of ``py3-none-any``."""

    def has_ext_modules(self) -> bool:  # noqa: D102
        return True


class build_py_with_cdylib(build_py):
    """Copies the cdylib from ``PITH_CDYLIB_DIR`` into the wheel."""

    def run(self) -> None:
        super().run()
        repo_root = Path(__file__).resolve().parent.parent.parent
        env_dir = os.environ.get("PITH_CDYLIB_DIR")
        candidates = [Path(env_dir)] if env_dir else []
        if not env_dir or not Path(env_dir).is_absolute():
            # Relative values are ambiguous: build backends run with the
            # package directory as cwd, while CD and local shells point the
            # variable at the repository-root-relative target/release.
            candidates.append(repo_root / (env_dir or "target/release"))
        candidates.append(repo_root / "target" / "release")
        pkg_dir = Path(self.build_lib) / "pith_hash"
        copied = 0
        for candidate in candidates:
            for name in CDYLIB_NAMES:
                source = candidate / name
                if source.is_file():
                    shutil.copy2(source, pkg_dir / name)
                    copied += 1
        if copied == 0:
            searched = ", ".join(str(c) for c in candidates)
            raise RuntimeError(
                "pith-hash: no cdylib found (looked for "
                + ", ".join(CDYLIB_NAMES)
                + " in "
                + searched
                + "); run cargo build --release first"
            )


setup(
    distclass=BinaryDistribution,
    cmdclass={"build_py": build_py_with_cdylib},
)
