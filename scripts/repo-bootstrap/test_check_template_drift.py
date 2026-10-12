"""Tests for check_template_drift.py (stdlib unittest)."""
import tempfile
import unittest
from pathlib import Path

import check_template_drift as drift


def make_suite(root: Path, canonical_text: str = "same\n") -> Path:
    suite = root / "suite"
    for repo in drift.REPOS:
        for rel in drift.TEMPLATE_FILES:
            path = suite / repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(canonical_text)
    canonical = root / "canonical"
    for rel in drift.TEMPLATE_FILES:
        path = canonical / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(canonical_text)
    return suite


class TemplateDriftTest(unittest.TestCase):
    def run_main(self, root: Path, suite: Path) -> int:
        return drift.main(
            ["--repos-root", str(suite), "--canonical-root", str(root / "canonical")]
        )

    def test_identical_suite_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(self.run_main(root, make_suite(root)), 0)

    def test_modified_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suite = make_suite(root)
            (suite / "pith-png" / ".github/workflows/ci.yml").write_text("edited\n")
            self.assertEqual(self.run_main(root, suite), 1)
            found = drift.compare(
                root / "canonical", lambda r, rel: drift.read_local(suite, r, rel)
            )
            self.assertEqual(found, {".github/workflows/ci.yml": ["pith-png: differs"]})

    def test_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suite = make_suite(root)
            (suite / "pith-zip" / "deny.toml").unlink()
            found = drift.compare(
                root / "canonical", lambda r, rel: drift.read_local(suite, r, rel)
            )
            self.assertEqual(found, {"deny.toml": ["pith-zip: missing"]})

    def test_repo_list_matches_suite_size(self):
        self.assertEqual(len(drift.REPOS), 19)
        self.assertEqual(len(set(drift.REPOS)), 19)


if __name__ == "__main__":
    unittest.main()
