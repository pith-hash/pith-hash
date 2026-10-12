"""Offline tests for check-registries.py: the checks must read the registry's
own metadata, so an HTTP 200 carrying the wrong content has to fail.

Run: python -m unittest scripts/test_check_registries.py
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest

_spec = importlib.util.spec_from_file_location(
    "check_registries", pathlib.Path(__file__).with_name("check-registries.py")
)
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)


def fake(routes: dict[str, tuple[int, object]]):
    def get(url: str):
        status, body = routes.get(url, (404, b"not found"))
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        return status, body

    return get


class CratesTests(unittest.TestCase):
    URL = "https://crates.io/api/v1/crates/pith-x"

    def doc(self, num="0.1.0", yanked=False, default="0.1.0"):
        return {
            "crate": {"name": "pith-x", "default_version": default},
            "versions": [{"num": num, "yanked": yanked}],
        }

    def test_ok(self):
        self.assertEqual(cr.check_crate("pith-x", "0.1.0", fake({self.URL: (200, self.doc())})), [])

    def test_wrong_version_with_http_200_fails(self):
        got = cr.check_crate("pith-x", "0.1.0", fake({self.URL: (200, self.doc(num="0.0.1", default="0.0.1"))}))
        self.assertTrue(any("missing" in p for p in got))

    def test_yanked_fails(self):
        got = cr.check_crate("pith-x", "0.1.0", fake({self.URL: (200, self.doc(yanked=True))}))
        self.assertTrue(any("yanked" in p for p in got))

    def test_absent_fails(self):
        self.assertTrue(cr.check_crate("pith-x", "0.1.0", fake({})))


class PypiTests(unittest.TestCase):
    URL = "https://pypi.org/pypi/pith-x/json"

    def test_ok_and_empty_release_fails(self):
        ok = {"info": {"name": "pith_x", "version": "0.1.0"}, "releases": {"0.1.0": [{"yanked": False}]}}
        self.assertEqual(cr.check_pypi("pith-x", "0.1.0", fake({self.URL: (200, ok)})), [])
        empty = {"info": {"name": "pith-x", "version": "0.1.0"}, "releases": {"0.1.0": []}}
        self.assertTrue(cr.check_pypi("pith-x", "0.1.0", fake({self.URL: (200, empty)})))


class NpmTests(unittest.TestCase):
    URL = "https://registry.npmjs.org/@pith-hash%2Fpith-x"
    NAME = "@pith-hash/pith-x"

    def test_placeholder_only_fails(self):
        doc = {
            "name": self.NAME,
            "dist-tags": {"latest": "0.0.0"},
            "versions": {"0.0.0": {"name": self.NAME, "version": "0.0.0", "stub": True}},
        }
        got = cr.check_npm(self.NAME, "0.1.0", fake({self.URL: (200, doc)}))
        self.assertTrue(any("missing" in p and "0.0.0" in p for p in got))

    def test_ok(self):
        v = {"name": self.NAME, "version": "0.1.0", "dist": {"tarball": "t", "integrity": "sha512-x"}}
        doc = {"name": self.NAME, "dist-tags": {"latest": "0.1.0"}, "versions": {"0.1.0": v}}
        self.assertEqual(cr.check_npm(self.NAME, "0.1.0", fake({self.URL: (200, doc)})), [])

    def test_latest_pointing_elsewhere_fails(self):
        v = {"name": self.NAME, "version": "0.1.0", "dist": {"tarball": "t", "integrity": "sha512-x"}}
        doc = {"name": self.NAME, "dist-tags": {"latest": "0.0.0"}, "versions": {"0.1.0": v}}
        self.assertTrue(any("latest" in p for p in cr.check_npm(self.NAME, "0.1.0", fake({self.URL: (200, doc)}))))


class MavenTests(unittest.TestCase):
    BASE = "https://repo1.maven.org/maven2/io/github/pith-hash/pith-x"

    def routes(self, release="0.1.0", jar=200):
        meta = (
            "<metadata><groupId>io.github.pith-hash</groupId><artifactId>pith-x</artifactId>"
            f"<versioning><release>{release}</release><versions><version>{release}</version></versions>"
            "</versioning></metadata>"
        ).encode()
        pom = (
            '<project xmlns="http://maven.apache.org/POM/4.0.0"><groupId>io.github.pith-hash</groupId>'
            f"<artifactId>pith-x</artifactId><version>{release}</version></project>"
        ).encode()
        return {
            f"{self.BASE}/maven-metadata.xml": (200, meta),
            f"{self.BASE}/{release}/pith-x-{release}.pom": (200, pom),
            f"{self.BASE}/{release}/pith-x-{release}.jar": (jar, b""),
        }

    def test_ok(self):
        self.assertEqual(cr.check_maven("io.github.pith-hash:pith-x", "0.1.0", fake(self.routes())), [])

    def test_wrong_version_fails(self):
        self.assertTrue(cr.check_maven("io.github.pith-hash:pith-x", "0.1.0", fake(self.routes(release="0.0.9"))))

    def test_missing_jar_fails(self):
        self.assertTrue(cr.check_maven("io.github.pith-hash:pith-x", "0.1.0", fake(self.routes(jar=404))))


class GoTests(unittest.TestCase):
    MOD = "github.com/pith-hash/pith-x/sdk/go"
    BASE = f"https://proxy.golang.org/{MOD}/@v"

    def test_unresolvable_tag_fails_with_hint(self):
        got = cr.check_go(self.MOD, "0.1.0", fake({}))
        self.assertTrue(any("sdk/go/v0.1.0" in p for p in got))

    def test_ok(self):
        routes = {
            f"{self.BASE}/v0.1.0.info": (200, {"Version": "v0.1.0"}),
            f"{self.BASE}/list": (200, b"v0.1.0\n"),
            f"{self.BASE}/v0.1.0.mod": (200, f"module {self.MOD}\n\ngo 1.25\n".encode()),
        }
        self.assertEqual(cr.check_go(self.MOD, "0.1.0", fake(routes)), [])


class InventoryTests(unittest.TestCase):
    def test_inventory_counts(self):
        by = {r: sum(1 for p in cr.PACKAGES if p[0] == r) for r in cr.REGISTRIES}
        self.assertEqual(by, {"crates": 8, "pypi": 7, "npm": 7, "maven": 4, "go": 7})

    def test_run_fails_when_any_package_fails(self):
        self.assertEqual(cr.run("0.1.0", {"npm"}, get=fake({})), 1)


if __name__ == "__main__":
    unittest.main()
