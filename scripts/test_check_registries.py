"""Offline tests for check-registries.py: the checks must read the registry's
own metadata, so an HTTP 200 carrying the wrong content has to fail.

Run: python -m unittest scripts/test_check_registries.py
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import unittest
import zipfile

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


LIBS = {
    "linux-x64": "libpith_x.so",
    "linux-arm64": "libpith_x.so",
    "darwin-arm64": "libpith_x.dylib",
    "darwin-x64": "libpith_x.dylib",
    "win32-x64": "pith_x.dll",
}
WHEEL_TAGS = {
    "linux-x64": "manylinux_2_17_x86_64",
    "linux-arm64": "manylinux_2_17_aarch64",
    "darwin-arm64": "macosx_11_0_arm64",
    "darwin-x64": "macosx_10_12_x86_64",
    "win32-x64": "win_amd64",
}


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def tgz_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class PypiContentTests(unittest.TestCase):
    URL = "https://pypi.org/pypi/pith-x/json"
    VERSION = "0.1.1"

    def routes(self, drop=(), abi="py3-none", lib_missing=()):
        files, routes = [], {}
        for platform, tag in WHEEL_TAGS.items():
            if platform in drop:
                continue
            filename = f"pith_x-{self.VERSION}-{abi}-{tag}.whl"
            body = zip_bytes({} if platform in lib_missing else {f"pith_x/{LIBS[platform]}": b"\x7fELF"})
            url = f"https://files.example/{filename}"
            files.append({"filename": filename, "url": url, "yanked": False})
            routes[url] = (200, body)
        doc = {"info": {"name": "pith-x", "version": self.VERSION}, "releases": {self.VERSION: files}}
        routes[self.URL] = (200, doc)
        return routes

    def check(self, routes, content=True):
        return cr.check_pypi("pith-x", self.VERSION, fake(routes), content=content)

    def test_complete_wheel_set_passes(self):
        self.assertEqual(self.check(self.routes()), [])

    def test_missing_platform_wheel_fails(self):
        got = self.check(self.routes(drop=("darwin-arm64",)))
        self.assertTrue(any("darwin-arm64" in p for p in got), got)

    def test_abi_specific_wheel_fails_content(self):
        got = self.check(self.routes(abi="cp313-cp313"))
        self.assertTrue(any("py3-none" in p for p in got), got)

    def test_wheel_without_its_library_fails(self):
        got = self.check(self.routes(lib_missing=("win32-x64",)))
        self.assertTrue(any("pith_x.dll" in p for p in got), got)

    def test_content_off_keeps_old_behaviour(self):
        ok = {"info": {"name": "pith-x", "version": "0.1.0"}, "releases": {"0.1.0": [{"yanked": False}]}}
        self.assertEqual(cr.check_pypi("pith-x", "0.1.0", fake({self.URL: (200, ok)}), content=False), [])


class NpmContentTests(unittest.TestCase):
    URL = "https://registry.npmjs.org/@pith-hash%2Fpith-x"
    NAME = "@pith-hash/pith-x"
    TARBALL = "https://registry.npmjs.org/@pith-hash/pith-x/-/pith-x-0.1.1.tgz"

    def routes(self, drop=(), served=None):
        entries = {f"package/prebuilds/{p}/{lib}": b"bin" for p, lib in LIBS.items() if p not in drop}
        entries["package/package.json"] = b"{}"
        body = tgz_bytes(entries)
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(body).digest()).decode()
        v = {"name": self.NAME, "version": "0.1.1", "dist": {"tarball": self.TARBALL, "integrity": integrity}}
        doc = {"name": self.NAME, "dist-tags": {"latest": "0.1.1"}, "versions": {"0.1.1": v}}
        return {self.URL: (200, doc), self.TARBALL: (200, body if served is None else served)}

    def check(self, routes):
        return cr.check_npm(self.NAME, "0.1.1", fake(routes), content=True)

    def test_complete_tarball_passes(self):
        self.assertEqual(self.check(self.routes()), [])

    def test_missing_prebuild_fails(self):
        got = self.check(self.routes(drop=("linux-arm64",)))
        self.assertTrue(any("linux-arm64" in p for p in got), got)

    def test_tarball_not_matching_registry_integrity_fails(self):
        got = self.check(self.routes(served=tgz_bytes({"package/package.json": b"{}"})))
        self.assertTrue(any("integrity" in p for p in got), got)


class MavenContentTests(unittest.TestCase):
    BASE = MavenTests.BASE

    def routes(self, drop=()):
        routes = MavenTests().routes(release="0.1.1")
        entries = {f"hash/pith/native/{p}/{lib}": b"bin" for p, lib in LIBS.items() if p not in drop}
        routes[f"{self.BASE}/0.1.1/pith-x-0.1.1.jar"] = (200, zip_bytes(entries))
        return routes

    def check(self, routes):
        return cr.check_maven("io.github.pith-hash:pith-x", "0.1.1", fake(routes), content=True)

    def test_complete_jar_passes(self):
        self.assertEqual(self.check(self.routes()), [])

    def test_missing_platform_library_fails(self):
        got = self.check(self.routes(drop=("darwin-x64",)))
        self.assertTrue(any("darwin-x64" in p for p in got), got)


class ContentModeTests(unittest.TestCase):
    def test_default_follows_the_version(self):
        self.assertFalse(cr.default_content("0.1.0"))
        self.assertTrue(cr.default_content("0.1.1"))
        self.assertTrue(cr.default_content("0.1.1-beta.1"))
        self.assertTrue(cr.default_content("0.2.0"))

    def test_run_passes_content_only_to_registries_that_open_packages(self):
        seen = []
        original = dict(cr.CHECKS)
        try:
            for name in cr.CHECKS:
                cr.CHECKS[name] = lambda n, v, g, content=False, _r=name: seen.append((_r, content)) or []
            cr.run("0.1.1", set(cr.REGISTRIES), get=fake({}), content=True)
        finally:
            cr.CHECKS.update(original)
        self.assertEqual({r for r, c in seen if c}, {"pypi", "npm", "maven"})
        self.assertEqual({r for r, c in seen if not c}, {"crates", "go"})


class InventoryTests(unittest.TestCase):
    def test_inventory_counts(self):
        by = {r: sum(1 for p in cr.PACKAGES if p[0] == r) for r in cr.REGISTRIES}
        self.assertEqual(by, {"crates": 20, "pypi": 19, "npm": 19, "maven": 10, "go": 19})

    def test_run_fails_when_any_package_fails(self):
        self.assertEqual(cr.run("0.1.0", {"npm"}, get=fake({})), 1)


if __name__ == "__main__":
    unittest.main()
