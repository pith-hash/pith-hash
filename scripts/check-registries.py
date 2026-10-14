#!/usr/bin/env python3
"""Registry readback gate for the pith suite.

Reads every published package back from its registry and fails unless the
registry itself says the expected version is there. An HTTP 200 is never
taken as proof: each check parses the registry's own metadata and compares
the package name, the version, the yank/deprecation state and the registry's
"latest" pointer against what this release is supposed to have shipped.

Registries and what is asserted for each package:

  crates.io  the crate lists the version, it is not yanked, and it is the
             crate's default version
  PyPI       the project has the version with at least one file, none of them
             yanked, and the version is the project's current version
  npm        the packument lists the version, it is not a stub or deprecated,
             it carries a tarball and integrity hash, and `latest` points at it
  Maven      maven-metadata.xml lists the version and names it as the release,
             the pom's coordinates match, and the jar is downloadable
  Go proxy   proxy.golang.org resolves the version to that exact version, the
             version is in the module's version list, and the served go.mod
             declares the module path (a module in a subdirectory resolves
             only from a `<subdir>/vX.Y.Z` tag, so a bare `vX.Y.Z` tag fails)

The package inventory below is explicit on purpose: it is the list of what the
release must have published, so a package that silently stopped publishing
shows up as a failure instead of vanishing from the loop.

Usage:
    python scripts/check-registries.py [--version 0.1.0] [--only crates,npm]

Exits 0 only when every checked package passes. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

EXPECTED_VERSION = "0.1.0"
USER_AGENT = "pith-registry-readback (github.com/pith-hash/pith-hash)"
ORG = "pith-hash"
MAVEN_GROUP = "io.github.pith-hash"

# Every pith repo ships a Rust core crate, a PyPI wheel set, an npm package and
# a cgo Go module; only some ship a JNI jar. pith-hash also ships the `pith` CLI
# crate. Keep in step with each repo's sdk/ directories and Cargo workspace.
REPOS = [
    "audio", "cdc", "digest", "file", "flac", "h264", "hash", "image", "inflate", "jpeg",
    "math", "mp3", "mp4", "pdf", "png", "text", "unicode", "video", "zip",
]
JAVA_REPOS = [
    "audio", "digest", "file", "hash", "image", "inflate", "math", "text", "unicode", "video",
]
EXTRA_CRATES = ["pith-hash-cli"]

REGISTRIES = ("crates", "pypi", "npm", "maven", "go")

# (registry, package name, repo) for every package the release must publish.
PACKAGES: list[tuple[str, str, str]] = (
    [("crates", f"pith-{r}", f"pith-{r}") for r in REPOS]
    + [("crates", name, "pith-hash") for name in EXTRA_CRATES]
    + [("pypi", f"pith-{r}", f"pith-{r}") for r in REPOS]
    + [("npm", f"@{ORG}/pith-{r}", f"pith-{r}") for r in REPOS]
    + [("maven", f"{MAVEN_GROUP}:pith-{r}", f"pith-{r}") for r in JAVA_REPOS]
    + [("go", f"github.com/{ORG}/pith-{r}/sdk/go", f"pith-{r}") for r in REPOS]
)

# A fetcher takes a URL and returns (status, body); status 0 means the request
# never completed. Injected so the checks can be tested without a network.
Fetch = Callable[[str], "tuple[int, bytes]"]


def fetch(url: str, method: str = "GET", attempts: int = 5) -> tuple[int, bytes]:
    """GET (or HEAD) with backoff on 429, 5xx and dropped connections."""
    delay = 2.0
    status, body = 0, b""
    for attempt in range(attempts):
        req = urllib.request.Request(
            url, method=method, headers={"User-Agent": USER_AGENT}
        )
        retry_after = None
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as err:
            status, body = err.code, err.read()
            if status != 429 and status < 500:
                return status, body
            retry_after = err.headers.get("Retry-After")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
            status, body = 0, str(err).encode()
        if attempt + 1 < attempts:
            wait = delay
            if retry_after and retry_after.isdigit():
                wait = max(wait, min(float(retry_after), 30.0))
            time.sleep(wait)
            delay *= 2
    return status, body


def _json(status: int, body: bytes, url: str) -> tuple[object | None, str | None]:
    """Decode a registry JSON reply, or explain why it cannot be trusted."""
    if status == 404:
        return None, f"not found on the registry ({url})"
    if status != 200:
        return None, f"registry answered HTTP {status} for {url}"
    try:
        return json.loads(body), None
    except ValueError:
        return None, f"registry reply is not JSON ({url})"


def check_crate(name: str, version: str, get: Fetch) -> list[str]:
    url = f"https://crates.io/api/v1/crates/{name}"
    doc, err = _json(*get(url), url)
    if err:
        return [err]
    assert isinstance(doc, dict)
    problems: list[str] = []
    crate = doc.get("crate") or {}
    if crate.get("name") != name:
        problems.append(f"registry names this crate {crate.get('name')!r}, not {name!r}")
    found = [v for v in doc.get("versions") or [] if v.get("num") == version]
    if not found:
        have = sorted(v.get("num", "?") for v in doc.get("versions") or [])
        return problems + [f"version {version} is missing (registry has: {', '.join(have) or 'none'})"]
    if found[0].get("yanked"):
        problems.append(f"version {version} is yanked")
    if crate.get("default_version") != version:
        problems.append(
            f"default version is {crate.get('default_version')!r}, expected {version}"
        )
    return problems


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def check_pypi(name: str, version: str, get: Fetch) -> list[str]:
    url = f"https://pypi.org/pypi/{name}/json"
    doc, err = _json(*get(url), url)
    if err:
        return [err]
    assert isinstance(doc, dict)
    problems: list[str] = []
    info = doc.get("info") or {}
    if _norm_py(info.get("name") or "") != _norm_py(name):
        problems.append(f"registry names this project {info.get('name')!r}, not {name!r}")
    files = (doc.get("releases") or {}).get(version) or []
    if not files:
        have = sorted((doc.get("releases") or {}).keys())
        return problems + [f"version {version} has no files (registry has: {', '.join(have) or 'none'})"]
    if all(f.get("yanked") for f in files):
        problems.append(f"every file of version {version} is yanked")
    if info.get("version") != version:
        problems.append(f"current version is {info.get('version')!r}, expected {version}")
    return problems


def check_npm(name: str, version: str, get: Fetch) -> list[str]:
    url = "https://registry.npmjs.org/" + name.replace("/", "%2F")
    doc, err = _json(*get(url), url)
    if err:
        return [err]
    assert isinstance(doc, dict)
    problems: list[str] = []
    if doc.get("name") != name:
        problems.append(f"registry names this package {doc.get('name')!r}, not {name!r}")
    versions = doc.get("versions") or {}
    latest = (doc.get("dist-tags") or {}).get("latest")
    meta = versions.get(version)
    if meta is None:
        have = sorted(versions.keys())
        problems.append(
            f"version {version} is missing (registry has: {', '.join(have) or 'none'}; latest={latest!r})"
        )
        return problems
    if meta.get("version") != version or meta.get("name") != name:
        problems.append(f"version record says {meta.get('name')}@{meta.get('version')}")
    if meta.get("stub"):
        problems.append(f"version {version} is a placeholder stub")
    if meta.get("deprecated"):
        problems.append(f"version {version} is deprecated: {meta['deprecated']}")
    dist = meta.get("dist") or {}
    if not dist.get("tarball") or not dist.get("integrity"):
        problems.append(f"version {version} has no tarball/integrity in its dist record")
    if latest != version:
        problems.append(f"dist-tag latest is {latest!r}, expected {version}")
    return problems


def _xml(status: int, body: bytes, url: str) -> tuple[ET.Element | None, str | None]:
    if status == 404:
        return None, f"not found on the registry ({url})"
    if status != 200:
        return None, f"registry answered HTTP {status} for {url}"
    try:
        return ET.fromstring(body), None
    except ET.ParseError:
        return None, f"registry reply is not XML ({url})"


def _text(root: ET.Element, tag: str) -> str | None:
    # Poms carry a namespace, maven-metadata.xml does not; match either.
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1] == tag:
            return (el.text or "").strip()
    return None


def check_maven(coords: str, version: str, get: Fetch) -> list[str]:
    group, artifact = coords.split(":")
    base = f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/{artifact}"
    meta_url = f"{base}/maven-metadata.xml"
    root, err = _xml(*get(meta_url), meta_url)
    if err:
        return [err]
    assert root is not None
    problems: list[str] = []
    if (_text(root, "groupId"), _text(root, "artifactId")) != (group, artifact):
        problems.append(
            f"metadata names {_text(root, 'groupId')}:{_text(root, 'artifactId')}, not {coords}"
        )
    listed = [(v.text or "").strip() for v in root.iter("version")]
    if version not in listed:
        return problems + [f"version {version} is missing (registry has: {', '.join(listed) or 'none'})"]
    if _text(root, "release") != version:
        problems.append(f"release is {_text(root, 'release')!r}, expected {version}")

    pom_url = f"{base}/{version}/{artifact}-{version}.pom"
    pom, err = _xml(*get(pom_url), pom_url)
    if err:
        problems.append(err)
    elif pom is not None:
        got = (_text(pom, "groupId"), _text(pom, "artifactId"), _text(pom, "version"))
        if got != (group, artifact, version):
            problems.append(f"pom declares {':'.join(map(str, got))}, expected {coords}:{version}")
    jar_status, _ = get(f"{base}/{version}/{artifact}-{version}.jar")
    if jar_status != 200:
        problems.append(f"jar is not downloadable (HTTP {jar_status})")
    return problems


def check_go(module: str, version: str, get: Fetch) -> list[str]:
    base = f"https://proxy.golang.org/{module}/@v"
    tag = f"v{version}"
    info_url = f"{base}/{tag}.info"
    status, body = get(info_url)
    if status in (404, 410):
        subdir = module.split("/", 3)[3] if module.count("/") >= 3 else ""
        hint = f" (module lives in {subdir}/, so the tag it resolves from is {subdir}/{tag})" if subdir else ""
        return [f"{module}@{tag} is not resolvable on the proxy{hint}"]
    doc, err = _json(status, body, info_url)
    if err:
        return [err]
    assert isinstance(doc, dict)
    problems: list[str] = []
    if doc.get("Version") != tag:
        problems.append(f"proxy resolved {tag} to {doc.get('Version')!r}")
    list_status, list_body = get(f"{base}/list")
    if list_status == 200 and tag not in list_body.decode(errors="replace").split():
        problems.append(f"{tag} is not in the module's version list")
    mod_status, mod_body = get(f"{base}/{tag}.mod")
    if mod_status != 200:
        problems.append(f"go.mod is not served (HTTP {mod_status})")
    else:
        m = re.search(r"^module\s+(\S+)", mod_body.decode(errors="replace"), re.M)
        if not m or m.group(1) != module:
            problems.append(f"go.mod declares module {m.group(1) if m else None!r}, expected {module}")
    return problems


CHECKS: dict[str, Callable[[str, str, Fetch], list[str]]] = {
    "crates": check_crate,
    "pypi": check_pypi,
    "npm": check_npm,
    "maven": check_maven,
    "go": check_go,
}


def run(version: str, only: set[str], get: Fetch = fetch, workers: int = 4) -> int:
    todo = [p for p in PACKAGES if p[0] in only]

    def one(pkg: tuple[str, str, str]) -> tuple[tuple[str, str, str], list[str]]:
        registry, name, _ = pkg
        try:
            return pkg, CHECKS[registry](name, version, get)
        except Exception as exc:  # a malformed reply must fail the gate, not crash it
            return pkg, [f"could not read the registry reply: {type(exc).__name__}: {exc}"]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(one, todo))

    failed = 0
    for (registry, name, _), problems in results:
        label = f"{registry:<6} {name}@{version}"
        if problems:
            failed += 1
            print(f"FAIL  {label}")
            for p in problems:
                print(f"        - {p}")
        else:
            print(f"ok    {label}")
    print(f"\n{len(results) - failed}/{len(results)} packages verified on their registries")
    if failed:
        print(f"FAIL: {failed} package(s) missing or on the wrong version")
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", default=EXPECTED_VERSION, help="expected version (default %(default)s)")
    ap.add_argument(
        "--only",
        default=",".join(REGISTRIES),
        help="comma-separated registries to check (default: all of %(default)s)",
    )
    args = ap.parse_args()
    only = {r.strip() for r in args.only.split(",") if r.strip()}
    unknown = only - set(REGISTRIES)
    if unknown:
        ap.error(f"unknown registry: {', '.join(sorted(unknown))}")
    return run(args.version.lstrip("v"), only)


if __name__ == "__main__":
    sys.exit(main())
