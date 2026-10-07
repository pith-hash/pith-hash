<p align="center">
  <img src="https://pith-hash.n24q02m.com/logo.svg" alt="pith-hash" width="120">
</p>

<h1 align="center">pith-hash</h1>

<p align="center">
  <strong>The pith suite curator: detect, tier-1 content hash, tier-2 signatures, match, calibrate and the pith CLI</strong>
</p>

<p align="center">
  <a href="https://github.com/pith-hash/pith-hash/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/pith-hash/pith-hash/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-hash/actions/workflows/cd.yml"><img alt="CD" src="https://github.com/pith-hash/pith-hash/actions/workflows/cd.yml/badge.svg"></a>
  <a href="https://github.com/pith-hash/pith-hash/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/pith-hash/pith-hash?display_name=tag&sort=semver"></a>
  <a href="https://github.com/n24q02m/better-semantic-release"><img alt="semantic-release" src="https://img.shields.io/badge/semantic--release-e10079?logo=semantic-release&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/github/license/pith-hash/pith-hash"></a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#the-pith-suite-contract">Suite contract</a>
</p>

<!-- BEGIN: AUTO-GENERATED-CROSS-PROMO -->
<!-- END: AUTO-GENERATED-CROSS-PROMO -->

`pith-hash` is the top of the suite's dependency DAG. It implements no
hashing itself: it *wires* the five modality crates behind one facade —
[`detect`](https://docs.rs/pith-hash) names the container's
`Format`/`Modality` pair, `content_hash` is **tier 1** (SHA-256 over the
normalized content), `signature` is **tier 2** (image pHash, spectral-peak
audio signature, 128-word MinHash for text, FastCDC chunk digests for
binary, frame-chain MinHash for video), and `match_`, `describe` and
`calibrate` build on those two tiers. The `pith` CLI exposes all of it
from a shell.

## Repository layout

```
src/               the facade (lib), the index module, the fuzz and gen-reference bins
pith-hash-cli/     the `pith` command line interface
tools/gen-reference  the vector generator binary (bin name: gen-reference)
tests/fixtures/    byte-exact corpus shared by the facade tests
fuzz/corpus        fuzz seeds replayed by the codec fuzz targets
reference.json     hex-exact cross-SDK test vectors
lab/calibrate-receipt  the calibrate receipt dataset + pinned output
```

## Install

Rust (the core library):

```bash
cargo add pith-hash
```

The `pith` CLI ships with this repository (`cargo install --path pith-hash-cli`).
Python / Node / Go SDKs are published from the same cdylib on every release;
see the release assets or the package registries for the matching version.

## Quick start

```rust
let bytes = std::fs::read("photo.png")?;

// Detection names the container before anything decodes it.
let det = pith_hash::detect(&bytes);
println!("{} / {}", det.format.as_str(), det.modality.as_str());

// Tier 1: SHA-256 over the decoded pixels — byte-identical re-encodes
// of the same picture hash identically.
let tier1 = pith_hash::content_hash(&bytes)?;

// Tier 2: the 64-bit perceptual hash.
let sig = pith_hash::signature(&bytes)?;

// Compare two images' signatures against the advisory bound.
let verdict = pith_hash::match_(&sig, &sig2)?;
```

```text
$ pith describe photo.png
modality: image
format: png
tier1: 9f2b…        # SHA-256 over decoded pixels
tier2: phash 0xc21bc25d12345678
tier3: orb keypoints=137
image: 1920x1080px

$ pith match a.png b.png
modality: image
score: hamming=4
advisory: hamming <= 10
verdict: match

$ pith dedup ~/Pictures --json          # cluster by tier-2 signature
$ pith calibrate --profile dedup pairs.csv   # fit a threshold, print a receipt
```

## The calibrate receipt

The default `dedup` profile ships with a receipt: `lab/calibrate-receipt/`
holds a 22-pair labeled dataset over 16 deterministic images plus the
pinned output of both profiles, and
`pith-hash-cli/tests/calibrate_receipt.rs` re-runs it on every build —
the regenerated dataset must be byte-identical to the committed CSV, and
both `pith calibrate` runs must reproduce the README's receipt blocks
bit-for-bit.

## Hex-exact vectors

`reference.json` at the repo root is the cross-language source of truth
(45 detect/signature/describe/match vectors over the deterministic
corpus in `tests/fixtures/`). `cargo run --bin gen-reference -- verify`
checks the committed copy is current; CI runs the same check.

## The pith suite contract

pith-hash is part of the **pith** suite (pith-hash). Every suite repository
follows the same rules; CI enforces them mechanically:

- **Naming**: a library is always `pith-<domain>` (`pith-image`, `pith-audio`,
  `pith-zip`, ...). The curator/repository of repositories is the bare
  `pith-hash`. Never invent a second naming scheme inside the suite.
- **Version pinning**: cross-library dependencies pin `~0.1` (e.g.
  `pith-image = { version = "~0.1", path = "../pith-image" }`). The whole suite
  moves together inside 0.1.x; breaking changes require a suite-wide version
  bump, never a silent minor drift. This repository pins the suite crates by
  `git, branch = "main"` until the R6 publish switches it to the versioned
  pins (see the `Cargo.toml` dependencies note).
- **Zero third-party dependencies**: every crate depends only on other
  `pith-*` crates plus `std`. `scripts/check-zero-deps.py` (run in CI) fails
  the build on any other crate, for normal, build and dev dependencies alike.
- **No unsafe**: every crate root carries `#![forbid(unsafe_code)]`.
- **Hex-exact vectors**: `reference.json` at the repo root is the
  cross-language source of truth. The `gen-reference` binary regenerates it;
  CI verifies the committed copy is current (`gen-reference verify`), and CD
  ships the regenerated file with every SDK artifact. Python, Node and Go SDKs
  MUST test against the same bytes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © pith-hash — Portions derived from n24q02m/modhash (MIT),
Copyright (c) 2026 n24q02m.
