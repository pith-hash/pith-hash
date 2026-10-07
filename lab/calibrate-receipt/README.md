# pith calibrate — R5-N1 receipt (image lane)

The default `dedup` profile ships because it reproduces, bit-for-bit, on
the committed dataset below. `pith-hash-cli/tests/calibrate_receipt.rs`
re-runs this receipt on every CI build: it regenerates the 16 BMPs with
the documented fixture recipe, diffs the rebuilt `pairs.csv` against the
committed one, and diffs both profile runs against the pinned
```receipt blocks in this file.

## Dataset

- `pairs.csv` — 22 labeled pairs over 16 deterministic 48×40 BMPs
  (`dataset/`): 16 positives (per base: v0/v1, v0/v2, v1/v2 and the
  heavy-edit v0/v3) and 6 negatives (cross-base v0 pairs).
- Recipe (all seeds SplitMix64 via `fixture::patterned_pixels` /
  `perturb_pixels`): bases b1..b4 = seeds 0xA1..0xA4;
  v1 = perturb(4, per 998), v2 = perturb(4, per 999),
  v3 = perturb(24, per 17) — a heavy edit that is still the same
  picture, deliberately overlapping the cross-base distance range so
  the two profiles must disagree.
- The heavy-edit positives (fn=2 below) are what separate the profiles:
  `dedup` (F0.5) trades them away for zero false positives;
  `search` (F2) buys one of them back at threshold 16.

## Reproduce

```text
cd lab/calibrate-receipt
pith calibrate --profile dedup pairs.csv
pith calibrate --profile search pairs.csv
```

Pinned output (pith 0.1.0, Windows x86_64, debug profile — the receipt
is integer math, so the build profile does not move it):

```receipt profile=dedup
dataset: pairs.csv (22 pairs: 16 positive, 6 negative)
profile: Dedup
threshold: 12   # match iff distance <= threshold
score (f-beta): 0.972222
precision: 1.000000
recall: 0.875000
counts: tp=14 fp=0 fn=2 tn=6
# receipt: measured on pairs.csv with pith 0.1.0
```

```receipt profile=search
dataset: pairs.csv (22 pairs: 16 positive, 6 negative)
profile: Search
threshold: 20   # match iff distance <= threshold
score (f-beta): 0.987654
precision: 0.941176
recall: 1.000000
counts: tp=16 fp=1 fn=0 tn=5
# receipt: measured on pairs.csv with pith 0.1.0
```

## Provenance

- Generated 2026-10-07 on the R5 curator workstation; re-verified by
  `cargo test -p pith-hash-cli --test calibrate_receipt`.
- The CSV sha256 at the time of pinning:
  616b481cca4bab8dfa6566aa385a17e4255e43105cc46780fd53df222a7135f5
