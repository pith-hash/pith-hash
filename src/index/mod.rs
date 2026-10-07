//! Similarity indexes over suite fingerprints: a BK-tree over 64-bit
//! hashes, a banded LSH index over MinHash signatures, and threshold
//! calibration.
//!
//! In-repo module of the curator (upstream `modhash-index` crate, ported
//! byte-compatibly; promoted to a standalone crate only when a consumer
//! outside the suite asks for one). Its only dependency is
//! [`pith_digest`] for the suite's shared error type, and
//! `scripts/check-zero-deps.py` keeps the whole workspace that way.
//!
//! Every structure here is a **candidate index** (design spec §4.4): it
//! answers "which entries are close enough to deserve a full comparison?"
//! and nothing more. The verdict "duplicate / not duplicate" belongs to
//! the caller — the facade's [`match_`](crate::match_) — so an LSH miss
//! or a generous radius can never masquerade as a decision.
//!
//! The module is `alloc`-only inside the crate's `no_std` build, and
//! every observable order is deterministic: ordered bucket maps,
//! distance-then-id sorted candidates, and a fixed splitmix64 bucket
//! mixer. Equal inputs produce identical output on every platform and
//! every run — the property `calibrate`'s reproducibility requirement is
//! built on.

mod bktree;
mod calibrate;
mod lsh;

pub use bktree::{BkTree, Candidate};
pub use calibrate::{Calibration, Profile, calibrate};
pub use lsh::LshIndex;
