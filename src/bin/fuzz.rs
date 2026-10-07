//! Deterministic fuzz harness for the `pith-hash` suite.
//!
//! One binary owns fuzzing for every lane, because the `pith-hash`
//! curator sits at the top of the suite DAG and can see all of them:
//!
//! ```text
//! cargo run --release --bin fuzz -- <target> <iters> <seed>
//! ```
//!
//! Everything is driven by a splitmix64 PRNG seeded from the command line, so
//! a failing iteration number reproduces exactly on any machine.
//!
//! The file-based codec targets read their seed corpora from
//! `fuzz/corpus/<target>/`; committing those corpora (with a
//! `tests/fuzz_corpus.rs` replay) is deferred to the suite's R6
//! milestone, so the corpus-backed targets name the missing directory
//! until then. `coremode` and `flac` are self-seeding and run today.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::ExitCode;
/// The four mutation modes every target is fuzzed with.
const MODES: [&str; 4] = ["random", "truncate", "bitflip", "repeat-insert"];

/// splitmix64: the reference finaliser from Steele et al. (2014).
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Creates a generator from `seed`.
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next 64-bit output.
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a value in `0..n`, or `0` when `n` is zero.
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }
}

/// Codec fuzz targets, registered by the phase that owns each codec.
///
/// Each owning phase appends its own name and a matching arm in
/// `dispatch`, and seeds `fuzz/corpus/<name>/` when its corpus is
/// file-based. Embedded-seed targets keep their seed in the arm.
const TARGET_NAMES: &[&str] = &["mp4", "h264", "flac", "png", "jpeg", "bmp", "audio"];

fn apply(mode: &str, rng: &mut SplitMix64, input: &[u8]) -> Vec<u8> {
    match mode {
        "random" => (0..=rng.below(512)).map(|_| rng.next_u64() as u8).collect(),
        "truncate" => {
            let end = rng.below(input.len() + 1);
            input[..end].to_vec()
        }
        "bitflip" => {
            // An empty input has no bit to flip. Returning it unchanged is the
            // honest semantic: this mode corrupts existing bytes and never
            // introduces new ones. Truncate can reach length zero, so this
            // case is reachable, not hypothetical.
            if input.is_empty() {
                return input.to_vec();
            }
            let mut out = input.to_vec();
            let flips = 1 + rng.below(8);
            for _ in 0..flips {
                let i = rng.below(out.len());
                out[i] ^= 1 << rng.below(8);
            }
            out
        }
        "repeat-insert" => {
            if input.is_empty() {
                return vec![rng.next_u64() as u8];
            }
            let at = rng.below(input.len());
            let take = 1 + rng.below(input.len());
            let end = at.saturating_add(take).min(input.len());
            let mut out = input[..at].to_vec();
            out.extend_from_slice(&input[at..end]);
            out.extend_from_slice(&input[at..]);
            out
        }
        other => unreachable!("unknown mutation mode {other}"),
    }
}
/// Routes `target` to its phase implementation.
fn dispatch(target: &str, rng: &mut SplitMix64, iters: usize, seed: u64) -> Result<(), String> {
    match target {
        "coremode" => fuzz_coremode(rng, iters, seed),
        "mp4" => fuzz_codec(rng, iters, seed, "mp4", |bytes| {
            // The container demuxer plus the video lane above it:
            // demux, the facade signature path and the full fingerprint
            // all see every mutated input.
            pith_mp4::demux(bytes)?;
            let _ = pith_hash::signature(bytes);
            pith_video::decode(bytes, &pith_video::Limits::default()).map(|_| ())
        }),
        "h264" => fuzz_codec(rng, iters, seed, "h264", |bytes| {
            pith_h264::decode(bytes).map(|_| ())
        }),
        "flac" => fuzz_flac(rng, iters, seed),
        "png" => fuzz_codec(rng, iters, seed, "png", |bytes| {
            // The decoder plus the facade's image lane above it.
            let _ = pith_hash::signature(bytes);
            pith_png::decode(bytes, &pith_png::Limits::default()).map(|_| ())
        }),
        "jpeg" => fuzz_codec(rng, iters, seed, "jpeg", |bytes| {
            let _ = pith_hash::signature(bytes);
            pith_jpeg::decode(bytes).map(|_| ())
        }),
        "bmp" => fuzz_codec(rng, iters, seed, "bmp", |bytes| {
            let _ = pith_hash::signature(bytes);
            pith_image::bmp::decode(bytes).map(|_| ())
        }),
        "audio" => fuzz_codec(rng, iters, seed, "audio", |bytes| {
            // Every audio entry point sees every mutated input: both
            // decoders and both signature facades, plus the facade.
            let _ = pith_hash::signature(bytes);
            let _ = pith_audio::wav::decode(bytes);
            let _ = pith_flac::decode(bytes, &pith_flac::Limits::default());
            let _ = pith_mp3::decode(bytes, &pith_mp3::Limits::default());
            let _ = pith_audio::signature_of_wav(bytes);
            let _ = pith_audio::signature_of_flac(bytes);
            Ok(())
        }),
        other => Err(format!("unknown target {other}")),
    }
}

/// Generic codec fuzz loop: seed corpus from `fuzz/corpus/<target>/` (one
/// file per case), mutate each seed through the four modes in round-robin,
/// run the decoder, and report panics with the reproducing iteration and
/// seed. Decoders signal corrupt input with `Err`, which is not a failure.
fn fuzz_codec(
    rng: &mut SplitMix64,
    iters: usize,
    seed: u64,
    target: &str,
    decode: impl Fn(&[u8]) -> Result<(), pith_digest::Error> + std::panic::RefUnwindSafe,
) -> Result<(), String> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
        .join(target);
    let mut corpus: Vec<Vec<u8>> = Vec::new();
    let entries = std::fs::read_dir(&dir)
        .map_err(|e| format!("corpus dir {} unreadable: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_file() {
            corpus.push(std::fs::read(&path).map_err(|e| format!("{e}"))?);
        }
    }
    if corpus.is_empty() {
        return Err(format!("corpus dir {} has no seed files", dir.display()));
    }
    for i in 0..iters {
        let base = &corpus[i % corpus.len()];
        let input = apply(MODES[i % MODES.len()], rng, base);
        // Panics inside the decoder are the failure the harness exists to
        // catch; catch_unwind turns them into a named crash report.
        let outcome = std::panic::catch_unwind(|| decode(&input));
        if outcome.is_err() {
            return Err(format!("{target} panicked at iter {i} (seed {seed})"));
        }
    }
    Ok(())
}

/// Fuzzes the mutation engine itself.
///
/// Every codec target is added later; this one exists so the PRNG, the four
/// mutation modes and the iteration loop are themselves verified from the
/// first commit. It asserts the property each mode is supposed to guarantee,
/// so a broken mutator fails here instead of silently weakening every codec
/// target that will be added on top of it.
fn fuzz_coremode(rng: &mut SplitMix64, iters: usize, seed: u64) -> Result<(), String> {
    // Two corpora. The first is seeded non-empty so truncate walks the corpus
    // down through its usual lengths. The second starts empty, so the
    // degenerate paths - mutate nothing, insert into nothing - are exercised
    // from iteration zero on every seed, rather than only when a seed happens
    // to truncate to zero first.
    let seeds: [&[u8]; 2] = [&(0..64u8).collect::<Vec<u8>>(), &[]];
    for (ci, base) in seeds.into_iter().enumerate() {
        let mut corpus: Vec<u8> = base.to_vec();
        for i in 0..iters {
            let mode = MODES[i % MODES.len()];
            let before = corpus.len();
            corpus = apply(mode, rng, &corpus);
            let after = corpus.len();
            let ok = match mode {
                // Length is chosen freely, but never unbounded.
                "random" => after <= 512,
                "truncate" => after <= before,
                // Length preserving, including zero -> zero.
                "bitflip" => after == before,
                "repeat-insert" => after >= before,
                _ => false,
            };
            if !ok {
                return Err(format!(
                    "mode {mode} broke its invariant at iter {i} of corpus {ci}: \
                     len {before} -> {after} (seed {seed})"
                ));
            }
        }
        let digest = corpus.iter().fold(0u64, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01B3)
        });
        println!(
            "coremode {ci}: {iters} iters, seed {seed}, final corpus {} B, digest {digest:#018x}",
            corpus.len()
        );
    }
    Ok(())
}

/// Fuzzes `pith-flac`'s decoder entry point.
///
/// The corpus starts from a complete, checksum-valid stream (a mono
/// 16-bit 44.1 kHz stream with one 8-sample verbatim frame, built
/// bit-for-bit by the crate's own test harness) and is mutated in place,
/// so most iterations land inside the format rather than bouncing off
/// the `fLaC` signature check. The decoder's contract is that every
/// input returns `Ok` or `Err` - the only hard failure is a panic, so
/// each call runs inside `catch_unwind` to turn one into a located
/// report instead of an abort.
fn fuzz_flac(rng: &mut SplitMix64, iters: usize, seed: u64) -> Result<(), String> {
    /// A complete valid stream: fLaC + STREAMINFO + one verbatim frame.
    const SEED_STREAM: &[u8] = &[
        0x66, 0x4c, 0x61, 0x43, 0x80, 0x00, 0x00, 0x22, 0x00, 0xc0, 0x12, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0a, 0xc4, 0x40, 0xf0, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xf8, 0x60, 0x00, 0x00, 0x07, 0xff,
        0x02, 0x00, 0x01, 0xff, 0xfe, 0x00, 0x03, 0xff, 0xfc, 0x00, 0x05, 0xff, 0xfa, 0x00, 0x07,
        0xff, 0xf8, 0xaf, 0x0b,
    ];
    let mut corpus: Vec<u8> = SEED_STREAM.to_vec();
    for i in 0..iters {
        let mode = MODES[i % MODES.len()];
        corpus = apply(mode, rng, &corpus);
        // Mutations can grow the corpus; cap it so the decode stays
        // inside `pith_flac::Limits::default().max_input` and every
        // iteration exercises parsing, not the input-length ceiling.
        if corpus.len() > 1024 {
            corpus.truncate(1024);
        }
        let input = corpus.clone();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            pith_flac::decode(&input, &pith_flac::Limits::default())
        }));
        if outcome.is_err() {
            return Err(format!(
                "flac panicked at iter {i} (mode {mode}, seed {seed}), input {} B",
                corpus.len()
            ));
        }
    }
    println!("flac: {iters} iters, seed {seed}, no panic");
    Ok(())
}

fn usage() -> String {
    let mut s = String::from("usage: fuzz <target> <iters> <seed>\n\ntargets:\n");
    s.push_str("  coremode  mutation engine self-check\n");
    // TARGET_NAMES is a `const`, so on the MSRV toolchain clippy can
    // const-fold `is_empty()` and reject the branch as dead code while
    // no codec target is registered. The check becomes load-bearing
    // with the first registration; the allow keeps the empty state
    // compilable and the populated state honest.
    #[allow(clippy::const_is_empty)]
    if TARGET_NAMES.is_empty() {
        s.push_str("  (no codec targets registered yet - each codec phase adds its own)\n");
    } else {
        for name in TARGET_NAMES {
            let _ = writeln!(s, "  {name}");
        }
    }
    let _ = write!(s, "\nmodes: {}\n", MODES.join(", "));
    s
}

fn main() -> ExitCode {
    run(&std::env::args().collect::<Vec<String>>())
}

/// The CLI body, split from `main` so the argument contract is unit
/// testable: 2 usage, 1 target failure, 0 clean run.
fn run(args: &[String]) -> ExitCode {
    if args.len() != 4 {
        eprint!("{}", usage());
        return ExitCode::from(2);
    }

    let target = args[1].as_str();
    let iters: usize = match args[2].parse() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("iters must be a non-negative integer, got {:?}", args[2]);
            return ExitCode::from(2);
        }
    };
    let seed: u64 = match args[3].parse() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("seed must be a u64, got {:?}", args[3]);
            return ExitCode::from(2);
        }
    };

    let mut rng = SplitMix64::new(seed);
    match dispatch(target, &mut rng, iters, seed) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fuzz failed: {e}");
            eprint!("{}", usage());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every mutation mode keeps its documented length invariant across
    /// a seeded run — the same property `coremode` asserts, checked
    /// here against `apply` directly.
    #[test]
    fn mutation_modes_keep_their_invariants() {
        let mut rng = SplitMix64::new(0xF00D);
        let base: Vec<u8> = (0..=255u8).collect();
        for i in 0..400 {
            let mode = MODES[i % MODES.len()];
            let before = base.len();
            let out = apply(mode, &mut rng, &base);
            let after = out.len();
            let ok = match mode {
                "random" => after <= 512,
                "truncate" => after <= before,
                "bitflip" => after == before,
                "repeat-insert" => after >= before,
                _ => false,
            };
            assert!(ok, "mode {mode}: len {before} -> {after}");
        }
    }

    /// The empty-input edges: bitflip is identity, repeat-insert
    /// materializes one byte, truncate can reach zero.
    #[test]
    fn empty_input_edges() {
        let mut rng = SplitMix64::new(7);
        assert!(apply("bitflip", &mut rng, b"").is_empty());
        assert_eq!(apply("repeat-insert", &mut rng, b"").len(), 1);
        assert_eq!(apply("truncate", &mut rng, b"").len(), 0);
    }

    /// The coremode target runs and reports both corpora.
    #[test]
    fn coremode_runs() {
        let mut rng = SplitMix64::new(0xC0DE);
        assert!(fuzz_coremode(&mut rng, 40, 0xC0DE).is_ok());
    }

    /// The embedded-seed flac target runs end to end.
    #[test]
    fn flac_target_runs() {
        let mut rng = SplitMix64::new(0xF1AC);
        assert!(fuzz_flac(&mut rng, 40, 0xF1AC).is_ok());
    }

    /// Unknown targets are named refusals, and the usage text lists
    /// every registered target plus the mutation modes.
    #[test]
    fn usage_and_dispatch_edges() {
        let mut rng = SplitMix64::new(1);
        assert_eq!(
            dispatch("nope", &mut rng, 1, 1),
            Err("unknown target nope".to_owned())
        );
        let u = usage();
        assert!(u.contains("usage: fuzz <target> <iters> <seed>"));
        assert!(u.contains("coremode"));
        for name in TARGET_NAMES {
            assert!(u.contains(name), "usage must list {name}");
        }
        assert!(u.contains("repeat-insert"));
    }

    /// Every corpus-backed codec target runs against the committed
    /// `fuzz/corpus/` seeds without a panic; a missing corpus dir is a
    /// named refusal, not a crash.
    #[test]
    fn corpus_backed_targets_run_and_refuse_cleanly() {
        let mut rng = SplitMix64::new(2);
        for target in TARGET_NAMES {
            dispatch(target, &mut rng, 8, 2).unwrap_or_else(|e| panic!("{target} must run: {e}"));
        }
        // A target whose corpus dir does not exist refuses by name.
        let err = fuzz_codec(&mut rng, 1, 2, "nope", |_| Ok(())).expect_err("missing corpus");
        assert!(err.contains("corpus dir"), "{err}");
        assert!(err.contains("nope"), "{err}");
    }

    /// The CLI body's argument contract: wrong arity, bad numbers and
    /// an unknown target map to 2/1, a clean run to success.
    #[test]
    fn run_argument_contract() {
        let a = |t: &str, i: &str, s: &str| {
            [
                std::string::String::from("fuzz"),
                std::string::String::from(t),
                std::string::String::from(i),
                std::string::String::from(s),
            ]
        };
        assert_eq!(run(&[]), ExitCode::from(2));
        assert_eq!(run(&a("mp4", "x", "1")), ExitCode::from(2));
        assert_eq!(run(&a("mp4", "1", "z")), ExitCode::from(2));
        assert_eq!(run(&a("nope", "1", "3")), ExitCode::from(1));
        assert_eq!(run(&a("coremode", "4", "9")), ExitCode::SUCCESS);
    }
}
