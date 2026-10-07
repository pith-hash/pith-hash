//! Regenerates and verifies `reference.json`, the hex-exact cross-SDK
//! test vectors for `pith-hash`, the suite's curator.
//!
//! Every vector is computed through the facade's public API
//! ([`detect`](pith_hash::detect), [`signature`](pith_hash::signature),
//! [`describe`](pith_hash::describe), [`match_`](pith_hash::match_))
//! over a deterministic corpus spanning every modality: image (the
//! upstream oracle PNG/JPEG fixtures plus a synthesized patterned BMP),
//! text (deterministic prose), audio (wav fixture and mp3 fixture),
//! video (mp4 fixture and its mov remux), pdf, zip/binary. Fixture
//! bytes are embedded at compile time from `tests/fixtures/` — no
//! working-directory dependence — and every inline recipe is
//! SplitMix64-seeded, so the output is byte-stable everywhere.
//!
//! Pin policy (the flat-fixture lesson from the video lane): DCT AC
//! coefficients near the subnormal floor flip bits across platforms, so
//! only fixtures with real low-frequency energy carry hash pins — all
//! pins are integers, folds, or raw IEEE-754 bit patterns (`policy:
//! "exact"`), never decimal floats.
//!
//! Usage:
//! - `gen-reference gen` — recompute every vector and write
//!   `reference.json` at the repository root.
//! - `gen-reference verify` — recompute and compare byte-for-byte
//!   against the committed copy; exit 1 on drift. This is the CI gate.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pith_digest::SplitMix64;
use pith_hash::reference::{f64_bits, fold_audio, fold_binary, fold_words, hex};
use pith_hash::{Description, Facts, MatchOutcome, Signature, describe, detect, match_, signature};

/// Where the committed copy lives, relative to the repository root.
const REFERENCE_PATH: &str = "reference.json";

/// The compact fold fields every signature vector carries, keyed by
/// modality.
fn signature_fold_fields(sig: &Signature) -> String {
    match sig {
        Signature::Image(h) => format!("      \"phash\": \"{h:#018x}\""),
        Signature::Audio(a) => {
            let (count, fnv, sha) = fold_audio(a);
            format!(
                "      \"peak_count\": {count},\n      \"peaks_fnv1a64\": \"{fnv:016x}\",\n      \"peaks_sha256\": \"{sha}\",\n      \"frames\": {}",
                a.frames()
            )
        }
        Signature::Text(words) => {
            let (count, fnv, sha) = fold_words(words);
            format!(
                "      \"minhash_words\": {count},\n      \"minhash_fnv1a64\": \"{fnv:016x}\",\n      \"minhash_sha256\": \"{sha}\""
            )
        }
        Signature::Binary(b) => {
            let (count, fnv, sha) = fold_binary(b);
            format!(
                "      \"chunk_count\": {count},\n      \"chunks_fnv1a64\": \"{fnv:016x}\",\n      \"chunks_sha256\": \"{sha}\""
            )
        }
        Signature::Video(v) => {
            let (frame_count, frame_fnv, frame_sha) = fold_words(&v.frame_hashes);
            let (minhash_words, minhash_fnv, _) = fold_words(&v.minhash);
            format!(
                "      \"frame_count\": {frame_count},\n      \"frames_fnv1a64\": \"{frame_fnv:016x}\",\n      \"frames_sha256\": \"{frame_sha}\",\n      \"minhash_words\": {minhash_words},\n      \"minhash_fnv1a64\": \"{minhash_fnv:016x}\",\n      \"width\": {},\n      \"height\": {},\n      \"duration_bits\": \"{}\"",
                v.width,
                v.height,
                f64_bits(v.duration)
            )
        }
    }
}

/// Serializes one vector from ordered field lines.
fn object(fields: &[String]) -> String {
    let mut s = String::from("    {\n");
    s.push_str(&fields.join(",\n"));
    s.push_str("\n    }");
    s
}

// ---------------------------------------------------------------------
// Deterministic inline corpus (the suite's fixture recipes)
// ---------------------------------------------------------------------

/// SplitMix64 byte stream: one `next_u64` per byte, low byte kept —
/// the upstream conformance recipe.
fn splitmix_bytes(seed: u64, length: usize) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed);
    (0..length).map(|_| rng.next_u64() as u8).collect()
}

/// The 48 KiB pseudo-file recipe of the upstream facade suite.
fn blob48(seed: u64) -> Vec<u8> {
    splitmix_bytes(seed, 48 * 1024)
}

/// Deterministic ~`bytes`-sized prose: words drawn from the suite's
/// seeded 24-word vocabulary, one space separated (the CLI fixture
/// recipe, verbatim).
fn prose(seed: u64, bytes: usize) -> String {
    const VOCAB: [&str; 24] = [
        "hash", "image", "audio", "signal", "codec", "block", "frame", "sample", "stream",
        "vector", "median", "kernel", "window", "raster", "pixel", "tone", "hash", "luma", "delta",
        "chunk", "radix", "filter", "table", "edge",
    ];
    let mut rng = SplitMix64::new(seed);
    let mut out = String::with_capacity(bytes + 16);
    while out.len() < bytes {
        out.push_str(VOCAB[(rng.next_u64() as usize) % VOCAB.len()]);
        out.push(' ');
    }
    out.truncate(bytes);
    out
}

/// Encodes RGB triples (`3·w·h` bytes) as a bottom-up 24-bit BMP — the
/// suite's deterministic fixture encoder, verbatim.
fn bmp24(w: u32, h: u32, rgb: &[u8]) -> Vec<u8> {
    debug_assert_eq!(rgb.len(), (w * h * 3) as usize);
    let row = (w as usize * 3).div_ceil(4) * 4;
    let img = row * h as usize;
    let mut f = Vec::with_capacity(54 + img);
    f.extend_from_slice(b"BM");
    f.extend_from_slice(&(54 + img as u32).to_le_bytes());
    f.extend_from_slice(&[0; 4]); // reserved
    f.extend_from_slice(&54u32.to_le_bytes()); // pixel offset
    f.extend_from_slice(&40u32.to_le_bytes()); // DIB header
    f.extend_from_slice(&w.to_le_bytes());
    f.extend_from_slice(&h.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes()); // planes
    f.extend_from_slice(&24u16.to_le_bytes()); // bpp
    f.extend_from_slice(&[0; 24]); // compression + sizes + ppm + colors
    for y in (0..h as usize).rev() {
        for x in 0..w as usize {
            let i = (y * w as usize + x) * 3;
            f.extend_from_slice(&[rgb[i + 2], rgb[i + 1], rgb[i]]); // BGR
        }
        f.resize(f.len() + (row - w as usize * 3), 0);
    }
    f
}

/// Smooth periodic RGB content with real low-frequency energy — the
/// patterned-fixture recipe. (Flat fills are excluded from hash pins:
/// their DCT AC coefficients sit near the subnormal floor and flip bits
/// across platforms.)
fn patterned_pixels(seed: u64, w: u32, h: u32) -> Vec<u8> {
    let mut rng = SplitMix64::new(seed);
    let fx = (rng.next_u64() % 5 + 1) as f64;
    let fy = (rng.next_u64() % 5 + 1) as f64;
    let p1 = (rng.next_u64() % 628) as f64 / 100.0;
    let p2 = (rng.next_u64() % 628) as f64 / 100.0;
    let mut px = Vec::with_capacity(w as usize * h as usize * 3);
    for y in 0..h as usize {
        for x in 0..w as usize {
            let u = x as f64 / w as f64;
            let v = y as f64 / h as f64;
            let r = 127.5 + 120.0 * (u * fx * std::f64::consts::TAU + p1).sin();
            let g = 127.5 + 120.0 * (v * fy * std::f64::consts::TAU + p2).sin();
            let b = 127.5 + 120.0 * ((u + v) * (fx + fy) + p1 + p2).sin();
            px.extend_from_slice(&[r as u8, g as u8, b as u8]);
        }
    }
    px
}

// Embedded fixture bytes (byte-exact copies of the upstream suite
// corpus; see tests/fixtures/PROVENANCE.md for per-file provenance).

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/",
            $name
        ))
    };
}

/// Builds the whole reference.json text.
fn reference_json() -> String {
    let mut vectors: Vec<String> = Vec::new();

    let png48 = fixture!("phash_rgb8_48x40.png");
    let gray40 = fixture!("phash_gray8_40x32.png");
    let png_base = fixture!("base_444.png");
    let jpg_base = fixture!("base_444.jpg");
    let wav = fixture!("tone.wav");
    let flac = fixture!("tone.flac");
    let mp3 = fixture!("l3_short.mp3");
    let mp4 = fixture!("a_64x48.mp4");
    let mov = fixture!("a_64x48.mov");
    let mp4v = fixture!("e_mp4v.mp4");
    let pdf = fixture!("text_page.pdf");

    let bmp_synth = bmp24(48, 40, &patterned_pixels(0xBEEF_0001, 48, 40));
    let blob = blob48(0xD15E_5EED);
    let blob_shifted = {
        let mut out = vec![0xAAu8];
        out.extend_from_slice(&blob48(0xD15E_5EED));
        out
    };
    let blob_other = blob48(0xBADC_0FFE);
    let prose_a = prose(0xD1, 4096);
    let prose_b = prose(0xD2, 4096);

    // --- detect vectors: one per container magic plus the heuristic
    //     lanes (bare text, non-UTF-8 binary, out-of-vocabulary zip/gif)
    let mut detect_row = |name: &str, bytes: &[u8]| {
        let d = detect(bytes);
        vectors.push(object(&[
            format!("      \"name\": \"detect-{name}\""),
            format!("      \"format\": \"{}\"", d.format.as_str()),
            format!("      \"modality\": \"{}\"", d.modality.as_str()),
            format!("      \"pending\": {}", d.pending),
        ]));
    };
    detect_row("png", png48);
    detect_row("jpeg", jpg_base);
    detect_row("bmp", &bmp_synth);
    detect_row("wav", wav);
    detect_row("flac", flac);
    detect_row("mp3", mp3);
    detect_row("mp4", mp4);
    detect_row("mov", mov);
    detect_row("pdf", pdf);
    detect_row("zip", b"PK\x03\x04\x14\x00\x00\x00\x00\x00");
    detect_row("gif", b"GIF89a\x01\x00\x01\x00");
    detect_row("text", b"just some words");
    detect_row("binary", b"\x00\xff\x02\xfe");

    // --- signature vectors: one per modality lane, integer/fold pins
    let mut sig_row = |name: &str, bytes: &[u8]| {
        let sig = signature(bytes).expect("reference corpus must sign");
        let mut fields = vec![format!("      \"name\": \"sig-{name}\"")];
        fields.push(format!(
            "      \"modality\": \"{}\"",
            sig.modality().as_str()
        ));
        fields.push(signature_fold_fields(&sig));
        vectors.push(object(&fields));
    };
    sig_row("image-phash_rgb8_48x40", png48);
    sig_row("image-phash_gray8_40x32", gray40);
    sig_row("image-base_444-png", png_base);
    sig_row("image-base_444-jpeg", jpg_base);
    sig_row("image-bmp-patterned-48x40", &bmp_synth);
    sig_row("audio-tone-wav", wav);
    sig_row("audio-tone-flac", flac);
    sig_row("audio-l3_short-mp3", mp3);
    sig_row("text-prose-4kib", prose_a.as_bytes());
    sig_row("binary-splitmix64-48kib", &blob);
    sig_row("binary-splitmix64-48kib-prefix-insert", &blob_shifted);
    sig_row("binary-splitmix64-48kib-unrelated", &blob_other);
    sig_row("video-a_64x48-mp4", mp4);
    sig_row("pdf-text_page", pdf);

    // --- describe vectors: tier-1 hex, facts integers, signature fold
    let mut describe_row = |name: &str, bytes: &[u8]| {
        let d: Description = describe(bytes).expect("reference corpus must describe");
        let mut fields = vec![format!("      \"name\": \"describe-{name}\"")];
        fields.push(format!("      \"format\": \"{}\"", d.format.as_str()));
        fields.push(format!("      \"modality\": \"{}\"", d.modality.as_str()));
        fields.push(format!("      \"tier1\": \"{}\"", hex(d.tier1.as_bytes())));
        fields.push(signature_fold_fields(&d.signature));
        fields.push(match &d.facts {
            Facts::Image {
                width,
                height,
                keypoints,
            } => format!(
                "      \"facts\": {{ \"width\": {width}, \"height\": {height}, \"keypoints\": {keypoints} }}"
            ),
            Facts::Audio {
                sample_rate,
                channels,
                frames,
                peaks,
            } => format!(
                "      \"facts\": {{ \"sample_rate\": {sample_rate}, \"channels\": {channels}, \"frames\": {frames}, \"peaks\": {peaks} }}"
            ),
            Facts::Text {
                words,
                canonical_len,
            } => format!(
                "      \"facts\": {{ \"words\": {words}, \"canonical_len\": {canonical_len} }}"
            ),
            Facts::Binary { len, chunks } => {
                format!("      \"facts\": {{ \"len\": {len}, \"chunks\": {chunks} }}")
            }
            Facts::Video {
                width,
                height,
                duration_s,
                frames_sampled,
            } => format!(
                "      \"facts\": {{ \"width\": {width}, \"height\": {height}, \"duration_bits\": \"{}\", \"frames_sampled\": {frames_sampled} }}",
                f64_bits(*duration_s)
            ),
        });
        vectors.push(object(&fields));
    };
    describe_row("image-phash_rgb8_48x40", png48);
    describe_row("image-bmp-patterned-48x40", &bmp_synth);
    describe_row("audio-tone-wav", wav);
    describe_row("text-prose-4kib", prose_a.as_bytes());
    describe_row("binary-splitmix64-48kib", &blob);
    describe_row("video-a_64x48-mp4", mp4);
    describe_row("pdf-text_page", pdf);

    // --- match vectors: distances and verdicts, floats as raw bits
    let mut match_row = |name: &str, a: &Signature, b: &Signature| {
        let outcome = match_(a, b).expect("same-modality match");
        let mut fields = vec![format!("      \"name\": \"match-{name}\"")];
        match &outcome {
            MatchOutcome::Image { hamming, matched } => {
                fields.push("      \"outcome\": \"image\"".to_owned());
                fields.push(format!("      \"hamming\": {hamming}"));
                fields.push(format!("      \"matched\": {matched}"));
            }
            MatchOutcome::Audio { best, matched } => {
                fields.push("      \"outcome\": \"audio\"".to_owned());
                match best {
                    Some(m) => {
                        fields.push(format!("      \"votes\": {}", m.votes));
                        fields.push(format!("      \"delta_t\": {}", m.delta_t));
                    }
                    None => fields.push("      \"votes\": 0".to_owned()),
                }
                fields.push(format!("      \"matched\": {matched}"));
            }
            MatchOutcome::Text { jaccard, matched } | MatchOutcome::Binary { jaccard, matched } => {
                fields.push("      \"outcome\": \"jaccard\"".to_owned());
                fields.push("      \"value_kind\": \"f64-ieee754-bits-hex\"".to_owned());
                fields.push(format!(
                    "      \"jaccard_bits\": \"{}\"",
                    f64_bits(*jaccard)
                ));
                fields.push(format!("      \"matched\": {matched}"));
            }
            MatchOutcome::Video {
                score,
                minhash_jaccard,
                matched,
            } => {
                fields.push("      \"outcome\": \"video\"".to_owned());
                fields.push("      \"value_kind\": \"f64-ieee754-bits-hex\"".to_owned());
                fields.push(format!("      \"score_bits\": \"{}\"", f64_bits(*score)));
                fields.push(format!(
                    "      \"minhash_jaccard_bits\": \"{}\"",
                    f64_bits(*minhash_jaccard)
                ));
                fields.push(format!("      \"matched\": {matched}"));
            }
        }
        vectors.push(object(&fields));
    };

    let sig_png48 = signature(png48).expect("signs");
    let sig_gray40 = signature(gray40).expect("signs");
    let sig_wav = signature(wav).expect("signs");
    let sig_mp4 = signature(mp4).expect("signs");
    let sig_mov = signature(mov).expect("signs");
    match_row("image-self", &sig_png48, &sig_png48);
    match_row("image-distinct", &sig_png48, &sig_gray40);
    match_row(
        "image-png-vs-jpeg-same-pixels",
        &signature(png_base).expect("signs"),
        &signature(jpg_base).expect("signs"),
    );
    match_row("audio-self", &sig_wav, &sig_wav);
    match_row(
        "text-self",
        &signature(prose_a.as_bytes()).expect("signs"),
        &signature(prose_a.as_bytes()).expect("signs"),
    );
    match_row(
        "text-distinct",
        &signature(prose_a.as_bytes()).expect("signs"),
        &signature(prose_b.as_bytes()).expect("signs"),
    );
    match_row(
        "binary-near-duplicate",
        &signature(&blob).expect("signs"),
        &signature(&blob_shifted).expect("signs"),
    );
    match_row(
        "binary-unrelated",
        &signature(&blob).expect("signs"),
        &signature(&blob_other).expect("signs"),
    );
    match_row("video-mp4-vs-mov", &sig_mp4, &sig_mov);

    // The cross-modality refusal is itself a pinned vector: the exact
    // Display message, stable across SDKs.
    let cross = match_(&sig_png48, &signature(prose_a.as_bytes()).expect("signs"));
    let cross_msg = match cross {
        Err(e) => e.to_string(),
        Ok(_) => panic!("cross-modality match must refuse"),
    };
    vectors.push(object(&[
        "      \"name\": \"match-error-cross-modality\"".to_owned(),
        "      \"outcome\": \"error\"".to_owned(),
        format!("      \"error_message\": \"{}\"", cross_msg),
    ]));

    // The non-AVC video track refusal names the codec — pinned text.
    let mp4v_err = match signature(mp4v) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("mpeg4-part-2 must refuse"),
    };
    vectors.push(object(&[
        "      \"name\": \"error-video-non-avc\"".to_owned(),
        "      \"outcome\": \"error\"".to_owned(),
        format!("      \"error_message\": \"{}\"", mp4v_err),
    ]));

    let mut s = String::new();
    s.push_str("{\n");
    s.push_str("  \"suite\": \"pith\",\n");
    s.push_str("  \"crate\": \"pith-hash\",\n");
    s.push_str("  \"format_version\": 1,\n");
    s.push_str("  \"generator\": \"cargo run --bin gen-reference -- gen\",\n");
    s.push_str("  \"description\": \"Hex-exact cross-modal reference vectors for the pith-hash curator: detect verdicts per container magic, tier-2 signature folds (image pHash, audio landmark folds, MinHash folds, FastCDC chunk folds, video frame-chain folds), describe tier-1 digests with facts, and match outcomes (integer hamming/votes, IEEE-754-bit Jaccard and score pins, exact refusal messages) over the committed fixture corpus plus deterministic inline recipes. Hash pins carry only fixtures with real low-frequency energy; flat fills are excluded (subnormal-floor DCT AC flips bits across platforms).\",\n");
    s.push_str("  \"vectors\": [\n");
    s.push_str(&vectors.join(",\n"));
    s.push_str("\n  ]\n");
    s.push_str("}\n");
    s
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    let path = args.next().map(PathBuf::from);
    run(&mode, path.as_deref())
}

/// One CLI invocation, split out of [`main`] so the mode dispatch is
/// unit-testable. `path` overrides the repository-root `reference.json`.
fn run(mode: &str, path: Option<&Path>) -> ExitCode {
    let path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join(REFERENCE_PATH));
    match mode {
        "gen" => {
            let json = reference_json();
            fs::write(&path, &json).unwrap_or_else(|e| panic!("cannot write {path:?}: {e}"));
            println!("wrote {} ({} bytes)", path.display(), json.len());
            ExitCode::SUCCESS
        }
        "verify" => {
            let json = reference_json();
            let committed = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("FAIL: cannot read {path:?}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if committed == json.as_bytes() {
                println!("reference.json is current");
                ExitCode::SUCCESS
            } else {
                let off = committed
                    .iter()
                    .zip(json.as_bytes())
                    .position(|(a, b)| a != b)
                    .unwrap_or(committed.len().min(json.len()));
                eprintln!(
                    "FAIL: reference.json is stale: committed {} bytes, computed {} bytes, first difference at byte {off}",
                    committed.len(),
                    json.len()
                );
                ExitCode::FAILURE
            }
        }
        _ => {
            eprintln!("usage: gen-reference <gen|verify> [PATH] (got {mode:?})");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The detect verdicts of the inline magics pin the heuristic lanes.
    #[test]
    fn detect_pins_the_heuristic_lanes() {
        assert_eq!(
            detect(b"just some words").modality,
            pith_hash::Modality::Text
        );
        assert_eq!(
            detect(b"\x00\xff\x02\xfe").modality,
            pith_hash::Modality::Binary
        );
        let d = detect(b"PK\x03\x04\x14\x00\x00\x00\x00\x00");
        assert_eq!((d.format.as_str(), d.modality.as_str()), ("zip", "binary"));
    }

    /// The synthesized BMP is not flat: distinct seeds yield distinct
    /// pHashes (the flat-fixture exclusion would otherwise bite here).
    #[test]
    fn patterned_bmp_hash_is_seed_sensitive() {
        let a = bmp24(32, 32, &patterned_pixels(1, 32, 32));
        let b = bmp24(32, 32, &patterned_pixels(2, 32, 32));
        let Signature::Image(ha) = signature(&a).expect("signs") else {
            panic!("not an image signature")
        };
        let Signature::Image(hb) = signature(&b).expect("signs") else {
            panic!("not an image signature")
        };
        assert_ne!(ha, hb);
    }

    /// The prose recipe is deterministic and non-trivially distinct
    /// across seeds (shared vocabulary keeps partial shingle overlap).
    #[test]
    fn prose_recipe_is_deterministic() {
        assert_eq!(prose(7, 1024), prose(7, 1024));
        let a = prose(7, 1024);
        let b = prose(8, 1024);
        assert_ne!(a, b);
        assert_eq!(a.len(), 1024);
    }

    /// The JSON header is the cross-SDK identity block.
    #[test]
    fn json_carries_suite_identity() {
        let json = reference_json();
        assert!(json.contains("\"suite\": \"pith\""));
        assert!(json.contains("\"crate\": \"pith-hash\""));
        assert!(json.contains("\"format_version\": 1"));
        assert!(json.ends_with("}\n"));
        assert!(json.contains("\"policy\"") || json.contains("\"value_kind\""));
    }

    /// Byte-stability: two builds of the corpus produce identical JSON.
    #[test]
    fn reference_json_is_deterministic() {
        assert_eq!(reference_json(), reference_json());
    }

    /// The whole vector set is non-empty across every section the
    /// cross-SDK contract names.
    #[test]
    fn all_sections_present() {
        let json = reference_json();
        for section in [
            "\"name\": \"detect-png\"",
            "\"name\": \"sig-image-phash_rgb8_48x40\"",
            "\"name\": \"sig-audio-tone-wav\"",
            "\"name\": \"sig-text-prose-4kib\"",
            "\"name\": \"sig-binary-splitmix64-48kib\"",
            "\"name\": \"sig-video-a_64x48-mp4\"",
            "\"name\": \"sig-pdf-text_page\"",
            "\"name\": \"describe-image-phash_rgb8_48x40\"",
            "\"name\": \"describe-video-a_64x48-mp4\"",
            "\"name\": \"match-image-self\"",
            "\"name\": \"match-audio-self\"",
            "\"name\": \"match-text-self\"",
            "\"name\": \"match-binary-near-duplicate\"",
            "\"name\": \"match-video-mp4-vs-mov\"",
            "\"name\": \"match-error-cross-modality\"",
            "\"name\": \"error-video-non-avc\"",
        ] {
            assert!(json.contains(section), "reference.json missing {section}");
        }
    }

    /// `gen` and `verify` roundtrip against a private temp copy — the
    /// same-run gen→verify property the CD artifacts rely on. The test
    /// never touches the repository-root `reference.json`, so parallel
    /// test threads cannot interleave a rewrite with the read-only
    /// committed-copy `verify` in `tests/gen_reference.rs`.
    #[test]
    fn gen_then_verify_roundtrip_on_a_private_copy() {
        let dir = std::env::temp_dir().join(format!("pith-hash-roundtrip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("reference.json");
        assert_eq!(run("gen", Some(&path)), ExitCode::SUCCESS);
        assert_eq!(run("verify", Some(&path)), ExitCode::SUCCESS);
        std::fs::remove_file(&path).expect("cleanup");
        std::fs::remove_dir(&dir).expect("cleanup");
    }
}
