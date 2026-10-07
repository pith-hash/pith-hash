//! The canonical serializations behind `reference.json`, re-expressed as
//! library code so the vector generator (`tools/gen-reference`) and the
//! C ABI surface ([`crate::ffi`]) share one implementation.
//!
//! Two kinds of streams live here:
//!
//! # Reference folds (the bytes the recorded digests cover)
//!
//! [`fold_bytes`], [`fold_words`], [`fold_audio`], [`fold_binary`] are
//! the exact serializations `tools/gen-reference` records `fnv1a64` /
//! `sha256` sub-digests over:
//!
//! - a **byte fold** is the payload verbatim;
//! - a **word fold** (`Vec<u64>`) is the little-endian words
//!   concatenated;
//! - the **audio fold** is each peak's `t` as `u32` LE then `f` as
//!   `u16` LE, in signature order;
//! - the **binary fold** is the sorted unique chunk digests
//!   concatenated.
//!
//! Every `*_count` / `frames` / `minhash_words` field `reference.json`
//! records is the *byte length* of the folded payload (594 = 99 peaks
//! × 6 B, 160 = 5 chunks × 32 B, 1024 = 128 words × 8 B), so the
//! cross-SDK check compares one number on both sides.
//!
//! # FFI wire streams (what the language SDKs parse)
//!
//! ## Signature stream ([`signature_stream`])
//!
//! `tag: u8` (`0` image, `1` audio, `2` text, `3` binary, `4` video —
//! declaration order), then the per-tag payload. Every count field is
//! the big-endian byte length of the payload that follows it, and the
//! fixed-width scalars are big-endian. The audio/binary/video payloads
//! are the canonical fold bytes (`(u32, u16)` peak pairs, chunk
//! digests, little-endian words) — exactly the bytes the recorded
//! `*_sha256` covers, so an SDK re-hashes the sub-slice it just
//! bounds-checked; the text payload carries the words big-endian
//! (repack little-endian before re-hashing):
//!
//! - `0` image: `u64` BE phash;
//! - `1` audio: `u64` BE peak_count (bytes) · `u32` BE frames ·
//!   peaks fold bytes;
//! - `2` text: `u64` BE word_count (bytes) · word_count bytes of
//!   `u64` BE words;
//! - `3` binary: `u64` BE chunk_count (bytes) · chunk_count bytes of
//!   32-byte digests;
//! - `4` video: `u32` BE frame_count (bytes) · `u32` BE width ·
//!   `u32` BE height · `u64` BE duration (IEEE-754 bits) · frames
//!   fold bytes · minhash fold bytes (the rest of the stream; its
//!   byte length is the recorded `minhash_words`).
//!
//! ## Describe stream ([`describe_stream`])
//!
//! `u8` format code (the `pith_digest::Format` declaration order, the
//! `PITH_HASH_FORMAT_*` constants in [`crate::ffi`]) · `u8` modality
//! code (the [`Modality`] declaration order, `PITH_HASH_MODALITY_*`)
//! · 32-byte tier-1 digest · the signature stream · the facts block
//! for the modality, all big-endian:
//!
//! - image: `u32` width · `u32` height · `u64` keypoints;
//! - audio: `u32` sample_rate · `u16` channels · `u32` frames ·
//!   `u64` peaks;
//! - text: `u64` words · `u64` canonical_len;
//! - binary: `u64` len · `u64` chunks;
//! - video: `u32` width · `u32` height · `u64` duration bits ·
//!   `u64` frames_sampled.
//!
//! No RNG, no time, no platform-dependent bytes: every stream is
//! byte-stable everywhere, which is what makes the hex-exact
//! cross-SDK contract testable.

use crate::{Description, Modality, Signature};
use alloc::string::String;
use alloc::vec::Vec;
use pith_digest::{fnv1a64, sha256};

/// Signature-stream tag: an image pHash payload.
pub const SIGNATURE_TAG_IMAGE: u8 = 0;
/// Signature-stream tag: an audio landmark payload.
pub const SIGNATURE_TAG_AUDIO: u8 = 1;
/// Signature-stream tag: a text MinHash payload.
pub const SIGNATURE_TAG_TEXT: u8 = 2;
/// Signature-stream tag: a binary chunk-digest payload.
pub const SIGNATURE_TAG_BINARY: u8 = 3;
/// Signature-stream tag: a video fingerprint payload.
pub const SIGNATURE_TAG_VIDEO: u8 = 4;

/// The compact fold of an ordered byte payload: element count, FNV-1a
/// 64 over the little-endian bytes, SHA-256 over the same bytes.
#[must_use]
pub fn fold_bytes(payload: &[u8]) -> (usize, u64, String) {
    (
        payload.len(),
        fnv1a64(payload),
        hex(sha256(payload).expect("sha256").as_bytes()),
    )
}

/// Folds an ordered `u64` word stream (MinHash signatures, frame-hash
/// chains): little-endian words concatenated.
#[must_use]
pub fn fold_words(words: &[u64]) -> (usize, u64, String) {
    let mut le = Vec::with_capacity(words.len() * 8);
    for w in words {
        le.extend_from_slice(&w.to_le_bytes());
    }
    fold_bytes(&le)
}

/// Folds the audio signature's `(t, f)` landmarks: `t` as `u32` LE then
/// `f` as `u16` LE, per peak, in signature order.
#[must_use]
pub fn fold_audio(sig: &crate::AudioSignature) -> (usize, u64, String) {
    let mut le = Vec::new();
    for p in sig.peaks() {
        le.extend_from_slice(&p.t.to_le_bytes());
        le.extend_from_slice(&p.f.to_le_bytes());
    }
    fold_bytes(&le)
}

/// Folds a binary chunk-digest set through the file slice's own
/// accessor (sorted unique digests, little-endian).
#[must_use]
pub fn fold_binary(sig: &pith_file::BinarySignature) -> (usize, u64, String) {
    fold_bytes(&sig.chunks().concat())
}

/// Lowercase hex of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&alloc::format!("{b:02x}"));
    }
    s
}

/// `f64` as 16-digit hex of the IEEE-754 bit pattern.
#[must_use]
pub fn f64_bits(v: f64) -> String {
    alloc::format!("{:016x}", v.to_bits())
}

/// Serializes one tier-2 signature into the FFI wire stream (see the
/// module docs for the exact layout).
#[must_use]
pub fn signature_stream(sig: &Signature) -> Vec<u8> {
    let mut out = Vec::new();
    match sig {
        Signature::Image(phash) => {
            out.push(SIGNATURE_TAG_IMAGE);
            out.extend_from_slice(&phash.to_be_bytes());
        }
        Signature::Audio(a) => {
            out.push(SIGNATURE_TAG_AUDIO);
            let peaks = audio_peaks_bytes(a);
            out.extend_from_slice(&(peaks.len() as u64).to_be_bytes());
            out.extend_from_slice(&a.frames().to_be_bytes());
            out.extend_from_slice(&peaks);
        }
        Signature::Text(words) => {
            out.push(SIGNATURE_TAG_TEXT);
            out.extend_from_slice(&((words.len() * 8) as u64).to_be_bytes());
            for w in words {
                out.extend_from_slice(&w.to_be_bytes());
            }
        }
        Signature::Binary(b) => {
            out.push(SIGNATURE_TAG_BINARY);
            let digests = b.chunks().concat();
            out.extend_from_slice(&(digests.len() as u64).to_be_bytes());
            out.extend_from_slice(&digests);
        }
        Signature::Video(v) => {
            out.push(SIGNATURE_TAG_VIDEO);
            let mut frames = Vec::with_capacity(v.frame_hashes.len() * 8);
            for h in &v.frame_hashes {
                frames.extend_from_slice(&h.to_le_bytes());
            }
            let mut minhash = Vec::with_capacity(v.minhash.len() * 8);
            for w in &v.minhash {
                minhash.extend_from_slice(&w.to_le_bytes());
            }
            out.extend_from_slice(&(frames.len() as u32).to_be_bytes());
            out.extend_from_slice(&v.width.to_be_bytes());
            out.extend_from_slice(&v.height.to_be_bytes());
            out.extend_from_slice(&v.duration.to_bits().to_be_bytes());
            out.extend_from_slice(&frames);
            out.extend_from_slice(&minhash);
        }
    }
    out
}

/// Serializes one [`Description`] into the FFI wire stream: format and
/// modality codes, the tier-1 digest, the signature stream and the
/// modality's facts block (see the module docs).
#[must_use]
pub fn describe_stream(desc: &Description) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(format_code(desc.format));
    out.push(modality_code(desc.modality));
    out.extend_from_slice(desc.tier1.as_bytes());
    out.extend_from_slice(&signature_stream(&desc.signature));
    match &desc.facts {
        crate::Facts::Image {
            width,
            height,
            keypoints,
        } => {
            out.extend_from_slice(&width.to_be_bytes());
            out.extend_from_slice(&height.to_be_bytes());
            out.extend_from_slice(&(*keypoints as u64).to_be_bytes());
        }
        crate::Facts::Audio {
            sample_rate,
            channels,
            frames,
            peaks,
        } => {
            out.extend_from_slice(&sample_rate.to_be_bytes());
            out.extend_from_slice(&channels.to_be_bytes());
            out.extend_from_slice(&frames.to_be_bytes());
            out.extend_from_slice(&(*peaks as u64).to_be_bytes());
        }
        crate::Facts::Text {
            words,
            canonical_len,
        } => {
            out.extend_from_slice(&(*words as u64).to_be_bytes());
            out.extend_from_slice(&(*canonical_len as u64).to_be_bytes());
        }
        crate::Facts::Binary { len, chunks } => {
            out.extend_from_slice(&(*len as u64).to_be_bytes());
            out.extend_from_slice(&(*chunks as u64).to_be_bytes());
        }
        crate::Facts::Video {
            width,
            height,
            duration_s,
            frames_sampled,
        } => {
            out.extend_from_slice(&width.to_be_bytes());
            out.extend_from_slice(&height.to_be_bytes());
            out.extend_from_slice(&duration_s.to_bits().to_be_bytes());
            out.extend_from_slice(&(*frames_sampled as u64).to_be_bytes());
        }
    }
    out
}

/// The `pith_digest::Format` declaration-order wire code — the same
/// number the `PITH_HASH_FORMAT_*` constants in [`crate::ffi`] name.
#[must_use]
pub fn format_code(format: pith_digest::Format) -> u8 {
    match format {
        pith_digest::Format::Png => 0,
        pith_digest::Format::Jpeg => 1,
        pith_digest::Format::Bmp => 2,
        pith_digest::Format::Zip => 3,
        pith_digest::Format::Mp4 => 4,
        pith_digest::Format::Mp3 => 5,
        pith_digest::Format::Wav => 6,
        pith_digest::Format::Flac => 7,
        pith_digest::Format::Pdf => 8,
        pith_digest::Format::Gif => 9,
        pith_digest::Format::Unknown => 10,
    }
}

/// The [`Modality`] declaration-order wire code — the same number the
/// `PITH_HASH_MODALITY_*` constants in [`crate::ffi`] name.
#[must_use]
pub fn modality_code(modality: Modality) -> u8 {
    match modality {
        Modality::Image => 0,
        Modality::Audio => 1,
        Modality::Text => 2,
        Modality::Binary => 3,
        Modality::Video => 4,
    }
}

/// The audio fold bytes (each peak's `t` `u32` LE then `f` `u16` LE).
fn audio_peaks_bytes(sig: &crate::AudioSignature) -> Vec<u8> {
    let mut le = Vec::new();
    for p in sig.peaks() {
        le.extend_from_slice(&p.t.to_le_bytes());
        le.extend_from_slice(&p.f.to_le_bytes());
    }
    le
}

#[cfg(test)]
mod tests {
    use super::{
        SIGNATURE_TAG_BINARY, SIGNATURE_TAG_IMAGE, SIGNATURE_TAG_TEXT, describe_stream, f64_bits,
        fold_audio, fold_binary, fold_bytes, fold_words, format_code, hex, modality_code,
        signature_stream,
    };
    use crate::{Description, Facts, Modality, Signature, describe, signature};
    use alloc::{format, vec, vec::Vec};

    /// The byte fold is the payload verbatim; `f64_bits` and `hex`
    /// pin the recorded text forms.
    #[test]
    fn folds_are_the_recorded_serializations() {
        let (len, fnv, sha) = fold_bytes(&[1, 2, 3]);
        assert_eq!(len, 3);
        assert_eq!(fnv, 0xd0aa_6218_672c_f5ab); // FNV-1a 64 of 01 02 03
        assert_eq!(
            sha,
            "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81"
        );
        let (wlen, _, _) = fold_words(&[0x0102_0304_0506_0708]);
        assert_eq!(wlen, 8);
        assert_eq!(hex(&[0xde, 0xad]), "dead");
        assert_eq!(f64_bits(4.0), "4010000000000000");
    }

    /// The image stream is the tag plus the big-endian pHash; the text
    /// stream is the tag, the big-endian word byte-count and the words
    /// big-endian.
    #[test]
    fn image_and_text_streams_match_the_documented_layout() {
        let img = signature_stream(&Signature::Image(0x0123_4567_89ab_cdef));
        assert_eq!(
            img,
            [
                SIGNATURE_TAG_IMAGE,
                0x01,
                0x23,
                0x45,
                0x67,
                0x89,
                0xab,
                0xcd,
                0xef
            ]
        );

        let text = signature_stream(&Signature::Text(vec![1, 2]));
        assert_eq!(text[0], SIGNATURE_TAG_TEXT);
        assert_eq!(&text[1..9], &16u64.to_be_bytes());
        assert_eq!(&text[9..17], &1u64.to_be_bytes());
        assert_eq!(&text[17..25], &2u64.to_be_bytes());
    }

    /// The binary stream prefixes the big-endian digest byte-count.
    #[test]
    fn binary_stream_carries_the_digest_concatenation() {
        let sig = pith_file::binary_signature(b"a small binary body for chunking").expect("chunks");
        let stream = signature_stream(&Signature::Binary(sig.clone()));
        assert_eq!(stream[0], SIGNATURE_TAG_BINARY);
        let count = u64::from_be_bytes(stream[1..9].try_into().expect("count"));
        assert_eq!(count as usize, stream.len() - 9);
        assert_eq!(count as usize % 32, 0);
        let (expected_len, _, _) = fold_binary(&sig);
        assert_eq!(count as usize, expected_len);
    }

    /// The describe stream is format code, modality code, tier 1, the
    /// signature stream, then the facts block — verified end to end on
    /// a text description (the lane with no decoder in the way).
    #[test]
    fn describe_stream_layout_for_text() {
        let desc = describe(b"just some words").expect("describes");
        let stream = describe_stream(&desc);
        assert_eq!(stream[0], format_code(desc.format));
        assert_eq!(stream[1], modality_code(Modality::Text));
        assert_eq!(&stream[2..34], desc.tier1.as_bytes());
        let sig = signature_stream(&desc.signature);
        assert_eq!(&stream[34..34 + sig.len()], &sig[..]);
        // Text facts: words u64 BE, canonical_len u64 BE.
        let facts = &stream[34 + sig.len()..];
        assert_eq!(facts.len(), 16);
        let (words, canonical_len) = match desc.facts {
            Facts::Text {
                words,
                canonical_len,
            } => (words, canonical_len),
            _ => panic!("text facts"),
        };
        assert_eq!(
            u64::from_be_bytes(facts[..8].try_into().expect("words")),
            words as u64
        );
        assert_eq!(
            u64::from_be_bytes(facts[8..].try_into().expect("len")),
            canonical_len as u64
        );
    }

    /// The image describe stream ends in the 20-byte image facts
    /// block, exercised through the real facade on a fixture.
    #[test]
    fn describe_stream_layout_for_image() {
        let png = fixture_bytes("phash_rgb8_48x40.png");
        let desc: Description = describe(&png).expect("describes");
        let stream = describe_stream(&desc);
        let sig = signature_stream(&desc.signature);
        let facts = &stream[34 + sig.len()..];
        assert_eq!(facts.len(), 16);
        match desc.facts {
            Facts::Image {
                width,
                height,
                keypoints,
            } => {
                assert_eq!(
                    u32::from_be_bytes(facts[0..4].try_into().expect("w")),
                    width
                );
                assert_eq!(
                    u32::from_be_bytes(facts[4..8].try_into().expect("h")),
                    height
                );
                assert_eq!(
                    u64::from_be_bytes(facts[8..].try_into().expect("kp")),
                    keypoints as u64
                );
            }
            _ => panic!("image facts"),
        }
        assert_eq!(stream[0], format_code(pith_digest::Format::Png));
    }

    /// The audio, binary and video describe streams end in their
    /// documented facts blocks, exercised through the real facade.
    #[test]
    fn describe_stream_layout_for_audio_binary_video() {
        // Audio: sample_rate u32, channels u16, frames u32, peaks u64.
        let wav = fixture_bytes("tone.wav");
        let desc = describe(&wav).expect("describes");
        let stream = describe_stream(&desc);
        let sig = signature_stream(&desc.signature);
        let facts = &stream[34 + sig.len()..];
        assert_eq!(facts.len(), 18);
        match desc.facts {
            Facts::Audio {
                sample_rate,
                channels,
                frames,
                peaks,
            } => {
                assert_eq!(
                    u32::from_be_bytes(facts[0..4].try_into().expect("rate")),
                    sample_rate
                );
                assert_eq!(
                    u16::from_be_bytes(facts[4..6].try_into().expect("ch")),
                    channels
                );
                assert_eq!(
                    u32::from_be_bytes(facts[6..10].try_into().expect("f")),
                    frames
                );
                assert_eq!(
                    u64::from_be_bytes(facts[10..].try_into().expect("p")),
                    peaks as u64
                );
            }
            _ => panic!("audio facts"),
        }

        // Binary: len u64, chunks u64.
        let desc = describe(b"just some words for the binary lane \xff").expect("describes");
        let stream = describe_stream(&desc);
        let sig = signature_stream(&desc.signature);
        let facts = &stream[34 + sig.len()..];
        assert_eq!(facts.len(), 16);
        match desc.facts {
            Facts::Binary { len, chunks } => {
                assert_eq!(
                    u64::from_be_bytes(facts[..8].try_into().expect("len")),
                    len as u64
                );
                assert_eq!(
                    u64::from_be_bytes(facts[8..].try_into().expect("chunks")),
                    chunks as u64
                );
            }
            _ => panic!("binary facts"),
        }

        // Video: width u32, height u32, duration bits u64,
        // frames_sampled u64.
        let mp4 = fixture_bytes("a_64x48.mp4");
        let desc = describe(&mp4).expect("describes");
        let stream = describe_stream(&desc);
        let sig = signature_stream(&desc.signature);
        let facts = &stream[34 + sig.len()..];
        assert_eq!(facts.len(), 24);
        match desc.facts {
            Facts::Video {
                width,
                height,
                duration_s,
                frames_sampled,
            } => {
                assert_eq!(
                    u32::from_be_bytes(facts[0..4].try_into().expect("w")),
                    width
                );
                assert_eq!(
                    u32::from_be_bytes(facts[4..8].try_into().expect("h")),
                    height
                );
                assert_eq!(
                    u64::from_be_bytes(facts[8..16].try_into().expect("d")),
                    duration_s.to_bits()
                );
                assert_eq!(
                    u64::from_be_bytes(facts[16..].try_into().expect("fs")),
                    frames_sampled as u64
                );
            }
            _ => panic!("video facts"),
        }
    }

    /// A real WAV through the audio stream: the peak byte-count
    /// header, the frames header and the fold bytes line up with the
    /// recorded fold helpers.
    #[test]
    fn audio_stream_carries_the_peak_fold() {
        let wav = fixture_bytes("tone.wav");
        let sig = signature(&wav).expect("signs");
        let stream = signature_stream(&sig);
        assert_eq!(stream[0], 1);
        let count = u64::from_be_bytes(stream[1..9].try_into().expect("count"));
        let frames = u32::from_be_bytes(stream[9..13].try_into().expect("frames"));
        let Signature::Audio(a) = &sig else {
            panic!("audio signature")
        };
        assert_eq!(frames, a.frames());
        assert_eq!(count as usize, stream.len() - 13);
        let (expected_len, expected_fnv, expected_sha) = fold_audio(a);
        assert_eq!(count as usize, expected_len);
        let (_, fnv, sha) = fold_bytes(&stream[13..]);
        assert_eq!((fnv, sha), (expected_fnv, expected_sha));
    }

    fn fixture_bytes(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .expect("fixture")
    }
}
