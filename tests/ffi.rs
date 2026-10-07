//! The C ABI surface exercised end to end through raw pointers.
//!
//! These tests live behind `cargo test` as an integration target on
//! purpose: `src/ffi.rs` compiles only into the normal rlib/cdylib
//! flavor of the crate (see the `#[cfg(not(test))]` gate on
//! `pith_hash::ffi`), so this is the only harness whose coverage lands
//! on the exported functions — the same flavor the release cdylib is
//! built from.

use std::fs;

use pith_hash::ffi::{
    PITH_E_INVALID, PITH_E_REJECTED, PITH_HASH_FORMAT_MP4, PITH_HASH_FORMAT_PNG,
    PITH_HASH_MATCH_IMAGE, PITH_HASH_MATCH_TEXT, PITH_HASH_MODALITY_IMAGE, PITH_OK,
    pith_hash_content_hash, pith_hash_describe, pith_hash_detect, pith_hash_free, pith_hash_match,
    pith_hash_signature,
};
use pith_hash::{Signature, content_hash, signature};

/// A committed conformance fixture by name.
fn fixture(name: &str) -> Vec<u8> {
    fs::read(format!(
        "{}/tests/fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    ))
    .expect("fixture")
}

/// The 48x40 RGB PNG, the suite's smallest image fixture with a pinned
/// hash.
fn png48() -> Vec<u8> {
    fixture("phash_rgb8_48x40.png")
}

/// A real fixture through `detect`, `signature` (with the handed
/// buffer freed) and `describe`: statuses OK, documented headers,
/// roundtrip through the raw pointers.
#[test]
fn ffi_image_detect_signature_describe_roundtrip() {
    let png = png48();

    let mut format: u32 = 0;
    let mut modality: u32 = 0;
    let mut pending: u32 = 1;
    let status = unsafe {
        pith_hash_detect(
            png.as_ptr(),
            png.len(),
            &mut format,
            &mut modality,
            &mut pending,
        )
    };
    assert_eq!(status, PITH_OK);
    assert_eq!(format, PITH_HASH_FORMAT_PNG);
    assert_eq!(modality, PITH_HASH_MODALITY_IMAGE);
    assert_eq!(pending, 0);

    let mut out: *mut u8 = core::ptr::null_mut();
    let mut out_len: usize = 0;
    let status = unsafe { pith_hash_signature(png.as_ptr(), png.len(), &mut out, &mut out_len) };
    assert_eq!(status, PITH_OK);
    // Image stream: tag 0 + big-endian pHash.
    assert_eq!(out_len, 9);
    let stream = unsafe { core::slice::from_raw_parts(out, out_len) };
    assert_eq!(stream[0], 0);
    let phash = u64::from_be_bytes(stream[1..9].try_into().expect("phash"));
    let Signature::Image(expected_phash) = signature(&png).expect("signs") else {
        panic!("image signature")
    };
    assert_eq!(phash, expected_phash);
    unsafe { pith_hash_free(out, out_len) };

    let status = unsafe { pith_hash_describe(png.as_ptr(), png.len(), &mut out, &mut out_len) };
    assert_eq!(status, PITH_OK);
    let stream = unsafe { core::slice::from_raw_parts(out, out_len) };
    // format code, modality code, 32-byte tier 1, 9-byte signature
    // stream, 16-byte image facts.
    assert_eq!(out_len, 2 + 32 + 9 + 16);
    assert_eq!(stream[0], PITH_HASH_FORMAT_PNG as u8);
    assert_eq!(stream[1], PITH_HASH_MODALITY_IMAGE as u8);
    unsafe { pith_hash_free(out, out_len) };

    // A null buffer is a legal free.
    unsafe { pith_hash_free(core::ptr::null_mut(), 0) };
}

/// Match slots for two modalities: image self-match (hamming 0) and a
/// text pair through the raw-pointer interface.
#[test]
fn ffi_match_slots_for_two_modalities() {
    let png = png48();

    let mut tag: u32 = 0;
    let mut slots = [0u64; 4];
    let mut matched: u32 = 0;
    let status = unsafe {
        pith_hash_match(
            png.as_ptr(),
            png.len(),
            png.as_ptr(),
            png.len(),
            &mut tag,
            slots.as_mut_ptr(),
            slots.len(),
            &mut matched,
        )
    };
    assert_eq!(status, PITH_OK);
    assert_eq!(tag, PITH_HASH_MATCH_IMAGE);
    assert_eq!(slots[0], 0);
    assert_eq!(matched, 1);

    let text = b"just some words here for the text lane";
    let status = unsafe {
        pith_hash_match(
            text.as_ptr(),
            text.len(),
            text.as_ptr(),
            text.len(),
            &mut tag,
            slots.as_mut_ptr(),
            slots.len(),
            &mut matched,
        )
    };
    assert_eq!(status, PITH_OK);
    assert_eq!(tag, PITH_HASH_MATCH_TEXT);
    assert_eq!(slots[0], 1.0f64.to_bits());
    assert_eq!(matched, 1);
}

/// The remaining match lanes through the same interface: audio
/// (vote/offset slots), binary (jaccard bits) and video (score +
/// minhash bits).
#[test]
fn ffi_match_slots_for_audio_binary_video() {
    let wav = fixture("tone.wav");
    let blob: Vec<u8> = {
        // The 48 KiB pseudo-file recipe (SplitMix64, one byte per draw).
        let mut out = Vec::with_capacity(48 * 1024);
        let mut state: u64 = 0xD15E_5EED;
        for _ in 0..48 * 1024 {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            out.push((z ^ (z >> 31)) as u8);
        }
        out
    };
    let mp4 = fixture("a_64x48.mp4");

    let mut tag: u32 = 0;
    let mut slots = [0u64; 4];
    let mut matched: u32 = 0;
    let status = unsafe {
        pith_hash_match(
            wav.as_ptr(),
            wav.len(),
            wav.as_ptr(),
            wav.len(),
            &mut tag,
            slots.as_mut_ptr(),
            slots.len(),
            &mut matched,
        )
    };
    assert_eq!(status, PITH_OK);
    assert_eq!(tag, pith_hash::ffi::PITH_HASH_MATCH_AUDIO);
    assert_eq!(matched, 1);
    let outcome = {
        let a = signature(&wav).expect("sig");
        let b = signature(&wav).expect("sig");
        pith_hash::match_(&a, &b).expect("match")
    };
    let pith_hash::MatchOutcome::Audio {
        best: outcome_best,
        matched: outcome_matched,
    } = outcome
    else {
        panic!("audio outcome")
    };
    assert!(outcome_matched);
    // vote/offset slots mirror the facade outcome exactly.
    match outcome_best {
        Some(m) => {
            assert_eq!(slots[0], u64::from(m.votes));
            assert_eq!(slots[1], m.delta_t as u64);
        }
        None => {
            assert_eq!(slots[0], 0);
            assert_eq!(slots[1], 0);
        }
    }

    let status = unsafe {
        pith_hash_match(
            blob.as_ptr(),
            blob.len(),
            blob.as_ptr(),
            blob.len(),
            &mut tag,
            slots.as_mut_ptr(),
            slots.len(),
            &mut matched,
        )
    };
    assert_eq!(status, PITH_OK);
    assert_eq!(tag, pith_hash::ffi::PITH_HASH_MATCH_BINARY);
    assert_eq!(slots[0], 1.0f64.to_bits());
    assert_eq!(matched, 1);

    let status = unsafe {
        pith_hash_match(
            mp4.as_ptr(),
            mp4.len(),
            mp4.as_ptr(),
            mp4.len(),
            &mut tag,
            slots.as_mut_ptr(),
            slots.len(),
            &mut matched,
        )
    };
    assert_eq!(status, PITH_OK);
    assert_eq!(tag, pith_hash::ffi::PITH_HASH_MATCH_VIDEO);
    assert_eq!(matched, 1);
    assert_ne!(slots[0], 0);
}

/// A cross-modality pair is refused with nothing written.
#[test]
fn ffi_match_cross_modality_is_rejected_without_writes() {
    let png = png48();
    let text = b"just some words here for the text lane";

    let mut tag: u32 = 7;
    let mut slots = [42u64; 4];
    let mut matched: u32 = 7;
    let status = unsafe {
        pith_hash_match(
            png.as_ptr(),
            png.len(),
            text.as_ptr(),
            text.len(),
            &mut tag,
            slots.as_mut_ptr(),
            slots.len(),
            &mut matched,
        )
    };
    assert_eq!(status, PITH_E_REJECTED);
    assert_eq!(tag, 7);
    assert_eq!(slots, [42; 4]);
    assert_eq!(matched, 7);
}

/// The tier-1 digest is exactly 32 bytes through the fixed-capacity
/// out-buffer.
#[test]
fn ffi_content_hash_writes_32_bytes() {
    let png = png48();
    let mut buf = [0u8; 64];
    let mut out_len: usize = 0;
    let status = unsafe {
        pith_hash_content_hash(png.as_ptr(), png.len(), buf.as_mut_ptr(), 64, &mut out_len)
    };
    assert_eq!(status, PITH_OK);
    assert_eq!(out_len, 32);
    let expected = content_hash(&png).expect("hashes");
    assert_eq!(&buf[..32], expected.as_bytes());
    // Bytes past the reported length stay untouched.
    assert_eq!(&buf[32..], &[0; 32]);
}

/// Caller bugs are `PITH_E_INVALID`: null pointers and a capacity too
/// small for the fixed wire shape.
#[test]
fn ffi_rejects_caller_bugs() {
    let png = png48();

    let mut format: u32 = 0;
    let mut modality: u32 = 0;
    let mut pending: u32 = 0;
    let status = unsafe {
        pith_hash_detect(
            core::ptr::null(),
            0,
            &mut format,
            &mut modality,
            &mut pending,
        )
    };
    assert_eq!(status, PITH_E_INVALID);
    let status = unsafe {
        pith_hash_detect(
            png.as_ptr(),
            png.len(),
            core::ptr::null_mut(),
            &mut modality,
            &mut pending,
        )
    };
    assert_eq!(status, PITH_E_INVALID);

    let mut out: *mut u8 = core::ptr::null_mut();
    let mut out_len: usize = 0;
    let status = unsafe { pith_hash_signature(core::ptr::null(), 0, &mut out, &mut out_len) };
    assert_eq!(status, PITH_E_INVALID);
    let status = unsafe {
        pith_hash_signature(png.as_ptr(), png.len(), core::ptr::null_mut(), &mut out_len)
    };
    assert_eq!(status, PITH_E_INVALID);
    let status =
        unsafe { pith_hash_describe(png.as_ptr(), png.len(), core::ptr::null_mut(), &mut out_len) };
    assert_eq!(status, PITH_E_INVALID);

    let mut buf = [0u8; 8];
    let status = unsafe {
        pith_hash_content_hash(png.as_ptr(), png.len(), buf.as_mut_ptr(), 8, &mut out_len)
    };
    assert_eq!(status, PITH_E_INVALID);
    let status =
        unsafe { pith_hash_content_hash(core::ptr::null(), 0, buf.as_mut_ptr(), 64, &mut out_len) };
    assert_eq!(status, PITH_E_INVALID);

    let mut tag: u32 = 0;
    let mut slots = [0u64; 4];
    let mut matched: u32 = 0;
    let status = unsafe {
        pith_hash_match(
            core::ptr::null(),
            0,
            png.as_ptr(),
            png.len(),
            &mut tag,
            slots.as_mut_ptr(),
            slots.len(),
            &mut matched,
        )
    };
    assert_eq!(status, PITH_E_INVALID);
    let status = unsafe {
        pith_hash_match(
            png.as_ptr(),
            png.len(),
            png.as_ptr(),
            png.len(),
            &mut tag,
            slots.as_mut_ptr(),
            3,
            &mut matched,
        )
    };
    assert_eq!(status, PITH_E_INVALID);
}

/// Core refusals are `PITH_E_REJECTED` — the whole `Error` surface,
/// every lane — and nothing panics.
#[test]
fn ffi_rejects_core_refusals() {
    let mut out: *mut u8 = core::ptr::null_mut();
    let mut out_len: usize = 0;

    // Decode { modality: image }: a PNG header over garbage.
    let corrupt_png: Vec<u8> = [0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]
        .into_iter()
        .chain(b"garbage".iter().copied())
        .collect();
    let status = unsafe {
        pith_hash_signature(
            corrupt_png.as_ptr(),
            corrupt_png.len(),
            &mut out,
            &mut out_len,
        )
    };
    assert_eq!(status, PITH_E_REJECTED);
    let status = unsafe {
        pith_hash_describe(
            corrupt_png.as_ptr(),
            corrupt_png.len(),
            &mut out,
            &mut out_len,
        )
    };
    assert_eq!(status, PITH_E_REJECTED);
    let mut buf = [0u8; 32];
    let status = unsafe {
        pith_hash_content_hash(
            corrupt_png.as_ptr(),
            corrupt_png.len(),
            buf.as_mut_ptr(),
            32,
            &mut out_len,
        )
    };
    assert_eq!(status, PITH_E_REJECTED);

    // Audio(pith_audio::Error): a structurally valid WAV whose rate the
    // audio pipeline refuses (anything ≠ 44100 Hz).
    let mut bad_wav = Vec::new();
    bad_wav.extend_from_slice(b"RIFF");
    bad_wav.extend_from_slice(&40u32.to_le_bytes());
    bad_wav.extend_from_slice(b"WAVE");
    bad_wav.extend_from_slice(b"fmt ");
    bad_wav.extend_from_slice(&16u32.to_le_bytes());
    bad_wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    bad_wav.extend_from_slice(&1u16.to_le_bytes()); // mono
    bad_wav.extend_from_slice(&8000u32.to_le_bytes()); // wrong rate
    bad_wav.extend_from_slice(&16000u32.to_le_bytes());
    bad_wav.extend_from_slice(&2u16.to_le_bytes());
    bad_wav.extend_from_slice(&16u16.to_le_bytes());
    bad_wav.extend_from_slice(b"data");
    bad_wav.extend_from_slice(&4u32.to_le_bytes());
    bad_wav.extend_from_slice(&[0, 0, 0, 0]);
    let status =
        unsafe { pith_hash_signature(bad_wav.as_ptr(), bad_wav.len(), &mut out, &mut out_len) };
    assert_eq!(status, PITH_E_REJECTED);

    // Pdf(pith_pdf::Error): a PDF header over garbage.
    let corrupt_pdf: Vec<u8> = b"%PDF-1.4 garbage not a pdf".to_vec();
    let status = unsafe {
        pith_hash_signature(
            corrupt_pdf.as_ptr(),
            corrupt_pdf.len(),
            &mut out,
            &mut out_len,
        )
    };
    assert_eq!(status, PITH_E_REJECTED);

    // The non-AVC mp4: a well-formed container whose codec the video
    // lane refuses.
    let mp4v = fixture("e_mp4v.mp4");
    let status = unsafe { pith_hash_signature(mp4v.as_ptr(), mp4v.len(), &mut out, &mut out_len) };
    assert_eq!(status, PITH_E_REJECTED);
    let mut format: u32 = 0;
    let mut modality: u32 = 0;
    let mut pending: u32 = 0;
    let status = unsafe {
        pith_hash_detect(
            mp4v.as_ptr(),
            mp4v.len(),
            &mut format,
            &mut modality,
            &mut pending,
        )
    };
    assert_eq!(status, PITH_OK);
    assert_eq!(format, PITH_HASH_FORMAT_MP4);
}
