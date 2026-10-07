//! The C ABI surface of `pith-hash`: the entry points the Python
//! (ctypes), Node (koffi) and Go (cgo) SDKs bind through.
//!
//! The suite's FFI convention, defined by this module and mirrored by
//! every `pith-*` cdylib:
//!
//! * one flat set of `#[unsafe(no_mangle)] pub unsafe extern "C"`
//!   functions — raw pointers plus lengths, no structs across the
//!   boundary;
//! * every function returns a status code (see the constants below),
//!   never a `Result`, never a panic: a `panic = "abort"` cdylib must
//!   not be reachable from a foreign caller;
//! * an operation either hands ownership to the caller (and ships a
//!   matching `_free` — [`pith_hash_free`] here) or writes into
//!   caller-provided out-parameters — [`pith_hash_detect`],
//!   [`pith_hash_match`] and [`pith_hash_content_hash`] allocate
//!   nothing on the caller's behalf;
//! * the `unsafe` allowance is confined to this module; every core
//!   module stays unsafe-free behind the crate-root `#![deny]`.
//!
//! Wire codes follow declaration order — the same rule every suite
//! cdylib uses:
//!
//! * modality: [`PITH_HASH_MODALITY_IMAGE`] … [`PITH_HASH_MODALITY_VIDEO`];
//! * format: [`PITH_HASH_FORMAT_PNG`] … [`PITH_HASH_FORMAT_UNKNOWN`]
//!   (the `pith_digest::Format` declaration order; `as_str()` values
//!   in that order: `png`, `jpeg`, `bmp`, `zip`, `mp4`, `mp3`, `wav`,
//!   `flac`, `pdf`, `gif`, `unknown`);
//! * match tag: `0` image, `1` audio, `2` text, `3` binary, `4` video.
//!
//! The match outcome rides out as a fixed four-slot `u64` array
//! (struct-as-slots, the pith-image precedent): `out_tag` names the
//! variant, `out_slots[0..n]` carries its fields, `out_matched` is
//! `0`/`1`:
//!
//! | tag | n | slots |
//! |-----|---|-------|
//! | 0 image  | 1 | `s0` hamming distance |
//! | 1 audio  | 2 | `s0` votes · `s1` delta_t (the `i64` two's-complement bit pattern) |
//! | 2 text   | 1 | `s0` Jaccard estimate (IEEE-754 bits) |
//! | 3 binary | 1 | `s0` Jaccard (IEEE-754 bits) |
//! | 4 video  | 2 | `s0` score bits · `s1` minhash Jaccard bits |
//!
//! An audio outcome with no shared peak slot (`best: None`) reports
//! `s0 = 0`, `s1 = 0` with `out_matched = 0`.
//!
//! The byte streams [`pith_hash_signature`] and [`pith_hash_describe`]
//! hand out are the canonical serializations of
//! [`crate::reference`] — the same layouts the `reference.json`
//! sub-digests are recorded over.

#![allow(unsafe_code)]

use crate::reference::{describe_stream, format_code, modality_code, signature_stream};
use crate::{Error, MatchOutcome};

/// Status: success.
pub const PITH_OK: i32 = 0;
/// Status: a caller argument is invalid — a null pointer or a capacity
/// too small for the fixed wire shape.
pub const PITH_E_INVALID: i32 = -1;
/// Status: the core pipeline refused the input — a decode failure in
/// any modality, a pending-lane refusal, a PDF/audio-layer rejection,
/// or a cross-modality `match` (`Error` is `#[non_exhaustive]`; every
/// variant, named or future, is an input rejection at this boundary).
pub const PITH_E_REJECTED: i32 = -2;

/// Format code for `Format::Png` (`"png"`).
pub const PITH_HASH_FORMAT_PNG: u32 = 0;
/// Format code for `Format::Jpeg` (`"jpeg"`).
pub const PITH_HASH_FORMAT_JPEG: u32 = 1;
/// Format code for `Format::Bmp` (`"bmp"`).
pub const PITH_HASH_FORMAT_BMP: u32 = 2;
/// Format code for `Format::Zip` (`"zip"`).
pub const PITH_HASH_FORMAT_ZIP: u32 = 3;
/// Format code for `Format::Mp4` (`"mp4"`).
pub const PITH_HASH_FORMAT_MP4: u32 = 4;
/// Format code for `Format::Mp3` (`"mp3"`).
pub const PITH_HASH_FORMAT_MP3: u32 = 5;
/// Format code for `Format::Wav` (`"wav"`).
pub const PITH_HASH_FORMAT_WAV: u32 = 6;
/// Format code for `Format::Flac` (`"flac"`).
pub const PITH_HASH_FORMAT_FLAC: u32 = 7;
/// Format code for `Format::Pdf` (`"pdf"`).
pub const PITH_HASH_FORMAT_PDF: u32 = 8;
/// Format code for `Format::Gif` (`"gif"`).
pub const PITH_HASH_FORMAT_GIF: u32 = 9;
/// Format code for `Format::Unknown` (`"unknown"` — bare text and
/// binary inputs).
pub const PITH_HASH_FORMAT_UNKNOWN: u32 = 10;

/// Modality code for `Modality::Image`.
pub const PITH_HASH_MODALITY_IMAGE: u32 = 0;
/// Modality code for `Modality::Audio`.
pub const PITH_HASH_MODALITY_AUDIO: u32 = 1;
/// Modality code for `Modality::Text`.
pub const PITH_HASH_MODALITY_TEXT: u32 = 2;
/// Modality code for `Modality::Binary`.
pub const PITH_HASH_MODALITY_BINARY: u32 = 3;
/// Modality code for `Modality::Video`.
pub const PITH_HASH_MODALITY_VIDEO: u32 = 4;

/// Match tag: image (slots: hamming).
pub const PITH_HASH_MATCH_IMAGE: u32 = 0;
/// Match tag: audio (slots: votes, delta_t).
pub const PITH_HASH_MATCH_AUDIO: u32 = 1;
/// Match tag: text (slots: Jaccard bits).
pub const PITH_HASH_MATCH_TEXT: u32 = 2;
/// Match tag: binary (slots: Jaccard bits).
pub const PITH_HASH_MATCH_BINARY: u32 = 3;
/// Match tag: video (slots: score bits, minhash Jaccard bits).
pub const PITH_HASH_MATCH_VIDEO: u32 = 4;

/// The slot count every `pith_hash_match` caller must provide room
/// for — the largest outcome (audio, video) uses two, the protocol
/// reserves four.
pub const PITH_HASH_MATCH_SLOTS: usize = 4;

/// Maps a facade error onto the flat status code: every variant is an
/// input rejection at this boundary (`-2`); nothing here is a caller
/// bug.
fn status_of(err: &Error) -> i32 {
    match err {
        Error::Decode { .. }
        | Error::Unsupported { .. }
        | Error::Pdf(_)
        | Error::Audio(_)
        | Error::BadValue(_) => PITH_E_REJECTED,
        // `Error` is `#[non_exhaustive]`: downstream crates can see new
        // variants at any time, and this boundary refuses them all. The
        // arm is unreachable inside the defining crate (which sees
        // every variant), kept so the status can never silently change
        // meaning when one is added.
        #[allow(unreachable_patterns)]
        _ => PITH_E_REJECTED,
    }
}

/// Hands a freshly built stream to the caller: writes the boxed-slice
/// pointer through `out`, its length through `out_len`.
fn emit(stream: alloc::vec::Vec<u8>, out: *mut *mut u8, out_len: *mut usize) -> i32 {
    let len = stream.len();
    // Hand the exact-length buffer to the caller; `pith_hash_free`
    // reconstructs the boxed slice from the same length.
    let ptr = alloc::boxed::Box::into_raw(stream.into_boxed_slice());
    // Safety: the caller contracted `out` and `out_len` to be writable
    // (checked by the exported wrapper before calling here).
    unsafe {
        *out = ptr.cast::<u8>();
        *out_len = len;
    }
    PITH_OK
}

/// Sniffs `data` and reports the verdict without decoding: the format
/// code, the modality code and the pending flag (`0`/`1`) through the
/// three out-params. Infallible for readable input — only null
/// pointers are [`PITH_E_INVALID`].
///
/// # Safety
///
/// `data` must point to `len` readable bytes; the three out-params to
/// one writable `u32` each, valid for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_hash_detect(
    data: *const u8,
    len: usize,
    out_format: *mut u32,
    out_modality: *mut u32,
    out_pending: *mut u32,
) -> i32 {
    if data.is_null() || out_format.is_null() || out_modality.is_null() || out_pending.is_null() {
        return PITH_E_INVALID;
    }
    // Safety: the caller contracted `len` readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    let det = crate::detect(bytes);
    // Safety: null-checked above.
    unsafe {
        *out_format = u32::from(format_code(det.format));
        *out_modality = u32::from(modality_code(det.modality));
        *out_pending = u32::from(det.pending);
    }
    PITH_OK
}

/// Computes the tier-2 signature of `data` and hands the canonical
/// signature stream (see [`crate::reference`]) to the caller: on
/// [`PITH_OK`] the buffer address goes through `out`, its length
/// through `out_len`, and the caller owns it until
/// [`pith_hash_free`].
///
/// # Safety
///
/// `data` must point to `len` readable bytes; `out` to one writable
/// pointer; `out_len` to one writable `usize`. All must stay valid for
/// the duration of the call; the function retains nothing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_hash_signature(
    data: *const u8,
    len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if data.is_null() || out.is_null() || out_len.is_null() {
        return PITH_E_INVALID;
    }
    // Safety: the caller contracted `len` readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    match signature_bytes(bytes) {
        Ok(stream) => emit(stream, out, out_len),
        Err(status) => status,
    }
}

/// Computes both tiers of `data` and hands the canonical describe
/// stream (format code, modality code, tier-1 digest, signature
/// stream, facts block — see [`crate::reference`]) to the caller,
/// with the same ownership contract as [`pith_hash_signature`].
///
/// # Safety
///
/// `data` must point to `len` readable bytes; `out` to one writable
/// pointer; `out_len` to one writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_hash_describe(
    data: *const u8,
    len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if data.is_null() || out.is_null() || out_len.is_null() {
        return PITH_E_INVALID;
    }
    // Safety: the caller contracted `len` readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    match describe_bytes(bytes) {
        Ok(stream) => emit(stream, out, out_len),
        Err(status) => status,
    }
}

/// Computes both tier-2 signatures from the raw inputs and reports the
/// [`crate::match_`] outcome as slots (see the module-doc table): the
/// outcome tag through `out_tag`, the fields through the first slots
/// of `out_slots`, and `0`/`1` through `out_matched`. Nothing is
/// written on a non-`PITH_OK` return — a cross-modality pair is
/// [`PITH_E_REJECTED`] with all three out-params untouched.
///
/// `slots_cap` below [`PITH_HASH_MATCH_SLOTS`] is [`PITH_E_INVALID`].
///
/// # Safety
///
/// `a` must point to `a_len` readable bytes and `b` to `b_len` readable
/// bytes; `out_tag`/`out_matched` to one writable `u32` each;
/// `out_slots` to `slots_cap` writable `u64`s. All must stay valid for
/// the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_hash_match(
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
    out_tag: *mut u32,
    out_slots: *mut u64,
    slots_cap: usize,
    out_matched: *mut u32,
) -> i32 {
    if a.is_null()
        || b.is_null()
        || out_tag.is_null()
        || out_slots.is_null()
        || out_matched.is_null()
    {
        return PITH_E_INVALID;
    }
    if slots_cap < PITH_HASH_MATCH_SLOTS {
        return PITH_E_INVALID;
    }
    // Safety: the caller contracted `a_len`/`b_len` readable bytes.
    let (left, right) = unsafe {
        (
            core::slice::from_raw_parts(a, a_len),
            core::slice::from_raw_parts(b, b_len),
        )
    };
    match match_slots(left, right) {
        Ok((tag, slots, matched)) => {
            // Safety: null-checked above, capacity checked above.
            unsafe {
                *out_tag = tag;
                core::ptr::copy_nonoverlapping(slots.as_ptr(), out_slots, slots.len());
                *out_matched = matched;
            }
            PITH_OK
        }
        Err(status) => status,
    }
}

/// Computes the tier-1 content hash of `data` and writes the 32-byte
/// digest into `out`, reporting the written length through `out_len`.
/// `out_cap` below 32 is [`PITH_E_INVALID`].
///
/// # Safety
///
/// `data` must point to `len` readable bytes; `out` to `out_cap`
/// writable bytes; `out_len` to one writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_hash_content_hash(
    data: *const u8,
    len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if data.is_null() || out.is_null() || out_len.is_null() {
        return PITH_E_INVALID;
    }
    if out_cap < 32 {
        return PITH_E_INVALID;
    }
    // Safety: the caller contracted `len` readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(data, len) };
    match crate::content_hash(bytes) {
        Ok(digest) => {
            // Safety: null-checked above, capacity checked above.
            unsafe {
                core::ptr::copy_nonoverlapping(digest.as_bytes().as_ptr(), out, 32);
                *out_len = 32;
            }
            PITH_OK
        }
        Err(err) => status_of(&err),
    }
}

/// Releases a buffer handed out by [`pith_hash_signature`] or
/// [`pith_hash_describe`].
///
/// # Safety
///
/// `ptr` must be a pointer returned by one of those functions with the
/// `out_len` value that came back with it, and must not have been
/// released (or otherwise freed) before. Null is accepted and ignored,
/// so callers can free unconditionally on the error path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pith_hash_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // Safety: the caller contracts a live boxed slice of exactly `len`
    // bytes handed out by this module.
    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
    drop(unsafe { alloc::boxed::Box::from_raw(slice) });
}

/// The safe core of [`pith_hash_signature`]: sign, then serialize.
/// Every facade refusal maps to [`PITH_E_REJECTED`].
fn signature_bytes(bytes: &[u8]) -> Result<alloc::vec::Vec<u8>, i32> {
    let sig = crate::signature(bytes).map_err(|err| status_of(&err))?;
    Ok(signature_stream(&sig))
}

/// The safe core of [`pith_hash_describe`]: describe, then serialize.
fn describe_bytes(bytes: &[u8]) -> Result<alloc::vec::Vec<u8>, i32> {
    let desc = crate::describe(bytes).map_err(|err| status_of(&err))?;
    Ok(describe_stream(&desc))
}

/// The safe core of [`pith_hash_match`]: sign both inputs, match, and
/// flatten the outcome to `(tag, slots, matched)`.
fn match_slots(a: &[u8], b: &[u8]) -> Result<(u32, [u64; PITH_HASH_MATCH_SLOTS], u32), i32> {
    let left = crate::signature(a).map_err(|err| status_of(&err))?;
    let right = crate::signature(b).map_err(|err| status_of(&err))?;
    let outcome = crate::match_(&left, &right).map_err(|err| status_of(&err))?;
    let matched = u32::from(matched_flag(&outcome));
    Ok((tag_of(&outcome), slots_of(&outcome), matched))
}

/// The match-outcome wire tag.
fn tag_of(outcome: &MatchOutcome) -> u32 {
    match outcome {
        MatchOutcome::Image { .. } => PITH_HASH_MATCH_IMAGE,
        MatchOutcome::Audio { .. } => PITH_HASH_MATCH_AUDIO,
        MatchOutcome::Text { .. } => PITH_HASH_MATCH_TEXT,
        MatchOutcome::Binary { .. } => PITH_HASH_MATCH_BINARY,
        MatchOutcome::Video { .. } => PITH_HASH_MATCH_VIDEO,
    }
}

/// The advisory verdict as `0`/`1`.
fn matched_flag(outcome: &MatchOutcome) -> bool {
    match outcome {
        MatchOutcome::Image { matched, .. }
        | MatchOutcome::Audio { matched, .. }
        | MatchOutcome::Text { matched, .. }
        | MatchOutcome::Binary { matched, .. }
        | MatchOutcome::Video { matched, .. } => *matched,
    }
}

/// The outcome's fields, slot-flattened per the module-doc table.
fn slots_of(outcome: &MatchOutcome) -> [u64; PITH_HASH_MATCH_SLOTS] {
    match outcome {
        MatchOutcome::Image { hamming, .. } => [u64::from(*hamming), 0, 0, 0],
        MatchOutcome::Audio { best, .. } => match best {
            Some(m) => [u64::from(m.votes), m.delta_t as u64, 0, 0],
            // No shared slot: zero votes, zero offset.
            None => [0, 0, 0, 0],
        },
        MatchOutcome::Text { jaccard, .. } | MatchOutcome::Binary { jaccard, .. } => {
            [jaccard.to_bits(), 0, 0, 0]
        }
        MatchOutcome::Video {
            score,
            minhash_jaccard,
            ..
        } => [score.to_bits(), minhash_jaccard.to_bits(), 0, 0],
    }
}
