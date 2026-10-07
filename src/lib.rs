//! The suite facade: canonical hash, tier 1, tier 2, match and describe.
//!
//! Part of the `pith-hash` zero-dependency hashing suite: the curator
//! consumes only the suite's own `pith-*` crates.
//!
//! This crate is the top of the suite DAG. It does not
//! implement hashing itself — it *wires* the modality crates behind one
//! surface, per the suite design (`docs/algorithms/kit.md` upstream):
//!
//! - [`detect`] sniffs the container and names the [`Format`] +
//!   [`Modality`] pair (or routes to text/binary heuristics);
//! - [`content_hash`] is **tier 1**: SHA-256 over the normalized content
//!   (decoded pixels / downmixed PCM / canonical text / raw bytes);
//! - [`signature`] is **tier 2**: the modality's perceptual or
//!   content-defined signature — image pHash, spectral-peak audio
//!   signature, 128-word MinHash for text, FastCDC chunk digests for
//!   binary;
//! - [`match_`] scores two signatures of the same modality;
//! - [`describe`] returns both tiers plus modality facts in one call.
//!
//! Every modality slot is wired: mp4 video lands through
//! `pith-video` (mp4 demux → h264 decode → 2 fps frame pHash chain →
//! MinHash, spec §4.2).
//!
//! `no_std` + `alloc`, like its siblings; the fuzz harness is the crate's
//! only `std` consumer (`src/bin/fuzz.rs`).
//!
//! The similarity indexes (BK-tree, banded LSH) and threshold
//! calibration live in the in-repo [`index`] module.

#![cfg_attr(not(feature = "std"), no_std)]
// `unsafe` is denied everywhere except `ffi` (the C ABI surface the
// language SDKs bind through) and `ffi_jni` (the JNI surface the Java
// SDK binds through): raw pointers exist only at those boundaries, and
// every exported function is a documented `unsafe extern "C"` fn.
#![deny(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod error;
mod phash;

// The C ABI surface compiles only into the normal rlib/cdylib — never
// into the `--cfg test` harness build. The test-harness and normal
// flavors of this crate are separate instrumented codegen units, and
// two same-named `no_mangle` exports with different function hashes
// make the coverage merger keep the zero-count copy (the exports are
// exercised through `tests/ffi.rs`, which links the normal flavor —
// the same flavor the cdylib is built from).
#[cfg(not(test))]
pub mod ffi;
// The JNI surface compiles only into the normal flavor for the same
// reason as `ffi` (same-named `no_mangle` exports across flavors);
// its fake-JNIEnv scenarios run through `tests/ffi_jni.rs`, which
// links the normal flavor.
#[cfg(not(test))]
#[doc(hidden)]
pub mod ffi_jni;
pub mod index;
pub mod reference;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub use error::Error;
pub use index::{BkTree, Calibration, Candidate, LshIndex, Profile, calibrate};
pub use pith_audio::{
    Index as AudioIndex, Match as AudioMatch, Peak, Signature as AudioSignature,
    build_index as build_audio_index, match_signature as match_audio_signature,
};
pub use pith_digest::{Algorithm, Digest, Format};
pub use pith_image::raster::{Image, Rgb};
pub use pith_text::{SIGNATURE_WORDS, canonicalize};
pub use pith_video::{VideoFingerprint, VideoMatch};

/// Facade result alias.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Advisory `matched` floor for audio `votes` — one shared slot is
/// coincidence, not a match (kit.md §6).
const AUDIO_VOTE_FLOOR: u32 = 8;
/// Advisory `matched` bound for image Hamming distance (kit.md §3).
const IMAGE_HAMMING_MAX: u32 = 10;
/// Advisory `matched` bound for text MinHash Jaccard estimate.
const TEXT_JACCARD_MIN: f64 = 0.8;
/// Advisory `matched` bound for video frame-match fraction (§4.2) —
/// the value `pith_video::MATCH_SCORE_MIN` pins.
const VIDEO_SCORE_MIN: f64 = pith_video::MATCH_SCORE_MIN;
/// Advisory `matched` bound for binary chunk-set Jaccard.
const BINARY_JACCARD_MIN: f64 = 0.5;

/// The content modality a signature belongs to — the name every error
/// and report carries.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Modality {
    /// Decoded raster images (png, jpeg, bmp).
    Image,
    /// Decoded PCM audio (wav, flac, mp3).
    Audio,
    /// Canonicalized UTF-8 text (bare text and pdf-extracted text).
    Text,
    /// Opaque bytes (zip, unknown, and every non-UTF-8 input).
    Binary,
    /// Video (mp4/mov ISO-BMFF containers carrying H.264).
    Video,
}

impl Modality {
    /// The stable wire form, e.g. `"image"`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Modality::Image => "image",
            Modality::Audio => "audio",
            Modality::Text => "text",
            Modality::Binary => "binary",
            Modality::Video => "video",
        }
    }
}

impl fmt::Display for Modality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What [`detect`] found: the container format plus the modality the
/// signature pipeline will treat it as.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    /// The sniffed container (`Format::Unknown` for bare text/binary).
    pub format: Format,
    /// The modality lane that handles it.
    pub modality: Modality,
    /// `true` when the slot is named but its crate has not landed —
    /// every tier call on this input answers [`Error::Unsupported`].
    pub pending: bool,
}

/// Sniffs `bytes` for a known container magic, falling back to UTF-8
/// text detection and finally `Binary`.
///
/// Rule (kit.md §1): a format whose crate exists in the DAG table but
/// has not landed is `pending`; a format outside the table entirely is
/// `Binary`. Detection never decodes — `describe`/`signature` surface
/// codec errors after this says what the bytes claim to be.
#[must_use]
pub fn detect(bytes: &[u8]) -> Detection {
    let d = |format: Format, modality: Modality, pending: bool| Detection {
        format,
        modality,
        pending,
    };
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return d(Format::Png, Modality::Image, false);
    }
    if bytes.starts_with(b"\xff\xd8\xff") {
        return d(Format::Jpeg, Modality::Image, false);
    }
    if bytes.starts_with(b"BM") {
        return d(Format::Bmp, Modality::Image, false);
    }
    if bytes.starts_with(b"GIF8") {
        return d(Format::Gif, Modality::Binary, false);
    }
    if bytes.starts_with(b"RIFF") && bytes.len() >= 12 && &bytes[8..12] == b"WAVE" {
        return d(Format::Wav, Modality::Audio, false);
    }
    if bytes.starts_with(b"fLaC") {
        return d(Format::Flac, Modality::Audio, false);
    }
    if is_mp3_magic(bytes) {
        return d(Format::Mp3, Modality::Audio, false);
    }
    if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" {
        return d(Format::Mp4, Modality::Video, false);
    }
    if bytes.starts_with(b"%PDF-") {
        return d(Format::Pdf, Modality::Text, false);
    }
    if bytes.starts_with(b"PK") {
        return d(Format::Zip, Modality::Binary, false);
    }
    if core::str::from_utf8(bytes).is_ok() {
        return d(Format::Unknown, Modality::Text, false);
    }
    d(Format::Unknown, Modality::Binary, false)
}

/// MPEG audio sniff: `ID3` tag header, or an MPEG audio frame sync —
/// `0xFF` + three set top bits, version bits not `01` (reserved), layer
/// bits not `00` (reserved). The JPEG magics are claimed by an earlier
/// rule; the UTF-16LE BOM `FF FE` is claimed by the rule below instead.
fn is_mp3_magic(b: &[u8]) -> bool {
    if b.starts_with(b"ID3") {
        return true;
    }
    b.len() >= 2
        && b[0] == 0xFF
        && b[1] != 0xFE
        && b[1] != 0xFF
        && (b[1] & 0xE0) == 0xE0
        && (b[1] & 0x18) != 0x08
        && (b[1] & 0x06) != 0x00
}

/// The unsupported answer for a pending slot, with the lane named.
/// Every slot in the DAG table has landed, so this is reachable only if
/// a `Detection.pending` flag is ever left stale — kept so a stale flag
/// still fails with a descriptive string, not a blank.
fn pending_err(format: Format, modality: Modality) -> Error {
    let what = match (format, modality) {
        // These slots are all implemented; each arm is dead code kept
        // so a stale `pending` flag fails descriptively, not blankly.
        (Format::Mp3, _) => "pith-mp3 pending flag left stale (bug)",
        (Format::Mp4, _) | (_, Modality::Video) => "pith-video pending flag left stale (bug)",
        (Format::Pdf, _) => "pith-pdf pending flag left stale (bug)",
        _ => "modality lane has not landed",
    };
    Error::Unsupported {
        modality,
        format,
        what,
    }
}

// ---------------------------------------------------------------------
// Decoding to normalized content
// ---------------------------------------------------------------------

/// A codec rejection with the modality attached — the one shape every
/// `pith_digest::Error` arrives through.
fn decode_err(modality: Modality, source: pith_digest::Error) -> Error {
    Error::Decode { modality, source }
}

/// `v >> 8` 16→8 sample reduction (PNG's sanctioned drop-the-low-byte
/// rule, kit.md §2); the identity for `u8`.
#[inline]
fn sample_u8<T: pith_image::raster::Sample>(v: T) -> u8 {
    if T::MAX_U64 == 255 {
        v.to_u64() as u8
    } else {
        (v.to_u64() >> 8) as u8
    }
}

/// Canonicalizes any decoded image to `Image<Rgb, u8>`: gray replicates,
/// alpha drops, `u16` halves by `>> 8`.
fn image_to_rgb8<L: pith_image::raster::Layout, T: pith_image::raster::Sample>(
    img: &Image<L, T>,
) -> Result<Image<Rgb, u8>> {
    let c = L::CHANNELS;
    let n = img.width() as usize * img.height() as usize;
    let src = img.as_slice();
    if src.len() != n * c {
        // Unreachable through Image's own invariants; named anyway so a
        // broken invariant is an error, not a panic.
        return Err(decode_err(
            Modality::Image,
            pith_digest::Error::BadValue("decoded image buffer malformed"),
        ));
    }
    let mut px = Vec::with_capacity(n * 3);
    for i in 0..n {
        let p = &src[i * c..i * c + c];
        match c {
            1 => {
                let g = sample_u8(p[0]);
                px.extend_from_slice(&[g, g, g]);
            }
            _ => px.extend_from_slice(&[sample_u8(p[0]), sample_u8(p[1]), sample_u8(p[2])]),
        }
    }
    Image::from_vec(img.width(), img.height(), px).map_err(|e| decode_err(Modality::Image, e))
}

/// The BT.601 luma plane of a canonical `Image<Rgb, u8>` — the input
/// the tier-3 features (FAST-9 / rBRIEF) are defined over.
fn rgb8_to_gray(img: &Image<Rgb, u8>) -> Result<Image<pith_image::raster::Gray, u8>> {
    let n = img.width() as usize * img.height() as usize;
    let src = img.as_slice();
    if src.len() != n * 3 {
        return Err(decode_err(
            Modality::Image,
            pith_digest::Error::BadValue("decoded image buffer malformed"),
        ));
    }
    let mut px = Vec::with_capacity(n);
    for p in src.chunks_exact(3) {
        px.push(pith_image::raster::luma_bt601(p[0], p[1], p[2]));
    }
    Image::from_vec(img.width(), img.height(), px).map_err(|e| decode_err(Modality::Image, e))
}

/// Decodes an image container to canonical `Image<Rgb, u8>` (kit.md §2).
fn decode_image_rgb8(bytes: &[u8], format: Format) -> Result<Image<Rgb, u8>> {
    let err = |e: pith_digest::Error| decode_err(Modality::Image, e);
    match format {
        Format::Png => {
            let png = pith_png::decode(bytes, &pith_png::Limits::default()).map_err(err)?;
            match png.pixels() {
                pith_png::Pixels::Gray8(i) => image_to_rgb8(i),
                pith_png::Pixels::Rgb8(i) => image_to_rgb8(i),
                pith_png::Pixels::Rgba8(i) => image_to_rgb8(i),
                pith_png::Pixels::Gray16(i) => image_to_rgb8(i),
                pith_png::Pixels::Rgb16(i) => image_to_rgb8(i),
                pith_png::Pixels::Rgba16(i) => image_to_rgb8(i),
            }
        }
        Format::Jpeg => match pith_jpeg::decode(bytes).map_err(err)? {
            pith_jpeg::Jpeg::Gray(i) => image_to_rgb8(&i),
            pith_jpeg::Jpeg::Rgb(i) => image_to_rgb8(&i),
        },
        Format::Bmp => image_to_rgb8(&pith_image::bmp::decode(bytes).map_err(err)?),
        other => Err(Error::BadValue(match other {
            Format::Gif => "gif is not a decodable image lane",
            _ => "not an image container",
        })),
    }
}

/// Decoded audio: the decoder's canonical interleaved `i32` stream plus
/// the facts tier 1 frames into the digest and `describe` reports.
struct Pcm {
    /// Interleaved `i32` samples (`frame * channels + channel`).
    samples: Vec<i32>,
    /// Channel count of the stream.
    channels: u16,
    /// Samples per second.
    rate: u32,
}

fn decode_audio(bytes: &[u8], format: Format) -> Result<Pcm> {
    let err = |e: pith_digest::Error| decode_err(Modality::Audio, e);
    match format {
        Format::Wav => {
            let w = pith_audio::wav::decode(bytes).map_err(err)?;
            Ok(Pcm {
                samples: w.samples().to_vec(),
                channels: w.channels(),
                rate: w.sample_rate(),
            })
        }
        Format::Flac => {
            let f = pith_flac::decode(bytes, &pith_flac::Limits::default()).map_err(err)?;
            Ok(Pcm {
                samples: f.samples().to_vec(),
                channels: f.channels(),
                rate: f.sample_rate(),
            })
        }
        Format::Mp3 => {
            // pith-mp3 landed after this facade's spec was written;
            // it decodes to the same canonical interleaved i32 PCM.
            let m = pith_mp3::decode(bytes, &pith_mp3::Limits::default()).map_err(err)?;
            Ok(Pcm {
                samples: m.samples,
                channels: m.channels,
                rate: m.sample_rate,
            })
        }
        _ => Err(Error::BadValue("not an audio container")),
    }
}

// ---------------------------------------------------------------------
// Tier 1
// ---------------------------------------------------------------------

/// Downmixes interleaved `i32` PCM to mono: `(Σ_c s[i·ch+c]) / ch` in
/// `i64`, truncated toward zero — the convention
/// `pith_audio::signature` uses, so tier 1 and tier 2 read the same
/// mono signal.
fn to_mono(pcm: &Pcm) -> Result<Vec<i32>> {
    let ch = usize::from(pcm.channels);
    if ch == 0 {
        return Err(decode_err(
            Modality::Audio,
            pith_digest::Error::BadValue("audio channel count is zero"),
        ));
    }
    if pcm.samples.len() % ch != 0 {
        return Err(decode_err(
            Modality::Audio,
            pith_digest::Error::BadValue("audio samples are not a whole number of frames"),
        ));
    }
    Ok(pcm
        .samples
        .chunks_exact(ch)
        .map(|f| (f.iter().map(|&s| i64::from(s)).sum::<i64>() / ch as i64) as i32)
        .collect())
}

/// The tier-1 canonical hash: SHA-256 over the *normalized content*,
/// not the container (kit.md §2 pins the exact input bytes per
/// modality).
///
/// - image → `R G B` `u8` triples in raster order (alpha dropped, `u16`
///   halved by `>> 8`);
/// - audio → `u32_le rate ∥ u64_le mono_frames ∥ i32_le mono PCM`
///   (rate pinned in the header so the same PCM at different rates
///   hashes differently);
/// - text → UTF-8 of `canonicalize()` (NFC + lowercase + one `\n`);
/// - video → the decoded-frame digest chain: `w ∥ h ∥ n ∥` per-frame
///   `sha256(y ∥ cb ∥ cr)` in presentation order
///   ([`pith_video::VideoFingerprint::content_digest`]);
/// - binary → the raw bytes.
///
/// # Errors
///
/// [`Error::Decode`] naming the modality when the container is claimed
/// but corrupt, never a panic.
pub fn content_hash(bytes: &[u8]) -> Result<Digest<32>> {
    let det = detect(bytes);
    if det.pending {
        return Err(pending_err(det.format, det.modality));
    }
    let payload: Vec<u8> = match det.modality {
        Modality::Image => decode_image_rgb8(bytes, det.format)?.into_vec(),
        Modality::Audio => {
            let pcm = decode_audio(bytes, det.format)?;
            let mono = to_mono(&pcm)?;
            let mut buf = Vec::with_capacity(12 + mono.len() * 4);
            buf.extend_from_slice(&pcm.rate.to_le_bytes());
            buf.extend_from_slice(&(mono.len() as u64).to_le_bytes());
            for s in mono {
                buf.extend_from_slice(&s.to_le_bytes());
            }
            buf
        }
        Modality::Text => {
            let text = text_content(bytes, det.format)?;
            match core::str::from_utf8(text.as_ref()) {
                Ok(s) => canonicalize(s).into_bytes(),
                // Pdf extraction is UTF-8 by construction; an impossible
                // state still answers with an error rather than silently
                // hashing bytes.
                Err(_) => {
                    return Err(Error::BadValue("text input failed UTF-8 recheck"));
                }
            }
        }
        Modality::Binary => bytes.to_vec(),
        // Tier-1 for video is the decoded-frame digest chain the video
        // crate computes while fingerprinting — same decode, one pass.
        Modality::Video => {
            return Ok(pith_video::decode(bytes, &pith_video::Limits::default())
                .map_err(|e| decode_err(det.modality, e))?
                .content_digest);
        }
    };
    pith_digest::sha256(&payload).map_err(|e| decode_err(det.modality, e))
}

/// The text a modality pipelines over: the raw UTF-8 bytes for bare
/// text, PDF-extracted text for a PDF container. The extraction itself
/// lives in [`pith_file::text_content`] (the suite's file slice); this
/// wrapper only re-shapes its error into the facade's.
///
/// `alloc::borrow::Cow` keeps the bare-text path allocation-free while
/// letting pdf hand back an owned `String`.
fn text_content(bytes: &[u8], format: Format) -> Result<alloc::borrow::Cow<'_, [u8]>> {
    match format {
        Format::Pdf => pith_file::text_content(bytes, format).map_err(|e| match e {
            pith_file::Error::Pdf(pe) => Error::Pdf(pe),
            pith_file::Error::Decode { source } => decode_err(Modality::Text, source),
            // `pith_file::Error` is `#[non_exhaustive]`; the two named
            // arms are its entire shape today, and anything new must be
            // routed explicitly rather than silently folded.
            _ => Error::BadValue("file slice answered on the wrong lane"),
        }),
        _ => Ok(alloc::borrow::Cow::Borrowed(bytes)),
    }
}

// ---------------------------------------------------------------------
// Tier 2 signatures
// ---------------------------------------------------------------------

/// A modality's tier-2 signature — the comparable fingerprint.
///
/// The variant *is* the modality; `match_` refuses to compare across
/// variants because no distance between a pHash and a MinHash vector is
/// defined.
#[derive(Clone, Debug, PartialEq)]
pub enum Signature {
    /// 64-bit perceptual hash (kit.md §3). Compare with
    /// [`pith_digest::hamming`].
    Image(u64),
    /// Spectral-peak landmark signature (kit.md §6). Compare with
    /// [`build_audio_index`] + [`match_audio_signature`], or
    /// [`match_`] for the pairwise form.
    Audio(AudioSignature),
    /// 128-word MinHash signature (kit.md §4). Compare with
    /// [`pith_text::jaccard_estimate`].
    Text(Vec<u64>),
    /// FastCDC chunk-digest set (kit.md §5) — the suite's file slice
    /// owns the type ([`pith_file::BinarySignature`]). Compare with
    /// [`pith_file::BinarySignature::jaccard`].
    Binary(pith_file::BinarySignature),
    /// Video fingerprint: ordered frame-pHash chain + MinHash over its
    /// shingles (spec §4.2). Compare with [`match_`] or
    /// `pith_video::video_match`.
    Video(VideoFingerprint),
}

impl Signature {
    /// The modality this signature belongs to.
    #[must_use]
    pub fn modality(&self) -> Modality {
        match self {
            Signature::Image(_) => Modality::Image,
            Signature::Audio(_) => Modality::Audio,
            Signature::Text(_) => Modality::Text,
            Signature::Binary(_) => Modality::Binary,
            Signature::Video(_) => Modality::Video,
        }
    }
}

/// Computes the tier-2 signature of `bytes`, routing on [`detect`].
///
/// Pending slots answer [`Error::Unsupported`] naming the modality —
/// every slot in the DAG table has landed, so today no lane is pending.
/// Non-UTF-8, non-container input is `Binary`; valid UTF-8 without a
/// container magic is `Text`; a PDF contributes its extracted text to
/// the `Text` lane; mp4/mov enters the video lane.
///
/// # Errors
///
/// [`Error::Decode`] naming the modality on corrupt containers,
/// [`Error::Audio`] for the audio pipeline's own errors (a WAV at the
/// wrong sample rate is `Unsupported` inside it — named, not silent),
/// [`Error::Pdf`] when the PDF text layer rejects the document.
pub fn signature(bytes: &[u8]) -> Result<Signature> {
    let det = detect(bytes);
    if det.pending {
        return Err(pending_err(det.format, det.modality));
    }
    match det.modality {
        Modality::Image => {
            let img = decode_image_rgb8(bytes, det.format)?;
            phash::image_phash(&img).map(Signature::Image)
        }
        Modality::Audio => audio_signature(&decode_audio(bytes, det.format)?).map(Signature::Audio),
        Modality::Text => {
            let text = text_content(bytes, det.format)?;
            match core::str::from_utf8(text.as_ref()) {
                Ok(s) => Ok(Signature::Text(pith_text::signature(s))),
                Err(_) => binary_signature(text.as_ref()).map(Signature::Binary),
            }
        }
        Modality::Binary => binary_signature(bytes).map(Signature::Binary),
        Modality::Video => pith_video::decode(bytes, &pith_video::Limits::default())
            .map_err(|e| decode_err(det.modality, e))
            .map(Signature::Video),
    }
}

/// The binary tier-2 signature: FastCDC chunks hashed with SHA-256
/// into a unique-digest set. The implementation lives in the suite's
/// file slice ([`pith_file::binary_signature`]); this wrapper routes
/// its refusal into the facade error with the modality named.
///
/// # Errors
///
/// [`Error::Decode`] in the `binary` modality if the chunker rejects
/// the (fixed, spec-pinned) parameters — unreachable in practice.
pub fn binary_signature(bytes: &[u8]) -> Result<pith_file::BinarySignature> {
    let source = match pith_file::binary_signature(bytes) {
        Ok(sig) => return Ok(sig),
        Err(pith_file::Error::Decode { source }) => source,
        // The Pdf arm exists only on the text-extraction path, which
        // the chunker never takes; named rather than unreachable so a
        // file-slice change surfaces as an error, not a panic.
        // `pith_file::Error` is `#[non_exhaustive]`; the Pdf arm exists
        // only on the text-extraction path, which the chunker never
        // takes. Named rather than `unreachable!` so a file-slice
        // change surfaces as an error, not a panic.
        Err(_) => pith_digest::Error::Unsupported("file slice answered on the wrong lane"),
    };
    Err(decode_err(Modality::Binary, source))
}

/// The audio tier-2 signature over already-decoded PCM: mono-mixed
/// exactly like tier 1, gated to [`pith_audio::SAMPLE_RATE`] (the
/// constants are tuned to 44 100 Hz and silently resampling is nobody's
/// friend). Wrong rate is `Error::Audio(Unsupported(..))` — the same
/// refusal `pith_audio::signature_of_wav` gives, named.
fn audio_signature(pcm: &Pcm) -> Result<AudioSignature> {
    if pcm.rate != pith_audio::SAMPLE_RATE {
        return Err(Error::Audio(pith_audio::Error::Unsupported(
            "audio sample rate ≠ 44100 Hz",
        )));
    }
    let mono = to_mono(pcm)?;
    Ok(pith_audio::signature(&mono, 1)?)
}

/// The text tier-2 signature of an already-string input: MinHash over
/// the canonical form's word-3 shingles.
#[must_use]
pub fn text_signature(text: &str) -> Signature {
    Signature::Text(pith_text::signature(text))
}

/// The image tier-2 hash of an already-decoded image — the public
/// entry point of [`phash::image_phash`] (kit.md §3).
///
/// # Errors
///
/// [`Error::Decode`] naming `image` on a malformed buffer (impossible
/// for a well-formed [`Image`], which always has exact dimensions).
pub fn image_phash<L: pith_image::raster::Layout, T: pith_image::raster::Sample>(
    img: &Image<L, T>,
) -> Result<u64> {
    phash::image_phash(img)
}

// ---------------------------------------------------------------------
// describe / match
// ---------------------------------------------------------------------

/// Modality-specific facts a [`Description`] surfaces.
#[derive(Clone, Debug, PartialEq)]
pub enum Facts {
    /// Decoded image geometry plus the tier-3 feature count.
    Image {
        /// Width in pixels.
        width: u32,
        /// Height in pixels.
        height: u32,
        /// FAST-9 keypoints found on the luma plane — the tier-3
        /// feature pool rBRIEF describes (spec §4.3).
        keypoints: usize,
    },
    /// Decoded stream parameters.
    Audio {
        /// Samples per second.
        sample_rate: u32,
        /// Channels in the file.
        channels: u16,
        /// Analysis frames the signature covered.
        frames: u32,
        /// Landmark peaks in the signature.
        peaks: usize,
    },
    /// Text statistics over the canonical form.
    Text {
        /// Words the shingles were drawn from.
        words: usize,
        /// Byte length of the canonical UTF-8 form.
        canonical_len: usize,
    },
    /// Raw-byte statistics.
    Binary {
        /// Input length in bytes.
        len: usize,
        /// Distinct FastCDC chunks.
        chunks: usize,
    },
    /// Decoded video facts (spec §4.2).
    Video {
        /// Displayed width in pixels.
        width: u32,
        /// Displayed height in pixels.
        height: u32,
        /// Track duration in seconds.
        duration_s: f64,
        /// Frames the 2 fps sampler kept.
        frames_sampled: usize,
    },
}

/// Everything the suite reports about one input: format, modality, the
/// tier-1 digest and the tier-2 signature, plus modality facts. The
/// `signature` field is the value `match_` consumes — `describe` never
/// reports a different number than `signature()` computes.
#[derive(Clone, Debug, PartialEq)]
pub struct Description {
    /// Sniffed container format.
    pub format: Format,
    /// The modality lane that answered.
    pub modality: Modality,
    /// Tier 1: SHA-256 of the normalized content.
    pub tier1: Digest<32>,
    /// Tier 2: the modality signature.
    pub signature: Signature,
    /// Modality facts (dimensions, rate, counts).
    pub facts: Facts,
}

impl fmt::Display for Description {
    /// One line per field group — modality and both tiers identified by
    /// name, per kit.md §7.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "modality: {}\nformat: {}\ntier1: {}\n",
            self.modality, self.format, self.tier1
        )?;
        match (&self.signature, &self.facts) {
            (
                Signature::Image(p),
                Facts::Image {
                    width,
                    height,
                    keypoints,
                },
            ) => write!(
                f,
                "tier2: phash {p:#018x}\ntier3: orb keypoints={keypoints}\nimage: {width}x{height}px"
            ),
            (
                Signature::Audio(_),
                Facts::Audio {
                    sample_rate,
                    channels,
                    frames,
                    peaks,
                },
            ) => write!(
                f,
                "tier2: audio peaks={peaks} frames={frames}\naudio: {sample_rate} Hz, {channels} ch"
            ),
            (
                Signature::Text(sig),
                Facts::Text {
                    words,
                    canonical_len,
                },
            ) => {
                let head: Vec<String> = sig
                    .iter()
                    .take(4)
                    .map(|w| alloc::format!("{w:016x}"))
                    .collect();
                write!(
                    f,
                    "tier2: minhash {} words ({}..)\ntext: {words} words, canonical {canonical_len} B",
                    sig.len(),
                    head.join(" ")
                )
            }
            (Signature::Binary(b), Facts::Binary { len, .. }) => write!(
                f,
                "tier2: fastcdc {} unique chunks\nbinary: {len} B",
                b.len()
            ),
            (
                Signature::Video(v),
                Facts::Video {
                    width,
                    height,
                    duration_s,
                    frames_sampled,
                },
            ) => write!(
                f,
                "tier2: video {frames_sampled} sampled frames, minhash {} words\nvideo: {width}x{height}px, {duration_s:.3} s",
                v.minhash.len()
            ),
            // Constructible only from inside the crate; today's code
            // never pairs them, and a future arm must still not panic.
            _ => f.write_str("tier2: <inconsistent facts>"),
        }
    }
}

/// Detects, decodes, and computes both tiers of `bytes`.
///
/// # Errors
///
/// The first refusal wins: [`Error::Unsupported`] on a pending slot,
/// [`Error::Decode`] / [`Error::Audio`] on corrupt input. Garbage in is
/// a named `Err`, never a panic.
pub fn describe(bytes: &[u8]) -> Result<Description> {
    let det = detect(bytes);
    if det.pending {
        return Err(pending_err(det.format, det.modality));
    }
    let tier1 = content_hash(bytes)?;
    match det.modality {
        Modality::Image => {
            let img = decode_image_rgb8(bytes, det.format)?;
            let p = phash::image_phash(&img)?;
            let gray = rgb8_to_gray(&img)?;
            let keypoints = pith_image::tier3::orb::fast9(&gray).len();
            Ok(Description {
                format: det.format,
                modality: Modality::Image,
                tier1,
                signature: Signature::Image(p),
                facts: Facts::Image {
                    width: img.width(),
                    height: img.height(),
                    keypoints,
                },
            })
        }
        Modality::Audio => {
            let pcm = decode_audio(bytes, det.format)?;
            let sig = audio_signature(&pcm)?;
            Ok(Description {
                format: det.format,
                modality: Modality::Audio,
                tier1,
                signature: Signature::Audio(sig.clone()),
                facts: Facts::Audio {
                    sample_rate: pcm.rate,
                    channels: pcm.channels,
                    frames: sig.frames(),
                    peaks: sig.peaks().len(),
                },
            })
        }
        Modality::Text => {
            let sig = signature(bytes)?;
            let text = text_content(bytes, det.format)?;
            let (words, canonical_len) = match core::str::from_utf8(text.as_ref()) {
                Ok(s) => {
                    let canon = canonicalize(s);
                    (canon.split_whitespace().count(), canon.len())
                }
                Err(_) => (0, text.len()),
            };
            Ok(Description {
                format: det.format,
                modality: Modality::Text,
                tier1,
                signature: sig,
                facts: Facts::Text {
                    words,
                    canonical_len,
                },
            })
        }
        Modality::Binary => {
            let sig = signature(bytes)?;
            let chunks = match &sig {
                Signature::Binary(b) => b.len(),
                _ => 0,
            };
            Ok(Description {
                format: det.format,
                modality: Modality::Binary,
                tier1,
                signature: sig,
                facts: Facts::Binary {
                    len: bytes.len(),
                    chunks,
                },
            })
        }
        Modality::Video => {
            let sig = signature(bytes)?;
            let Signature::Video(v) = &sig else {
                unreachable!("video modality yields a video signature")
            };
            let facts = Facts::Video {
                width: v.width,
                height: v.height,
                duration_s: v.duration,
                frames_sampled: v.frame_hashes.len(),
            };
            Ok(Description {
                format: det.format,
                modality: Modality::Video,
                tier1,
                signature: sig,
                facts,
            })
        }
    }
}

/// The outcome of comparing two same-modality signatures.
#[derive(Clone, Debug, PartialEq)]
pub enum MatchOutcome {
    /// Image: Hamming distance between the two pHashes.
    Image {
        /// `hamming(a, b)` on the 64-bit hashes, `0..=64`.
        hamming: u32,
        /// Advisory verdict: `hamming <= 10` (kit.md §3).
        matched: bool,
    },
    /// Audio: the top hit of the left signature against an index over
    /// the right one (empty when nothing shares a peak slot).
    Audio {
        /// The best [`AudioMatch`], or `None` for no shared slots.
        best: Option<AudioMatch>,
        /// Advisory verdict: `votes >= 8` (kit.md §6).
        matched: bool,
    },
    /// Text: MinHash Jaccard estimate of the two shingle sets.
    Text {
        /// `pith_text::jaccard_estimate`, `0.0..=1.0`.
        jaccard: f64,
        /// Advisory verdict: `jaccard >= 0.8`.
        matched: bool,
    },
    /// Binary: exact Jaccard over the FastCDC chunk-digest sets.
    Binary {
        /// `|A∩B| / |A∪B|`, `0.0..=1.0` (`1.0` for two empty sets).
        jaccard: f64,
        /// Advisory verdict: `jaccard >= 0.5`.
        matched: bool,
    },
    /// Video: fraction of temporally aligned sampled frames within the
    /// pHash bound, plus the MinHash Jaccard of the two shingle sets.
    Video {
        /// `pith_video::match_score`, `0.0..=1.0`.
        score: f64,
        /// `pith_text::jaccard_estimate` over the frame-chain
        /// MinHash signatures, `0.0..=1.0`.
        minhash_jaccard: f64,
        /// Advisory verdict: `score >= 0.8` (spec §4.2 bound).
        matched: bool,
    },
}

/// Compares two tier-2 signatures of the same modality.
///
/// Named `match_` because `match` is a keyword; this is the spec's
/// `match()`. Modality mismatch is [`Error::BadValue`], not a zero
/// score — an incomparable pair has no defined distance.
///
/// # Errors
///
/// [`Error::BadValue`] when `a.modality() != b.modality()`.
pub fn match_(a: &Signature, b: &Signature) -> Result<MatchOutcome> {
    match (a, b) {
        (Signature::Image(x), Signature::Image(y)) => {
            let hamming = pith_digest::hamming(
                &Digest::from_bytes(x.to_be_bytes()),
                &Digest::from_bytes(y.to_be_bytes()),
            );
            Ok(MatchOutcome::Image {
                hamming,
                matched: hamming <= IMAGE_HAMMING_MAX,
            })
        }
        (Signature::Audio(x), Signature::Audio(y)) => {
            let index = build_audio_index(core::slice::from_ref(y));
            let best = match_audio_signature(x, &index).into_iter().next();
            Ok(MatchOutcome::Audio {
                matched: best.is_some_and(|m| m.votes >= AUDIO_VOTE_FLOOR),
                best,
            })
        }
        (Signature::Text(x), Signature::Text(y)) => {
            let j = pith_text::jaccard_estimate(x, y);
            Ok(MatchOutcome::Text {
                jaccard: j,
                matched: j >= TEXT_JACCARD_MIN,
            })
        }
        (Signature::Binary(x), Signature::Binary(y)) => {
            let j = x.jaccard(y);
            Ok(MatchOutcome::Binary {
                jaccard: j,
                matched: j >= BINARY_JACCARD_MIN,
            })
        }
        (Signature::Video(x), Signature::Video(y)) => {
            let m = pith_video::video_match(x, y);
            Ok(MatchOutcome::Video {
                score: m.score,
                minhash_jaccard: m.minhash_jaccard,
                matched: m.score >= VIDEO_SCORE_MIN,
            })
        }
        _ => Err(Error::BadValue("match_ across different modalities")),
    }
}

#[cfg(test)]
mod internal_tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Minimal mono 16-bit 44.1 kHz WAV with a 440 Hz sine, for a real
    /// `Signature::Audio` without the CLI fixture module.
    fn tone_wav() -> Vec<u8> {
        let seconds = 1;
        let n = 44_100 * seconds;
        let mut pcm = Vec::with_capacity(n * 2);
        for i in 0..n {
            let s = (2.0 * core::f64::consts::PI * 440.0 * i as f64 / 44_100.0).sin();
            let v = (s * 12_000.0) as i16;
            pcm.extend_from_slice(&v.to_le_bytes());
        }
        let mut w = Vec::new();
        w.extend_from_slice(b"RIFF");
        w.extend_from_slice(&((36 + pcm.len()) as u32).to_le_bytes());
        w.extend_from_slice(b"WAVEfmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&44_100u32.to_le_bytes());
        w.extend_from_slice(&88_200u32.to_le_bytes());
        w.extend_from_slice(&2u16.to_le_bytes());
        w.extend_from_slice(&16u16.to_le_bytes());
        w.extend_from_slice(b"data");
        w.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
        w.extend_from_slice(&pcm);
        w
    }

    /// The pending answer names every landed slot descriptively —
    /// reachable only via a stale `pending` flag, but each arm must
    /// still say which lane went stale.
    #[test]
    fn pending_err_names_every_landed_slot() {
        for (fmt, m, want) in [
            (
                Format::Mp3,
                Modality::Audio,
                "pith-mp3 pending flag left stale (bug)",
            ),
            (
                Format::Mp4,
                Modality::Video,
                "pith-video pending flag left stale (bug)",
            ),
            (
                Format::Pdf,
                Modality::Text,
                "pith-pdf pending flag left stale (bug)",
            ),
            (
                Format::Zip,
                Modality::Binary,
                "modality lane has not landed",
            ),
        ] {
            let e = pending_err(fmt, m);
            let Error::Unsupported { what, .. } = &e else {
                panic!("want Unsupported, got {e:?}")
            };
            assert_eq!(what, &want);
            assert!(e.to_string().contains(want));
        }
    }

    /// The image decoder refuses non-image containers with the lane's
    /// own message, gif by name.
    #[test]
    fn decode_image_refuses_non_image_containers() {
        let e = decode_image_rgb8(b"GIF89a", Format::Gif).expect_err("gif refused");
        assert!(
            e.to_string().contains("gif is not a decodable image lane"),
            "{e}"
        );
        let e = decode_image_rgb8(b"RIFF", Format::Wav).expect_err("wav refused");
        assert!(e.to_string().contains("not an image container"), "{e}");
    }

    /// The mono downmix refuses a zero channel count and a partial
    /// trailing frame with named errors.
    #[test]
    fn to_mono_refuses_impossible_pcm() {
        let e = to_mono(&Pcm {
            samples: vec![],
            channels: 0,
            rate: 44_100,
        })
        .expect_err("zero channels");
        assert!(e.to_string().contains("audio channel count is zero"), "{e}");
        let e = to_mono(&Pcm {
            samples: vec![1, 2, 3],
            channels: 2,
            rate: 44_100,
        })
        .expect_err("partial frame");
        assert!(
            e.to_string()
                .contains("audio samples are not a whole number of frames"),
            "{e}"
        );
        // Stereo downmix truncates toward zero like the audio crate.
        let mono = to_mono(&Pcm {
            samples: vec![1, -2, 3, -4],
            channels: 2,
            rate: 44_100,
        })
        .expect("mono");
        assert_eq!(mono, vec![0, 0]);
    }

    /// `Display` for `Description` spells every modality's facts and
    /// degrades to the inconsistent-facts line instead of panicking.
    #[test]
    fn description_display_covers_every_modality() {
        let tier1 = Digest::<32>::from_bytes([7u8; 32]);
        let mk = |signature, facts| Description {
            format: Format::Png,
            modality: Modality::Image,
            tier1,
            signature,
            facts,
        };
        let image = mk(
            Signature::Image(0xc21b_c25d_1234_5678),
            Facts::Image {
                width: 48,
                height: 40,
                keypoints: 9,
            },
        );
        let text = image.to_string();
        assert!(text.contains("modality: image"), "{text}");
        assert!(text.contains("phash 0xc21bc25d12345678"), "{text}");
        assert!(text.contains("orb keypoints=9"), "{text}");

        let wav = tone_wav();
        let Signature::Audio(audio_sig) = signature(&wav).expect("audio signs") else {
            panic!("wav must sign as audio")
        };
        let (frames, peaks) = (audio_sig.frames(), audio_sig.len());
        let audio = mk(
            Signature::Audio(audio_sig),
            Facts::Audio {
                sample_rate: 44_100,
                channels: 1,
                frames,
                peaks,
            },
        );
        let text = audio.to_string();
        assert!(text.contains("audio: 44100 Hz, 1 ch"), "{text}");
        assert!(text.contains("audio peaks="), "{text}");

        let textual = mk(
            Signature::Text(pith_text::signature("alpha beta gamma")),
            Facts::Text {
                words: 3,
                canonical_len: 16,
            },
        );
        assert!(
            textual.to_string().contains("text: 3 words, canonical"),
            "{textual}"
        );

        let bsig = pith_file::binary_signature(b"0123456789abcdef0123456789abcdef").expect("signs");
        let binary = mk(
            Signature::Binary(bsig),
            Facts::Binary { len: 32, chunks: 3 },
        );
        let text = binary.to_string();
        assert!(text.contains("fastcdc 1 unique chunks"), "{text}");
        assert!(text.contains("binary: 32 B"), "{text}");

        let video = mk(
            Signature::Video(pith_video::VideoFingerprint {
                frame_hashes: vec![1, 2, 3],
                minhash: vec![4; 128],
                duration: 2.0,
                fps_sampled: 2.0,
                width: 64,
                height: 48,
                content_digest: Digest::<32>::from_bytes([9u8; 32]),
            }),
            Facts::Video {
                width: 64,
                height: 48,
                duration_s: 2.0,
                frames_sampled: 3,
            },
        );
        let text = video.to_string();
        assert!(text.contains("video: 64x48px, 2.000 s"), "{text}");
        assert!(
            text.contains("3 sampled frames, minhash 128 words"),
            "{text}"
        );

        // Signature/facts pairs that cannot arise from `describe` still
        // render without panicking.
        let inconsistent = mk(
            Signature::Image(1),
            Facts::Text {
                words: 0,
                canonical_len: 0,
            },
        );
        assert!(
            inconsistent
                .to_string()
                .contains("tier2: <inconsistent facts>")
        );
    }

    /// The facade's `image_phash` entry point agrees with the module
    /// function (the public seam `describe` uses).
    #[test]
    fn facade_image_phash_matches_module_fn() {
        let px: Vec<u8> = (0..32 * 32).map(|i| (i * 11) as u8).collect();
        let img = pith_image::raster::Image::<pith_image::raster::Gray, u8>::from_vec(32, 32, px)
            .expect("from_vec");
        assert_eq!(
            image_phash(&img).expect("facade"),
            phash::image_phash(&img).expect("module")
        );
    }
}
