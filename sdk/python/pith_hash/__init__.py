# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""pith-hash SDK: the suite curator through ctypes.

Detect, tier-1 content hash, tier-2 signatures, match and describe via
the `pith_hash` Rust cdylib. The byte streams the cdylib hands out are
the canonical serializations of the Rust `reference` module — the same
layouts the repository-root `reference.json` records its fnv1a64 /
sha256 sub-digests over — so this wrapper parses them back into plain
Python objects and re-hashes every payload.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "Detection",
    "Signature",
    "Description",
    "MatchResult",
    "FfiError",
    "LibraryNotFoundError",
    "find_cdylib",
    "detect",
    "signature",
    "describe",
    "match_signatures",
    "content_hash",
    "parse_signature",
    "parse_describe",
    "fnv1a64",
    "FORMATS",
    "MODALITIES",
    "MATCH_TAGS",
    "STATUS_OK",
    "STATUS_INVALID",
    "STATUS_REJECTED",
]

#: Status: success.
STATUS_OK = 0
#: Status: a caller argument is invalid (a null pointer, a capacity too
#: small for the fixed wire shape).
STATUS_INVALID = -1
#: Status: the core pipeline refused the input (decode failure in any
#: modality, a pending lane, a PDF/audio-layer rejection, or a
#: cross-modality match).
STATUS_REJECTED = -2

#: Format names by wire code (`pith_digest::Format` declaration order).
FORMATS = ("png", "jpeg", "bmp", "zip", "mp4", "mp3", "wav", "flac", "pdf", "gif", "unknown")

#: Modality names by wire code (declaration order).
MODALITIES = ("image", "audio", "text", "binary", "video")

#: Match-outcome tags by wire code (declaration order).
MATCH_TAGS = ("image", "audio", "text", "binary", "video")

#: Signature-stream tag bytes (declaration order).
SIGNATURE_TAGS = ("image", "audio", "text", "binary", "video")

#: Every cdylib file name cargo may drop into the build directory, per
#: platform (windows / linux / macOS).
CDYLIB_NAMES = ("pith_hash.dll", "libpith_hash.so", "libpith_hash.dylib")


class LibraryNotFoundError(OSError):
    """No cdylib was found through the discovery chain."""


class FfiError(Exception):
    """A non-zero status code came back from the cdylib."""

    def __init__(self, op: str, status: int) -> None:
        kind = {
            STATUS_INVALID: "invalid argument",
            STATUS_REJECTED: "input rejected",
        }.get(status, "unknown failure")
        super().__init__(f"{op} failed: {kind} (status {status})")
        #: The raw status code the FFI returned.
        self.status = status


@dataclass(frozen=True)
class Detection:
    """What `detect` found, re-expressed from the wire codes."""

    #: The sniffed container name (`unknown` for bare text/binary).
    format: str
    #: The modality lane that handles it.
    modality: str
    #: `True` when the lane is named but not served yet.
    pending: bool


@dataclass(frozen=True)
class Signature:
    """A tier-2 signature, re-expressed from the signature stream.

    The `*_count` fields mirror `reference.json`'s semantics: they are
    the *byte length* of the canonical payload the sub-digests cover
    (594 = 99 peaks × 6 B, 1024 = 128 words × 8 B).
    """

    #: The modality tag (`image` … `video`).
    modality: str
    #: Image: the 64-bit perceptual hash.
    phash: int | None = None
    #: Audio: peak payload byte count, analysis frames, `(t, f)` peaks.
    peak_count: int | None = None
    #: Audio: analysis frames the signature covered.
    frames: int | None = None
    #: Audio: parsed `(t, f)` peak pairs.
    peaks: tuple[tuple[int, int], ...] | None = None
    #: Audio: the canonical peaks payload the digests cover.
    peaks_bytes: bytes | None = None
    #: Text/binary/video: payload byte counts.
    word_count: int | None = None
    #: Text: the 128 big-endian-carried MinHash words.
    words: tuple[int, ...] | None = None
    #: Binary: digest payload byte count and the 32-byte digests.
    chunk_count: int | None = None
    #: Binary: the sorted unique chunk digests, concatenated.
    digest_bytes: bytes | None = None
    #: Video: frame payload byte count, geometry, duration IEEE bits.
    frame_count: int | None = None
    #: Video: displayed geometry.
    width: int | None = None
    #: Video: displayed height.
    height: int | None = None
    #: Video: track duration as the raw IEEE-754 bit pattern.
    duration_bits: int | None = None
    #: Video: the frame-pHash chain, little-endian words.
    frame_hashes: tuple[int, ...] | None = None
    #: Video: the MinHash words over the chain's shingles.
    minhash: tuple[int, ...] | None = None


@dataclass(frozen=True)
class Description:
    """Both tiers plus facts, re-expressed from the describe stream."""

    #: The sniffed container name.
    format: str
    #: The modality lane that answered.
    modality: str
    #: Tier 1: hex of the 32-byte content digest.
    tier1: str
    #: Tier 2: the parsed signature stream.
    signature: Signature
    #: Modality facts (dimensions, rate, counts).
    facts: dict


@dataclass(frozen=True)
class MatchResult:
    """A match outcome, re-expressed from the slots."""

    #: The outcome tag (`image` … `video`).
    tag: str
    #: The outcome's fields: `hamming`; `votes, delta_t` (delta_t is
    #: the `i64` two's-complement pattern, sign-extended back);
    #: `jaccard`; `score, minhash_jaccard` (f64 bit patterns).
    slots: tuple[int, ...]
    #: Advisory verdict.
    matched: bool

    def slot_float(self, index: int) -> float:
        """Reinterprets slot `index` as an IEEE-754 double."""
        import struct

        return struct.unpack("<d", struct.pack("<Q", self.slots[index]))[0]


def fnv1a64(data: bytes) -> int:
    """The 64-bit FNV-1a fold the reference sub-digests use."""
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def find_cdylib() -> Path:
    """Locates the cdylib through the suite's discovery chain."""
    explicit = os.environ.get("PITH_CDYLIB")
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return p
    env_dir = os.environ.get("PITH_CDYLIB_DIR")
    candidates: list[Path] = []
    if env_dir:
        env_dir_path = Path(env_dir)
        candidates.append(env_dir_path)
        if not env_dir_path.is_absolute():
            # CD and local runs invoke tools from the repository root or
            # from sdk/<lang>; resolve the env value against both.
            candidates.append(Path.cwd() / env_dir_path)
            candidates.append(Path(__file__).resolve().parents[3] / env_dir_path)
    candidates.append(Path(__file__).resolve().parent)  # packaged wheel
    candidates.append(Path(__file__).resolve().parents[3] / "target" / "release")
    for directory in candidates:
        for name in CDYLIB_NAMES:
            p = directory / name
            if p.is_file():
                return p
    raise LibraryNotFoundError(
        "no pith-hash cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, "
        "the package directory and <repo>/target/release); "
        "run `cargo build --release` first"
    )


_lib: ctypes.CDLL | None = None


def _load() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        lib = ctypes.CDLL(str(find_cdylib()))
        lib.pith_hash_detect.argtypes = [
            ctypes.c_void_p,  # data
            ctypes.c_size_t,  # len
            ctypes.POINTER(ctypes.c_uint32),  # out format
            ctypes.POINTER(ctypes.c_uint32),  # out modality
            ctypes.POINTER(ctypes.c_uint32),  # out pending
        ]
        lib.pith_hash_detect.restype = ctypes.c_int32
        for op in ("pith_hash_signature", "pith_hash_describe"):
            fn = getattr(lib, op)
            fn.argtypes = [
                ctypes.c_void_p,  # data
                ctypes.c_size_t,  # len
                ctypes.POINTER(ctypes.c_void_p),  # out buffer
                ctypes.POINTER(ctypes.c_size_t),  # out length
            ]
            fn.restype = ctypes.c_int32
        lib.pith_hash_match.argtypes = [
            ctypes.c_void_p,  # a
            ctypes.c_size_t,  # a_len
            ctypes.c_void_p,  # b
            ctypes.c_size_t,  # b_len
            ctypes.POINTER(ctypes.c_uint32),  # out tag
            ctypes.POINTER(ctypes.c_uint64),  # out slots
            ctypes.c_size_t,  # slots capacity
            ctypes.POINTER(ctypes.c_uint32),  # out matched
        ]
        lib.pith_hash_match.restype = ctypes.c_int32
        lib.pith_hash_content_hash.argtypes = [
            ctypes.c_void_p,  # data
            ctypes.c_size_t,  # len
            ctypes.POINTER(ctypes.c_ubyte),  # out buffer
            ctypes.c_size_t,  # out capacity
            ctypes.POINTER(ctypes.c_size_t),  # out length
        ]
        lib.pith_hash_content_hash.restype = ctypes.c_int32
        lib.pith_hash_free.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.pith_hash_free.restype = None
        _lib = lib
    return _lib


def _hand_out(status: int, op: str, out: ctypes.c_void_p, out_len: ctypes.c_size_t) -> bytes:
    """Copies a handed-out buffer and frees it (null-safe on error)."""
    if status != STATUS_OK:
        raise FfiError(op, status)
    try:
        return ctypes.string_at(out, out_len.value)
    finally:
        _load().pith_hash_free(out, out_len.value)


def detect(data: bytes) -> Detection:
    """Sniffs `data` without decoding: format, modality, pending."""
    fmt = ctypes.c_uint32()
    mod = ctypes.c_uint32()
    pending = ctypes.c_uint32()
    status = _load().pith_hash_detect(
        data, len(data), ctypes.byref(fmt), ctypes.byref(mod), ctypes.byref(pending)
    )
    if status != STATUS_OK:
        raise FfiError("pith_hash_detect", status)
    return Detection(
        format=FORMATS[fmt.value],
        modality=MODALITIES[mod.value],
        pending=pending.value == 1,
    )


def _stream_op(op: str, data: bytes) -> bytes:
    out = ctypes.c_void_p()
    out_len = ctypes.c_size_t()
    status = getattr(_load(), op)(data, len(data), ctypes.byref(out), ctypes.byref(out_len))
    return _hand_out(status, op, out, out_len)


def signature(data: bytes) -> Signature:
    """Computes the tier-2 signature and parses the signature stream."""
    return parse_signature(_stream_op("pith_hash_signature", data))


def describe(data: bytes) -> Description:
    """Computes both tiers and parses the describe stream."""
    return parse_describe(_stream_op("pith_hash_describe", data))


def match_signatures(a: bytes, b: bytes) -> MatchResult:
    """Scores two raw inputs, slots flattened per the wire table.

    Raises :class:`FfiError` with ``status == STATUS_REJECTED`` for a
    cross-modality pair (nothing is written on that path).
    """
    tag = ctypes.c_uint32()
    slots = (ctypes.c_uint64 * 4)()
    matched = ctypes.c_uint32()
    status = _load().pith_hash_match(
        a,
        len(a),
        b,
        len(b),
        ctypes.byref(tag),
        slots,
        len(slots),
        ctypes.byref(matched),
    )
    if status != STATUS_OK:
        raise FfiError("pith_hash_match", status)
    return MatchResult(
        tag=MATCH_TAGS[tag.value],
        slots=tuple(s for s in slots),
        matched=matched.value == 1,
    )


def content_hash(data: bytes) -> bytes:
    """Computes the 32-byte tier-1 content digest."""
    buf = (ctypes.c_ubyte * 32)()
    out_len = ctypes.c_size_t()
    status = _load().pith_hash_content_hash(
        data, len(data), buf, len(buf), ctypes.byref(out_len)
    )
    if status != STATUS_OK:
        raise FfiError("pith_hash_content_hash", status)
    return bytes(buf[: out_len.value])


def parse_signature(raw: bytes) -> Signature:
    """Re-expresses the canonical signature stream as a :class:`Signature`."""
    if len(raw) < 1:
        raise ValueError("signature stream is empty")
    tag = raw[0]
    if tag >= len(SIGNATURE_TAGS):
        raise ValueError(f"unknown signature tag {tag}")
    modality = SIGNATURE_TAGS[tag]
    if modality == "image":
        if len(raw) != 9:
            raise ValueError("image stream is not tag + u64")
        return Signature(modality=modality, phash=int.from_bytes(raw[1:9], "big"))
    if modality == "audio":
        if len(raw) < 13:
            raise ValueError("audio stream is shorter than its 13-byte header")
        peak_count = int.from_bytes(raw[1:9], "big")
        frames = int.from_bytes(raw[9:13], "big")
        payload = raw[13:]
        if peak_count != len(payload) or len(payload) % 6 != 0:
            raise ValueError("audio peak count disagrees with the payload")
        peaks = tuple(
            (
                int.from_bytes(payload[i : i + 4], "little"),
                int.from_bytes(payload[i + 4 : i + 6], "little"),
            )
            for i in range(0, len(payload), 6)
        )
        return Signature(
            modality=modality,
            peak_count=peak_count,
            frames=frames,
            peaks=peaks,
            peaks_bytes=payload,
        )
    if modality == "text":
        if len(raw) < 9:
            raise ValueError("text stream is shorter than its 9-byte header")
        word_count = int.from_bytes(raw[1:9], "big")
        payload = raw[9:]
        if word_count != len(payload) or len(payload) % 8 != 0:
            raise ValueError("text word count disagrees with the payload")
        words = tuple(int.from_bytes(payload[i : i + 8], "big") for i in range(0, len(payload), 8))
        return Signature(modality=modality, word_count=word_count, words=words)
    if modality == "binary":
        if len(raw) < 9:
            raise ValueError("binary stream is shorter than its 9-byte header")
        chunk_count = int.from_bytes(raw[1:9], "big")
        payload = raw[9:]
        if chunk_count != len(payload) or len(payload) % 32 != 0:
            raise ValueError("binary chunk count disagrees with the payload")
        return Signature(modality=modality, chunk_count=chunk_count, digest_bytes=payload)
    # video
    if len(raw) < 18:
        raise ValueError("video stream is shorter than its 18-byte header")
    frame_count = int.from_bytes(raw[1:5], "big")
    width = int.from_bytes(raw[5:9], "big")
    height = int.from_bytes(raw[9:13], "big")
    duration_bits = int.from_bytes(raw[13:21], "big")
    rest = raw[21:]
    if frame_count > len(rest) or frame_count % 8 != 0:
        raise ValueError("video frame count disagrees with the payload")
    frames_payload = rest[:frame_count]
    minhash_payload = rest[frame_count:]
    if len(minhash_payload) % 8 != 0:
        raise ValueError("video minhash payload is not whole words")
    return Signature(
        modality=modality,
        frame_count=frame_count,
        width=width,
        height=height,
        duration_bits=duration_bits,
        frame_hashes=tuple(
            int.from_bytes(frames_payload[i : i + 8], "little")
            for i in range(0, len(frames_payload), 8)
        ),
        minhash=tuple(
            int.from_bytes(minhash_payload[i : i + 8], "little")
            for i in range(0, len(minhash_payload), 8)
        ),
    )


def parse_describe(raw: bytes) -> Description:
    """Re-expresses the canonical describe stream as a :class:`Description`."""
    if len(raw) < 35:
        raise ValueError("describe stream is shorter than its 35-byte header")
    fmt = raw[0]
    mod = raw[1]
    if fmt >= len(FORMATS) or mod >= len(MODALITIES):
        raise ValueError(f"unknown describe codes {fmt}/{mod}")
    tier1 = raw[2:34].hex()
    modality = MODALITIES[mod]
    # The facts block terminates the stream; its size is known from
    # the modality code, so the signature stream is the exact middle
    # slice (a bare parse_signature would see the facts as payload).
    sig_end = len(raw) - _facts_len(modality)
    sig = parse_signature(raw[34:sig_end])
    facts_raw = raw[sig_end:]
    facts: dict = {}
    if modality == "image":
        _need(facts_raw, 16)
        facts = {"width": _be32(facts_raw, 0), "height": _be32(facts_raw, 4), "keypoints": _be64(facts_raw, 8)}
    elif modality == "audio":
        _need(facts_raw, 18)
        facts = {
            "sample_rate": _be32(facts_raw, 0),
            "channels": int.from_bytes(facts_raw[4:6], "big"),
            "frames": _be32(facts_raw, 6),
            "peaks": _be64(facts_raw, 10),
        }
    elif modality == "text":
        _need(facts_raw, 16)
        facts = {"words": _be64(facts_raw, 0), "canonical_len": _be64(facts_raw, 8)}
    elif modality == "binary":
        _need(facts_raw, 16)
        facts = {"len": _be64(facts_raw, 0), "chunks": _be64(facts_raw, 8)}
    else:
        _need(facts_raw, 24)
        facts = {
            "width": _be32(facts_raw, 0),
            "height": _be32(facts_raw, 4),
            "duration_bits": _be64(facts_raw, 8),
            "frames_sampled": _be64(facts_raw, 16),
        }
    return Description(format=FORMATS[fmt], modality=modality, tier1=tier1, signature=sig, facts=facts)


def _be32(raw: bytes, off: int) -> int:
    return int.from_bytes(raw[off : off + 4], "big")


def _be64(raw: bytes, off: int) -> int:
    return int.from_bytes(raw[off : off + 8], "big")


def _need(raw: bytes, n: int) -> None:
    if len(raw) != n:
        raise ValueError(f"facts block is {len(raw)} bytes, want {n}")


def _facts_len(modality: str) -> int:
    """The byte size of each modality's facts block."""
    if modality == "audio":
        return 18
    if modality == "video":
        return 24
    return 16
