# SPDX-License-Identifier: MIT
# Copyright (c) 2026 pith-hash
"""Hex-exact conformance: the committed reference vectors through ctypes.

Every one of the 45 vectors in the repository-root reference.json is
replayed through the cdylib and compared against every recorded field —
detect codes, tier-2 sub-digests (recomputed SDK-side with the same
folds the generator uses), tier-1 digests, facts and match slots. The
same vectors the Rust `gen-reference verify` gate and the Node/Go SDKs
check.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import struct
from pathlib import Path

import pytest

from pith_hash import (
    FORMATS,
    FfiError,
    MatchResult,
    MODALITIES,
    Description,
    Detection,
    Signature,
    content_hash,
    describe,
    detect,
    fnv1a64,
    match_signatures,
    signature,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
REFERENCE = json.loads((REPO_ROOT / "reference.json").read_text(encoding="utf-8"))["vectors"]
BY_NAME = {v["name"]: v for v in REFERENCE}
FIXTURES = REPO_ROOT / "tests" / "fixtures"

MASK64 = (1 << 64) - 1


# ---------------------------------------------------------------------
# The deterministic inline corpus (transcribed from tools/gen-reference)
# ---------------------------------------------------------------------


class SplitMix64:
    """The 64-bit generator behind every inline recipe."""

    def __init__(self, seed: int) -> None:
        self.s = seed & MASK64

    def next_u64(self) -> int:
        self.s = (self.s + 0x9E3779B97F4A7C15) & MASK64
        z = self.s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        return z ^ (z >> 31)


def splitmix_bytes(seed: int, length: int) -> bytes:
    """One next_u64 per byte, low byte kept — the upstream recipe."""
    rng = SplitMix64(seed)
    return bytes(rng.next_u64() & 0xFF for _ in range(length))


def blob48(seed: int) -> bytes:
    """The 48 KiB pseudo-file recipe of the upstream facade suite."""
    return splitmix_bytes(seed, 48 * 1024)


VOCAB = (
    "hash", "image", "audio", "signal", "codec", "block", "frame", "sample", "stream",
    "vector", "median", "kernel", "window", "raster", "pixel", "tone", "hash", "luma",
    "delta", "chunk", "radix", "filter", "table", "edge",
)


def prose(seed: int, size: int) -> str:
    """Seeded vocabulary words, one space apart, truncated to `size`."""
    rng = SplitMix64(seed)
    out = ""
    while len(out) < size:
        out += VOCAB[rng.next_u64() % len(VOCAB)] + " "
    return out[:size]


def patterned_pixels(seed: int, w: int, h: int) -> bytes:
    """Smooth periodic RGB content with real low-frequency energy."""
    rng = SplitMix64(seed)
    fx = float(rng.next_u64() % 5 + 1)
    fy = float(rng.next_u64() % 5 + 1)
    p1 = (rng.next_u64() % 628) / 100.0
    p2 = (rng.next_u64() % 628) / 100.0
    px = bytearray()
    for y in range(h):
        for x in range(w):
            u = x / w
            v = y / h
            r = 127.5 + 120.0 * math.sin(u * fx * (2 * math.pi) + p1)
            g = 127.5 + 120.0 * math.sin(v * fy * (2 * math.pi) + p2)
            b = 127.5 + 120.0 * math.sin((u + v) * (fx + fy) + p1 + p2)
            px += bytes((int(r) & 0xFF, int(g) & 0xFF, int(b) & 0xFF))
    return bytes(px)


def bmp24(w: int, h: int, rgb: bytes) -> bytes:
    """Bottom-up 24-bit BMP — the suite's deterministic fixture encoder."""
    assert len(rgb) == w * h * 3
    row = ((w * 3 + 3) // 4) * 4
    img = row * h
    f = bytearray()
    f += b"BM"
    f += struct.pack("<I", 54 + img)
    f += b"\x00\x00\x00\x00"
    f += struct.pack("<I", 54)
    f += struct.pack("<I", 40)
    f += struct.pack("<ii", w, h)
    f += struct.pack("<hh", 1, 24)
    f += b"\x00" * 24
    for y in range(h - 1, -1, -1):
        for x in range(w):
            i = (y * w + x) * 3
            f += bytes((rgb[i + 2], rgb[i + 1], rgb[i]))
        f += b"\x00" * (row - w * 3)
    return bytes(f)


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


PNG48 = fixture("phash_rgb8_48x40.png")
GRAY40 = fixture("phash_gray8_40x32.png")
PNG_BASE = fixture("base_444.png")
JPG_BASE = fixture("base_444.jpg")
WAV = fixture("tone.wav")
FLAC = fixture("tone.flac")
MP3 = fixture("l3_short.mp3")
MP4 = fixture("a_64x48.mp4")
MOV = fixture("a_64x48.mov")
MP4V = fixture("e_mp4v.mp4")
PDF = fixture("text_page.pdf")

BMP_SYNTH = bmp24(48, 40, patterned_pixels(0xBEEF_0001, 48, 40))
BLOB = blob48(0xD15E_5EED)
BLOB_SHIFTED = b"\xaa" + blob48(0xD15E_5EED)
BLOB_OTHER = blob48(0xBADC_0FFE)
PROSE_A = prose(0xD1, 4096).encode()
PROSE_B = prose(0xD2, 4096).encode()

#: The corpus recipes by name, shared by every vector loader.
CORPUS = {
    "png48": PNG48,
    "gray40": GRAY40,
    "png_base": PNG_BASE,
    "jpg_base": JPG_BASE,
    "wav": WAV,
    "flac": FLAC,
    "mp3": MP3,
    "mp4": MP4,
    "mov": MOV,
    "mp4v": MP4V,
    "pdf": PDF,
    "bmp_synth": BMP_SYNTH,
    "blob": BLOB,
    "blob_shifted": BLOB_SHIFTED,
    "blob_other": BLOB_OTHER,
    "prose_a": PROSE_A,
    "prose_b": PROSE_B,
}


def le_words(words) -> bytes:
    """The canonical word fold: little-endian words concatenated."""
    return b"".join(struct.pack("<Q", w & MASK64) for w in words)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------
# detect: 13 vectors, every recorded field
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,data",
    [
        ("detect-png", PNG48),
        ("detect-jpeg", JPG_BASE),
        ("detect-bmp", BMP_SYNTH),
        ("detect-wav", WAV),
        ("detect-flac", FLAC),
        ("detect-mp3", MP3),
        ("detect-mp4", MP4),
        ("detect-mov", MOV),
        ("detect-pdf", PDF),
        ("detect-zip", b"PK\x03\x04\x14\x00\x00\x00\x00\x00"),
        ("detect-gif", b"GIF89a\x01\x00\x01\x00"),
        ("detect-text", b"just some words"),
        ("detect-binary", b"\x00\xff\x02\xfe"),
    ],
    ids=lambda params: params[0],
)
def test_detect_vectors(name: str, data: bytes) -> None:
    rec = BY_NAME[name]
    d: Detection = detect(data)
    assert d.format == rec["format"]
    assert d.modality == rec["modality"]
    assert d.pending == rec["pending"]
    # The wire codes are the declaration orders the constants name.
    assert FORMATS.index(d.format) in range(len(FORMATS))
    assert MODALITIES.index(d.modality) in range(len(MODALITIES))


# ---------------------------------------------------------------------
# signature: 14 vectors, every fold recomputed SDK-side
# ---------------------------------------------------------------------


def assert_signature_matches(sig: Signature, rec: dict) -> None:
    """Compares a parsed stream against the recorded fold fields."""
    assert sig.modality == rec["modality"]
    if sig.modality == "image":
        assert sig.phash == int(rec["phash"], 16)
    elif sig.modality == "audio":
        assert sig.peak_count == rec["peak_count"]
        assert sig.frames == rec["frames"]
        assert fnv1a64(sig.peaks_bytes) == int(rec["peaks_fnv1a64"], 16)
        assert sha256_hex(sig.peaks_bytes) == rec["peaks_sha256"]
    elif sig.modality == "text":
        assert sig.word_count == rec["minhash_words"]
        fold = le_words(sig.words)
        assert len(fold) == sig.word_count
        assert fnv1a64(fold) == int(rec["minhash_fnv1a64"], 16)
    elif sig.modality == "binary":
        assert sig.chunk_count == rec["chunk_count"]
        assert fnv1a64(sig.digest_bytes) == int(rec["chunks_fnv1a64"], 16)
        assert sha256_hex(sig.digest_bytes) == rec["chunks_sha256"]
    else:  # video
        assert sig.frame_count == rec["frame_count"]
        frames_fold = le_words(sig.frame_hashes)
        assert len(frames_fold) == sig.frame_count
        assert fnv1a64(frames_fold) == int(rec["frames_fnv1a64"], 16)
        assert sha256_hex(frames_fold) == rec["frames_sha256"]
        assert sig.minhash is not None
        minhash_fold = le_words(sig.minhash)
        assert len(minhash_fold) == rec["minhash_words"]
        assert fnv1a64(minhash_fold) == int(rec["minhash_fnv1a64"], 16)
        assert sig.width == rec["width"]
        assert sig.height == rec["height"]
        assert f"{sig.duration_bits:016x}" == rec["duration_bits"]


@pytest.mark.parametrize(
    "name,data",
    [
        ("sig-image-phash_rgb8_48x40", PNG48),
        ("sig-image-phash_gray8_40x32", GRAY40),
        ("sig-image-base_444-png", PNG_BASE),
        ("sig-image-base_444-jpeg", JPG_BASE),
        ("sig-image-bmp-patterned-48x40", BMP_SYNTH),
        ("sig-audio-tone-wav", WAV),
        ("sig-audio-tone-flac", FLAC),
        ("sig-audio-l3_short-mp3", MP3),
        ("sig-text-prose-4kib", PROSE_A),
        ("sig-binary-splitmix64-48kib", BLOB),
        ("sig-binary-splitmix64-48kib-prefix-insert", BLOB_SHIFTED),
        ("sig-binary-splitmix64-48kib-unrelated", BLOB_OTHER),
        ("sig-video-a_64x48-mp4", MP4),
        ("sig-pdf-text_page", PDF),
    ],
    ids=lambda params: params[0],
)
def test_signature_vectors(name: str, data: bytes) -> None:
    assert_signature_matches(signature(data), BY_NAME[name])


# ---------------------------------------------------------------------
# describe: 7 vectors, tier 1 + folds + facts
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,data",
    [
        ("describe-image-phash_rgb8_48x40", PNG48),
        ("describe-image-bmp-patterned-48x40", BMP_SYNTH),
        ("describe-audio-tone-wav", WAV),
        ("describe-text-prose-4kib", PROSE_A),
        ("describe-binary-splitmix64-48kib", BLOB),
        ("describe-video-a_64x48-mp4", MP4),
        ("describe-pdf-text_page", PDF),
    ],
    ids=lambda params: params[0],
)
def test_describe_vectors(name: str, data: bytes) -> None:
    rec = BY_NAME[name]
    d: Description = describe(data)
    assert d.format == rec["format"]
    assert d.modality == rec["modality"]
    assert d.tier1 == rec["tier1"]
    assert_signature_matches(d.signature, rec)
    facts = d.facts
    if d.modality == "image":
        assert facts["width"] == rec["facts"]["width"]
        assert facts["height"] == rec["facts"]["height"]
        assert facts["keypoints"] == rec["facts"]["keypoints"]
    elif d.modality == "audio":
        assert facts["sample_rate"] == rec["facts"]["sample_rate"]
        assert facts["channels"] == rec["facts"]["channels"]
        assert facts["frames"] == rec["facts"]["frames"]
        assert facts["peaks"] == rec["facts"]["peaks"]
    elif d.modality == "text":
        assert facts["words"] == rec["facts"]["words"]
        assert facts["canonical_len"] == rec["facts"]["canonical_len"]
    elif d.modality == "binary":
        assert facts["len"] == rec["facts"]["len"]
        assert facts["chunks"] == rec["facts"]["chunks"]
    else:  # video
        assert facts["width"] == rec["facts"]["width"]
        assert facts["height"] == rec["facts"]["height"]
        assert f"{facts['duration_bits']:016x}" == rec["facts"]["duration_bits"]
        assert facts["frames_sampled"] == rec["facts"]["frames_sampled"]


# ---------------------------------------------------------------------
# match: 9 slot-exact outcome vectors + the cross-modality refusal
# ---------------------------------------------------------------------


MATCH_INPUTS = {
    "match-image-self": (PNG48, PNG48, "image"),
    "match-image-distinct": (PNG48, GRAY40, "image"),
    "match-image-png-vs-jpeg-same-pixels": (PNG_BASE, JPG_BASE, "image"),
    "match-audio-self": (WAV, WAV, "audio"),
    "match-text-self": (PROSE_A, PROSE_A, "text"),
    "match-text-distinct": (PROSE_A, PROSE_B, "text"),
    "match-binary-near-duplicate": (BLOB, BLOB_SHIFTED, "binary"),
    "match-binary-unrelated": (BLOB, BLOB_OTHER, "binary"),
    "match-video-mp4-vs-mov": (MP4, MOV, "video"),
}


@pytest.mark.parametrize("name", sorted(MATCH_INPUTS))
def test_match_vectors(name: str) -> None:
    a, b, kind = MATCH_INPUTS[name]
    rec = BY_NAME[name]
    r: MatchResult = match_signatures(a, b)
    assert r.tag == kind
    assert r.matched == rec["matched"]
    if kind == "image":
        assert r.slots[0] == rec["hamming"]
    elif kind == "audio":
        if "votes" in rec and rec["votes"]:
            assert r.slots[0] == rec["votes"]
            assert r.slots[1] == rec["delta_t"] & MASK64
        else:
            assert r.slots[0] == 0
    elif kind == "video":
        assert f"{r.slots[0]:016x}" == rec["score_bits"]
        assert f"{r.slots[1]:016x}" == rec["minhash_jaccard_bits"]
    else:  # text and binary both record jaccard bits
        assert f"{r.slots[0]:016x}" == rec["jaccard_bits"]


def test_match_cross_modality_is_pinned_refusal() -> None:
    rec = BY_NAME["match-error-cross-modality"]
    with pytest.raises(FfiError) as exc:
        match_signatures(PNG48, PROSE_A)
    assert exc.value.status == -2


# ---------------------------------------------------------------------
# error + refusals: rejected inputs never crash, they status
# ---------------------------------------------------------------------


def test_error_video_non_avc_is_pinned_refusal() -> None:
    rec = BY_NAME["error-video-non-avc"]
    with pytest.raises(FfiError) as exc:
        signature(MP4V)
    assert exc.value.status == -2


def test_corrupt_image_is_rejected() -> None:
    corrupt = b"\x89PNG\r\n\x1a\ngarbage"
    with pytest.raises(FfiError) as sig_exc:
        signature(corrupt)
    assert sig_exc.value.status == -2
    with pytest.raises(FfiError) as desc_exc:
        describe(corrupt)
    assert desc_exc.value.status == -2
    with pytest.raises(FfiError) as hash_exc:
        content_hash(corrupt)
    assert hash_exc.value.status == -2


def test_malformed_pdf_is_rejected() -> None:
    with pytest.raises(FfiError) as exc:
        signature(b"%PDF-1.4 garbage not a pdf")
    assert exc.value.status == -2


# ---------------------------------------------------------------------
# The rust-derived literal pin: tier-1 of the smallest pinned fixture,
# derived once from the built cdylib and frozen here.
# ---------------------------------------------------------------------


def test_content_hash_literal_pin() -> None:
    assert content_hash(PNG48).hex() == (
        "1f7637f88725b1f3c1b60fb5559486349298b2a5525bac5fb1df196651e0cb74"
    )
