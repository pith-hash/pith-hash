// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

// Hex-exact conformance: the committed reference vectors through koffi.
// Every one of the 45 vectors in the repository-root reference.json is
// replayed through the cdylib and compared against every recorded
// field — detect codes, tier-2 sub-digests (recomputed SDK-side with
// the same folds the generator uses), tier-1 digests, facts and match
// slots. The same vectors the Rust `gen-reference verify` gate and the
// Python/Go SDKs check.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const {
  FfiError,
  MODALITIES,
  FORMATS,
  contentHash,
  describe,
  detect,
  fnv1a64,
  findCdylib,
  matchSignatures,
  signature,
} = require("../index.js");

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const REFERENCE = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "reference.json"), "utf8")).vectors;
const BY_NAME = new Map(REFERENCE.map((v) => [v.name, v]));

const MASK64 = (1n << 64n) - 1n;

/** SplitMix64 next_u64 (BigInt, wrapping). @param {{s: bigint}} st */
function splitmixNext(st) {
  st.s = (st.s + 0x9e3779b97f4a7c15n) & MASK64;
  let z = st.s;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
  return z ^ (z >> 31n);
}

/** The upstream conformance byte recipe: one next_u64 per byte, low byte. */
function splitmixBytes(seed, length) {
  const st = { s: BigInt(seed) };
  const out = Buffer.alloc(length);
  for (let i = 0; i < length; i++) out[i] = Number(splitmixNext(st) & 0xffn);
  return out;
}

/** The 48 KiB pseudo-file recipe of the upstream facade suite. */
function blob48(seed) {
  return splitmixBytes(seed, 48 * 1024);
}

const VOCAB = [
  "hash", "image", "audio", "signal", "codec", "block", "frame", "sample", "stream",
  "vector", "median", "kernel", "window", "raster", "pixel", "tone", "hash", "luma",
  "delta", "chunk", "radix", "filter", "table", "edge",
];

/** Deterministic ~bytes-sized prose from the seeded 24-word vocabulary. */
function prose(seed, bytes) {
  const st = { s: BigInt(seed) };
  let out = "";
  while (out.length < bytes) {
    out += VOCAB[Number(splitmixNext(st) % BigInt(VOCAB.length))];
    out += " ";
  }
  return out.slice(0, bytes);
}

/** Smooth periodic RGB content with real low-frequency energy. */
function patternedPixels(seed, w, h) {
  const st = { s: BigInt(seed) };
  const fx = Number(splitmixNext(st) % 5n) + 1;
  const fy = Number(splitmixNext(st) % 5n) + 1;
  const p1 = Number(splitmixNext(st) % 628n) / 100.0;
  const p2 = Number(splitmixNext(st) % 628n) / 100.0;
  const TAU = 6.283185307179586;
  const px = Buffer.alloc(w * h * 3);
  let i = 0;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const u = x / w;
      const v = y / h;
      const r = 127.5 + 120.0 * Math.sin(u * fx * TAU + p1);
      const g = 127.5 + 120.0 * Math.sin(v * fy * TAU + p2);
      const b = 127.5 + 120.0 * Math.sin((u + v) * (fx + fy) + p1 + p2);
      px[i++] = Math.trunc(r);
      px[i++] = Math.trunc(g);
      px[i++] = Math.trunc(b);
    }
  }
  return px;
}

/** Encodes RGB triples as a bottom-up 24-bit BMP. */
function bmp24(w, h, rgb) {
  const row = Math.ceil((w * 3) / 4) * 4;
  const img = row * h;
  const f = [Buffer.from("BM", "ascii")];
  const head = Buffer.alloc(52);
  head.writeUInt32LE(54 + img, 0); // file size
  head.writeUInt32LE(54, 8); // pixel offset (4 reserved bytes at 4..8)
  head.writeUInt32LE(40, 12); // DIB header
  head.writeInt32LE(w, 16);
  head.writeInt32LE(h, 20);
  head.writeUInt16LE(1, 24); // planes
  head.writeUInt16LE(24, 26); // bpp
  f.push(head);
  const pad = Buffer.alloc(row - w * 3);
  for (let y = h - 1; y >= 0; y--) {
    const rowBuf = Buffer.alloc(w * 3);
    for (let x = 0; x < w; x++) {
      const i = (y * w + x) * 3;
      rowBuf[x * 3] = rgb[i + 2];
      rowBuf[x * 3 + 1] = rgb[i + 1];
      rowBuf[x * 3 + 2] = rgb[i];
    }
    f.push(rowBuf, pad);
  }
  return Buffer.concat(f);
}

function fixture(name) {
  return fs.readFileSync(path.join(REPO_ROOT, "tests", "fixtures", name));
}

// The gen-reference corpus, name -> input bytes (cached).
const inputCache = new Map();
function input(name) {
  if (!inputCache.has(name)) {
    inputCache.set(name, makeInput(name));
  }
  return inputCache.get(name);
}

/** The exact name->input mapping tools/gen-reference defines. */
function makeInput(name) {
  switch (name) {
    case "detect-png":
    case "sig-image-phash_rgb8_48x40":
    case "describe-image-phash_rgb8_48x40":
      return fixture("phash_rgb8_48x40.png");
    case "detect-jpeg":
    case "sig-image-base_444-jpeg":
      return fixture("base_444.jpg");
    case "detect-bmp":
    case "sig-image-bmp-patterned-48x40":
    case "describe-image-bmp-patterned-48x40":
      return bmp24(48, 40, patternedPixels(0xbeef0001, 48, 40));
    case "detect-wav":
    case "sig-audio-tone-wav":
    case "describe-audio-tone-wav":
      return fixture("tone.wav");
    case "detect-flac":
    case "sig-audio-tone-flac":
      return fixture("tone.flac");
    case "detect-mp3":
    case "sig-audio-l3_short-mp3":
      return fixture("l3_short.mp3");
    case "detect-mp4":
    case "sig-video-a_64x48-mp4":
    case "describe-video-a_64x48-mp4":
      return fixture("a_64x48.mp4");
    case "detect-mov":
      return fixture("a_64x48.mov");
    case "detect-pdf":
    case "sig-pdf-text_page":
    case "describe-pdf-text_page":
      return fixture("text_page.pdf");
    case "detect-zip":
      return Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00]);
    case "detect-gif":
      return Buffer.from("GIF89a\x01\x00\x01\x00", "binary");
    case "detect-text":
      return Buffer.from("just some words", "binary");
    case "detect-binary":
      return Buffer.from([0x00, 0xff, 0x02, 0xfe]);
    case "sig-image-phash_gray8_40x32":
      return fixture("phash_gray8_40x32.png");
    case "sig-image-base_444-png":
      return fixture("base_444.png");
    case "sig-text-prose-4kib":
    case "describe-text-prose-4kib":
      return Buffer.from(prose(0xd1, 4096), "binary");
    case "sig-binary-splitmix64-48kib":
    case "describe-binary-splitmix64-48kib":
      return blob48(0xd15e5eed);
    case "sig-binary-splitmix64-48kib-prefix-insert": {
      const out = Buffer.alloc(1 + 48 * 1024);
      out[0] = 0xaa;
      blob48(0xd15e5eed).copy(out, 1);
      return out;
    }
    case "sig-binary-splitmix64-48kib-unrelated":
      return blob48(0xbadc0ffe);
    case "match-image-self":
    case "match-image-distinct":
    case "match-error-cross-modality":
      return fixture("phash_rgb8_48x40.png");
    case "match-image-png-vs-jpeg-same-pixels":
      return fixture("base_444.png");
    case "match-audio-self":
      return fixture("tone.wav");
    case "match-text-self":
    case "match-text-distinct":
      return Buffer.from(prose(0xd1, 4096), "binary");
    case "match-binary-near-duplicate":
    case "match-binary-unrelated":
      return blob48(0xd15e5eed);
    case "match-video-mp4-vs-mov":
      return fixture("a_64x48.mp4");
    default:
      throw new Error(`no input recipe for ${name}`);
  }
}

/** The right-hand input of each match vector. */
function matchRight(name) {
  switch (name) {
    case "match-image-distinct":
    case "match-image-png-vs-jpeg-same-pixels":
      return name === "match-image-distinct"
        ? fixture("phash_gray8_40x32.png")
        : fixture("base_444.jpg");
    case "match-text-distinct":
      return Buffer.from(prose(0xd2, 4096), "binary");
    case "match-binary-near-duplicate": {
      const out = Buffer.alloc(1 + 48 * 1024);
      out[0] = 0xaa;
      blob48(0xd15e5eed).copy(out, 1);
      return out;
    }
    case "match-binary-unrelated":
      return blob48(0xbadc0ffe);
    case "match-video-mp4-vs-mov":
      return fixture("a_64x48.mov");
    default:
      return input(name); // self-matches
  }
}

/** f64 bit pattern from a recorded 16-hex-digit string. @param {string} hex */
const bits = (hex) => BigInt(`0x${hex}`);
const fnvHex = (bytes) => fnv1a64(bytes).toString(16).padStart(16, "0");
const shaHex = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

/** Words folded little-endian, the canonical payload behind the digests. */
function wordsLe(words) {
  const out = Buffer.alloc(words.length * 8);
  words.forEach((w, i) => out.writeBigUInt64LE(w, i * 8));
  return out;
}

test("cdylib is discoverable", () => {
  assert.ok(fs.statSync(findCdylib()).isFile());
});

// --- detect: 13 verdict vectors --------------------------------------
for (const [name, v] of BY_NAME) {
  if (!name.startsWith("detect-")) continue;
  test(`${name} verdict is reproduced`, () => {
    const det = detect(input(name));
    assert.equal(det.format, v.format, name);
    assert.equal(det.modality, v.modality, name);
    assert.equal(det.pending, v.pending, name);
    assert.ok(FORMATS.includes(det.format) && MODALITIES.includes(det.modality), name);
  });
}

// --- signature: 14 fold vectors --------------------------------------
for (const [name, v] of BY_NAME) {
  if (!name.startsWith("sig-")) continue;
  test(`${name} signature folds are reproduced hex-exact`, () => {
    const sig = signature(input(name));
    assert.equal(sig.modality, v.modality, name);
    if (sig.modality === "image") {
      assert.equal(sig.phash, BigInt(v.phash), name);
    } else if (sig.modality === "audio") {
      assert.equal(sig.peakCount, v.peak_count, name);
      assert.equal(sig.peakCount, sig.peaksBytes.length, name);
      assert.equal(sig.peakCount % 6, 0, name);
      assert.equal(sig.frames, v.frames, name);
      assert.equal(fnvHex(sig.peaksBytes), v.peaks_fnv1a64, name);
      assert.equal(shaHex(sig.peaksBytes), v.peaks_sha256, name);
    } else if (sig.modality === "text") {
      assert.equal(sig.wordCount, v.minhash_words, name);
      assert.equal(sig.words.length * 8, v.minhash_words, name);
      assert.equal(fnvHex(wordsLe(sig.words)), v.minhash_fnv1a64, name);
      assert.equal(shaHex(wordsLe(sig.words)), v.minhash_sha256, name);
    } else if (sig.modality === "binary") {
      assert.equal(sig.chunkCount, v.chunk_count, name);
      assert.equal(sig.chunkCount, sig.digestBytes.length, name);
      assert.equal(sig.chunkCount % 32, 0, name);
      assert.equal(fnvHex(sig.digestBytes), v.chunks_fnv1a64, name);
      assert.equal(shaHex(sig.digestBytes), v.chunks_sha256, name);
    } else {
      const frames = wordsLe(sig.frameHashes);
      const minhash = wordsLe(sig.minhash);
      assert.equal(sig.frameCount, v.frame_count, name);
      assert.equal(sig.frameCount, frames.length, name);
      assert.equal(fnvHex(frames), v.frames_fnv1a64, name);
      assert.equal(shaHex(frames), v.frames_sha256, name);
      assert.equal(minhash.length, v.minhash_words, name);
      assert.equal(fnvHex(minhash), v.minhash_fnv1a64, name);
      assert.equal(sig.width, v.width, name);
      assert.equal(sig.height, v.height, name);
      assert.equal(sig.durationBits, bits(v.duration_bits), name);
    }
  });
}

// --- describe: 7 both-tiers vectors ----------------------------------
for (const [name, v] of BY_NAME) {
  if (!name.startsWith("describe-")) continue;
  test(`${name} description is reproduced hex-exact`, () => {
    const d = describe(input(name));
    assert.equal(d.format, v.format, name);
    assert.equal(d.modality, v.modality, name);
    assert.equal(d.tier1, v.tier1, name);
    const s = d.signature;
    if (s.modality === "image") {
      assert.equal(s.phash, BigInt(v.phash), name);
      assert.deepEqual(d.facts, { width: v.facts.width, height: v.facts.height, keypoints: v.facts.keypoints }, name);
    } else if (s.modality === "audio") {
      assert.equal(s.peakCount, v.peak_count, name);
      assert.equal(fnvHex(s.peaksBytes), v.peaks_fnv1a64, name);
      assert.equal(shaHex(s.peaksBytes), v.peaks_sha256, name);
      assert.equal(s.frames, v.frames, name);
      assert.deepEqual(
        d.facts,
        { sampleRate: v.facts.sample_rate, channels: v.facts.channels, frames: v.facts.frames, peaks: v.facts.peaks },
        name,
      );
    } else if (s.modality === "text") {
      assert.equal(s.wordCount, v.minhash_words, name);
      assert.equal(fnvHex(wordsLe(s.words)), v.minhash_fnv1a64, name);
      assert.equal(shaHex(wordsLe(s.words)), v.minhash_sha256, name);
      assert.deepEqual(d.facts, { words: v.facts.words, canonicalLen: v.facts.canonical_len }, name);
    } else if (s.modality === "binary") {
      assert.equal(s.chunkCount, v.chunk_count, name);
      assert.equal(fnvHex(s.digestBytes), v.chunks_fnv1a64, name);
      assert.equal(shaHex(s.digestBytes), v.chunks_sha256, name);
      assert.deepEqual(d.facts, { len: v.facts.len, chunks: v.facts.chunks }, name);
    } else {
      const frames = wordsLe(s.frameHashes);
      assert.equal(s.frameCount, v.frame_count, name);
      assert.equal(fnvHex(frames), v.frames_fnv1a64, name);
      assert.equal(shaHex(frames), v.frames_sha256, name);
      assert.equal(wordsLe(s.minhash).length, v.minhash_words, name);
      assert.equal(fnvHex(wordsLe(s.minhash)), v.minhash_fnv1a64, name);
      assert.equal(s.width, v.width, name);
      assert.equal(s.height, v.height, name);
      assert.equal(s.durationBits, bits(v.duration_bits), name);
      assert.deepEqual(
        d.facts,
        {
          width: v.facts.width,
          height: v.facts.height,
          durationBits: bits(v.facts.duration_bits),
          framesSampled: v.facts.frames_sampled,
        },
        name,
      );
    }
  });
}

// --- match: 10 outcome vectors ---------------------------------------
/** Recorded decimal delta_t -> the u64 two's-complement slot. */
const deltaSlot = (dt) => BigInt(dt < 0 ? dt + 0x10000000000000000 : dt);

for (const [name, v] of BY_NAME) {
  if (!name.startsWith("match-")) continue;
  if (v.outcome === "error") {
    test(`${name} is refused with status -2`, () => {
      assert.throws(() => matchSignatures(input(name), input("sig-text-prose-4kib")), (err) => {
        assert.ok(err instanceof FfiError);
        assert.equal(err.status, -2);
        return true;
      });
    });
    continue;
  }
  test(`${name} match slots are reproduced exactly`, () => {
    const m = matchSignatures(input(name), matchRight(name));
    assert.equal(m.matched, v.matched, name);
    if (v.outcome === "image") {
      assert.equal(m.tag, "image", name);
      assert.equal(m.slots[0], BigInt(v.hamming), name);
    } else if (v.outcome === "audio") {
      assert.equal(m.tag, "audio", name);
      assert.equal(m.slots[0], BigInt(v.votes), name);
      assert.equal(m.slots[1], deltaSlot(v.delta_t), name);
    } else if (v.outcome === "jaccard") {
      assert.equal(m.tag, name.startsWith("match-text") ? "text" : "binary", name);
      assert.equal(m.slots[0], bits(v.jaccard_bits), name);
    } else {
      assert.equal(m.tag, "video", name);
      assert.equal(m.slots[0], bits(v.score_bits), name);
      assert.equal(m.slots[1], bits(v.minhash_jaccard_bits), name);
    }
  });
}

// --- error vector + refusals -----------------------------------------
test("non-AVC mp4 is refused with status -2", () => {
  assert.throws(() => signature(fixture("e_mp4v.mp4")), (err) => {
    assert.ok(err instanceof FfiError);
    assert.equal(err.status, -2);
    return true;
  });
});

test("corrupt container is refused, not crashing", () => {
  const corrupt = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from("garbage")]);
  assert.throws(() => signature(corrupt), (err) => {
    assert.ok(err instanceof FfiError);
    assert.equal(err.status, -2);
    return true;
  });
  assert.throws(() => describe(corrupt), FfiError);
  assert.throws(() => contentHash(corrupt), (err) => {
    assert.ok(err instanceof FfiError);
    assert.equal(err.status, -2);
    return true;
  });
});

test("content hash matches a rust-derived pinned value", () => {
  // text_page.pdf's tier-1 digest, derived once from the built cdylib
  // and pinned here so a wrongly regenerated reference.json cannot
  // mask drift. The same pin lives in the Python and Go harnesses and
  // the Rust ffi tests.
  const digest = contentHash(fixture("text_page.pdf"));
  assert.equal(digest.length, 32);
  assert.equal(
    digest.toString("hex"),
    "849978a1682ba75372094611c8fc290b9c39b84d75641bf0b6129cdbaa880fa9",
  );
});
