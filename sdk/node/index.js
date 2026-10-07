// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash
"use strict";

/**
 * pith-hash SDK: the suite curator through koffi.
 *
 * Detect, tier-1 content hash, tier-2 signatures, match and describe
 * via the `pith_hash` Rust cdylib. The byte streams the cdylib hands
 * out are the canonical serializations of the Rust `reference` module
 * — the same layouts the repository-root reference.json records its
 * fnv1a64 / sha256 sub-digests over — so this wrapper parses them
 * back into plain objects and re-hashes every payload.
 */

const koffi = require("koffi");
const fs = require("node:fs");
const path = require("node:path");

const STATUS_OK = 0;
const STATUS_INVALID = -1;
const STATUS_REJECTED = -2;

/** Format names by wire code (`pith_digest::Format` declaration order). */
const FORMATS = Object.freeze(["png", "jpeg", "bmp", "zip", "mp4", "mp3", "wav", "flac", "pdf", "gif", "unknown"]);

/** Modality names by wire code (declaration order). */
const MODALITIES = Object.freeze(["image", "audio", "text", "binary", "video"]);

/** Match-outcome tags by wire code (declaration order). */
const MATCH_TAGS = Object.freeze(["image", "audio", "text", "binary", "video"]);

/** Signature-stream tag bytes (declaration order). */
const SIGNATURE_TAGS = Object.freeze(["image", "audio", "text", "binary", "video"]);

/** Every cdylib file name cargo may drop into the build directory, per platform. */
const CDYLIB_NAMES = ["pith_hash.dll", "libpith_hash.so", "libpith_hash.dylib"];

const PKG_ROOT = path.join(__dirname);
const REPO_ROOT = path.resolve(__dirname, "..", "..");

/** FfiError: a non-zero status code came back from the cdylib. */
class FfiError extends Error {
  /**
   * @param {string} op the FFI operation name
   * @param {number} status the raw status code
   */
  constructor(op, status) {
    const kind = { [STATUS_INVALID]: "invalid argument", [STATUS_REJECTED]: "input rejected" }[status] ?? "unknown failure";
    super(`${op} failed: ${kind} (status ${status})`);
    this.name = "FfiError";
    /** The raw status code the FFI returned. */
    this.status = status;
  }
}

/**
 * Locates the cdylib through the suite's discovery chain.
 * @returns {string} an absolute path to the cdylib file
 * @throws {Error} when nothing is found
 */
function findCdylib() {
  const explicit = process.env.PITH_CDYLIB;
  if (explicit && fs.statSync(explicit, { throwIfNoEntry: false })?.isFile()) {
    return path.resolve(explicit);
  }
  /** @type {string[]} */
  const dirs = [];
  const envDir = process.env.PITH_CDYLIB_DIR;
  if (envDir) {
    dirs.push(envDir);
    if (!path.isAbsolute(envDir)) {
      dirs.push(path.join(REPO_ROOT, envDir));
    }
  }
  const osArch = `${process.platform}-${process.arch}`;
  dirs.push(path.join(PKG_ROOT, "prebuilds", osArch));
  dirs.push(path.join(PKG_ROOT, "prebuilds"));
  dirs.push(path.join(REPO_ROOT, "target", "release"));
  for (const dir of dirs) {
    for (const name of CDYLIB_NAMES) {
      const p = path.join(dir, name);
      if (fs.statSync(p, { throwIfNoEntry: false })?.isFile()) return p;
    }
  }
  throw new Error(
    "no pith-hash cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR, prebuilds/ and <repo>/target/release); " +
      "run `cargo build --release` first",
  );
}

let cached = undefined;

/**
 * Loads the cdylib and binds the exported symbols (lazily, once).
 * @returns {{detect: Function, signature: Function, describe: Function, match: Function,
 *   contentHash: Function, free: Function}}
 */
function loadLibrary() {
  if (cached) return cached;
  const lib = koffi.load(findCdylib());
  const detect = lib.func("pith_hash_detect", "int32_t", [
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("uint32_t")),
    koffi.out(koffi.pointer("uint32_t")),
    koffi.out(koffi.pointer("uint32_t")),
  ]);
  const streamProto = ["const uint8_t *", "size_t", koffi.out(koffi.pointer("void *")), koffi.out(koffi.pointer("size_t"))];
  const signature = lib.func("pith_hash_signature", "int32_t", streamProto);
  const describe = lib.func("pith_hash_describe", "int32_t", streamProto);
  const match = lib.func("pith_hash_match", "int32_t", [
    "const uint8_t *",
    "size_t",
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("uint32_t")),
    koffi.out(koffi.pointer("uint64_t")),
    "size_t",
    koffi.out(koffi.pointer("uint32_t")),
  ]);
  const contentHash = lib.func("pith_hash_content_hash", "int32_t", [
    "const uint8_t *",
    "size_t",
    koffi.out(koffi.pointer("uint8_t")),
    "size_t",
    koffi.out(koffi.pointer("size_t")),
  ]);
  const free = lib.func("void pith_hash_free(void *ptr, size_t len)");
  cached = { detect, signature, describe, match, contentHash, free };
  return cached;
}

/**
 * Copies a handed-out stream buffer into a Buffer and frees it.
 * @param {number} status the FFI status
 * @param {string} op the operation name
 * @param {unknown[]} out the [ptr] holder
 * @param {unknown[]} outLen the [len] holder
 * @returns {Buffer}
 */
function handOut(status, op, out, outLen) {
  if (status !== STATUS_OK) {
    throw new FfiError(op, status);
  }
  try {
    // koffi.decode hands back a Uint8Array view over the external
    // buffer; copy it into a Buffer before the cdylib buffer is freed.
    return Buffer.from(koffi.decode(out[0], "uint8_t", Number(outLen[0])));
  } finally {
    loadLibrary().free(out[0], Number(outLen[0]));
  }
}

function streamOp(op, data) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("data must be a Buffer");
  }
  const out = [null];
  const outLen = [0];
  const status = loadLibrary()[op](data, data.length, out, outLen);
  return handOut(status, `pith_hash_${op}`, out, outLen);
}

/**
 * Sniffs `data` without decoding.
 * @param {Buffer} data the file bytes
 * @returns {{format: string, modality: string, pending: boolean}}
 */
function detect(data) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("data must be a Buffer");
  }
  const format = new Uint32Array(1);
  const modality = new Uint32Array(1);
  const pending = new Uint32Array(1);
  const status = loadLibrary().detect(data, data.length, format, modality, pending);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_hash_detect", status);
  }
  return { format: FORMATS[format[0]], modality: MODALITIES[modality[0]], pending: pending[0] === 1 };
}

/**
 * Computes the tier-2 signature and parses the signature stream.
 * @param {Buffer} data the file bytes
 * @returns {object} the parsed signature (modality + per-lane fields)
 */
function signature(data) {
  return parseSignature(streamOp("signature", data));
}

/**
 * Computes both tiers and parses the describe stream.
 * @param {Buffer} data the file bytes
 * @returns {object} {format, modality, tier1, signature, facts}
 */
function describe(data) {
  return parseDescribe(streamOp("describe", data));
}

/**
 * Scores two raw inputs, slots flattened per the wire table.
 * @param {Buffer} a the left file bytes
 * @param {Buffer} b the right file bytes
 * @returns {{tag: string, slots: BigInt64Array|number[], matched: boolean}}
 * @throws {FfiError} with status -2 for a cross-modality pair
 */
function matchSignatures(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError("inputs must be Buffers");
  }
  const tag = new Uint32Array(1);
  const slots = new BigUint64Array(4);
  const matched = new Uint32Array(1);
  const status = loadLibrary().match(a, a.length, b, b.length, tag, slots, 4, matched);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_hash_match", status);
  }
  return { tag: MATCH_TAGS[tag[0]], slots: Array.from(slots), matched: matched[0] === 1 };
}

/**
 * Computes the 32-byte tier-1 content digest.
 * @param {Buffer} data the file bytes
 * @returns {Buffer} the 32-byte digest
 */
function contentHash(data) {
  if (!Buffer.isBuffer(data)) {
    throw new TypeError("data must be a Buffer");
  }
  const buf = new Uint8Array(32);
  const outLen = new BigUint64Array(1);
  const status = loadLibrary().contentHash(data, data.length, buf, 32, outLen);
  if (status !== STATUS_OK) {
    throw new FfiError("pith_hash_content_hash", status);
  }
  return Buffer.from(buf.subarray(0, Number(outLen[0])));
}

/**
 * The 64-bit FNV-1a fold the reference sub-digests use.
 * @param {Buffer|Uint8Array} data the bytes to fold
 * @returns {bigint}
 */
function fnv1a64(data) {
  let h = 0xcbf29ce484222325n;
  for (const b of data) {
    h ^= BigInt(b);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h;
}

/** Reads a big-endian u64 as BigInt. @param {Buffer} b @param {number} off */
function be64(b, off) {
  return b.readBigUInt64BE(off);
}

/**
 * Re-expresses the canonical signature stream as a plain object.
 * @param {Buffer} raw the signature stream
 * @returns {object}
 */
function parseSignature(raw) {
  if (!Buffer.isBuffer(raw) || raw.length < 1) {
    throw new TypeError("signature stream is empty");
  }
  const tag = raw[0];
  if (tag >= SIGNATURE_TAGS.length) {
    throw new TypeError(`unknown signature tag ${tag}`);
  }
  const modality = SIGNATURE_TAGS[tag];
  if (modality === "image") {
    if (raw.length !== 9) throw new TypeError("image stream is not tag + u64");
    return { modality, phash: be64(raw, 1) };
  }
  if (modality === "audio") {
    if (raw.length < 13) throw new TypeError("audio stream is shorter than its 13-byte header");
    const peakCount = Number(be64(raw, 1));
    const frames = raw.readUInt32BE(9);
    const payload = raw.subarray(13);
    if (peakCount !== payload.length || payload.length % 6 !== 0) {
      throw new TypeError("audio peak count disagrees with the payload");
    }
    const peaks = [];
    for (let i = 0; i < payload.length; i += 6) {
      peaks.push([payload.readUInt32LE(i), payload.readUInt16LE(i + 4)]);
    }
    return { modality, peakCount, frames, peaks, peaksBytes: Buffer.from(payload) };
  }
  if (modality === "text") {
    if (raw.length < 9) throw new TypeError("text stream is shorter than its 9-byte header");
    const wordCount = Number(be64(raw, 1));
    const payload = raw.subarray(9);
    if (wordCount !== payload.length || payload.length % 8 !== 0) {
      throw new TypeError("text word count disagrees with the payload");
    }
    const words = [];
    for (let i = 0; i < payload.length; i += 8) words.push(be64(payload, i));
    return { modality, wordCount, words };
  }
  if (modality === "binary") {
    if (raw.length < 9) throw new TypeError("binary stream is shorter than its 9-byte header");
    const chunkCount = Number(be64(raw, 1));
    const payload = raw.subarray(9);
    if (chunkCount !== payload.length || payload.length % 32 !== 0) {
      throw new TypeError("binary chunk count disagrees with the payload");
    }
    return { modality, chunkCount, digestBytes: Buffer.from(payload) };
  }
  // video
  if (raw.length < 21) throw new TypeError("video stream is shorter than its 21-byte header");
  const frameCount = raw.readUInt32BE(1);
  const width = raw.readUInt32BE(5);
  const height = raw.readUInt32BE(9);
  const durationBits = be64(raw, 13);
  const rest = raw.subarray(21);
  if (frameCount > rest.length || frameCount % 8 !== 0) {
    throw new TypeError("video frame count disagrees with the payload");
  }
  const framesPayload = rest.subarray(0, frameCount);
  const minhashPayload = rest.subarray(frameCount);
  if (minhashPayload.length % 8 !== 0) {
    throw new TypeError("video minhash payload is not whole words");
  }
  const frameHashes = [];
  const minhash = [];
  for (let i = 0; i < framesPayload.length; i += 8) frameHashes.push(framesPayload.readBigUInt64LE(i));
  for (let i = 0; i < minhashPayload.length; i += 8) minhash.push(minhashPayload.readBigUInt64LE(i));
  return { modality, frameCount, width, height, durationBits, frameHashes, minhash };
}

/** The byte size of each modality's facts block. @param {string} modality */
function factsLen(modality) {
  if (modality === "audio") return 18;
  if (modality === "video") return 24;
  return 16;
}

/**
 * Re-expresses the canonical describe stream as a plain object.
 * @param {Buffer} raw the describe stream
 * @returns {object} {format, modality, tier1, signature, facts}
 */
function parseDescribe(raw) {
  if (!Buffer.isBuffer(raw) || raw.length < 35) {
    throw new TypeError("describe stream is shorter than its 35-byte header");
  }
  const fmt = raw[0];
  const mod = raw[1];
  if (fmt >= FORMATS.length || mod >= MODALITIES.length) {
    throw new TypeError(`unknown describe codes ${fmt}/${mod}`);
  }
  const tier1 = raw.subarray(2, 34).toString("hex");
  const modality = MODALITIES[mod];
  // The facts block terminates the stream; its size is known from the
  // modality code, so the signature stream is the exact middle slice
  // (a bare parseSignature would see the facts as payload).
  const sigEnd = raw.length - factsLen(modality);
  const sig = parseSignature(raw.subarray(34, sigEnd));
  const factsRaw = raw.subarray(sigEnd);
  let facts;
  if (modality === "image") {
    if (factsRaw.length !== 16) throw new TypeError("image facts block is 16 bytes");
    facts = { width: factsRaw.readUInt32BE(0), height: factsRaw.readUInt32BE(4), keypoints: Number(be64(factsRaw, 8)) };
  } else if (modality === "audio") {
    if (factsRaw.length !== 18) throw new TypeError("audio facts block is 18 bytes");
    facts = {
      sampleRate: factsRaw.readUInt32BE(0),
      channels: factsRaw.readUInt16BE(4),
      frames: factsRaw.readUInt32BE(6),
      peaks: Number(be64(factsRaw, 10)),
    };
  } else if (modality === "text") {
    if (factsRaw.length !== 16) throw new TypeError("text facts block is 16 bytes");
    facts = { words: Number(be64(factsRaw, 0)), canonicalLen: Number(be64(factsRaw, 8)) };
  } else if (modality === "binary") {
    if (factsRaw.length !== 16) throw new TypeError("binary facts block is 16 bytes");
    facts = { len: Number(be64(factsRaw, 0)), chunks: Number(be64(factsRaw, 8)) };
  } else {
    if (factsRaw.length !== 24) throw new TypeError("video facts block is 24 bytes");
    facts = {
      width: factsRaw.readUInt32BE(0),
      height: factsRaw.readUInt32BE(4),
      durationBits: be64(factsRaw, 8),
      framesSampled: Number(be64(factsRaw, 16)),
    };
  }
  return { format: FORMATS[fmt], modality, tier1, signature: sig, facts };
}

module.exports = {
  STATUS_OK,
  STATUS_INVALID,
  STATUS_REJECTED,
  FORMATS,
  MODALITIES,
  MATCH_TAGS,
  SIGNATURE_TAGS,
  CDYLIB_NAMES,
  FfiError,
  findCdylib,
  detect,
  signature,
  describe,
  matchSignatures,
  contentHash,
  parseSignature,
  parseDescribe,
  fnv1a64,
};
