// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

// Package pithhash provides Go bindings for the pith-hash Rust cdylib:
// detect, tier-1 content hash, tier-2 signatures, match and describe.
//
// The single Rust core (built by `cargo build --release`) is loaded at
// runtime; the package carries zero module dependencies. On unix the
// cdylib is opened with dlopen through cgo, on Windows with
// LoadLibrary through the standard syscall package — both resolve the
// library through the same discovery chain, so `go build ./... &&
// go test ./...` works unchanged on every OS the CD matrix builds.
//
// Discovery order (the suite's cdylib convention):
//
//  1. PITH_CDYLIB — an explicit cdylib file path;
//  2. PITH_CDYLIB_DIR — a directory scanned for the cdylib names (the
//     CD pipeline points this at target/release);
//  3. <repo root>/target/release — the repository working-tree layout,
//     anchored at this package's source directory, so a source
//     checkout runs against a local cargo build unconfigured.
//
// The FFI surface is seven exports: pith_hash_detect,
// pith_hash_signature, pith_hash_describe, pith_hash_match,
// pith_hash_content_hash, pith_hash_free. The byte streams
// SignatureStream/DescribeStream hand out are the canonical
// serializations of the Rust reference module — the same layouts the
// repository-root reference.json records its sub-digests over — and
// ParseSignature/ParseDeserialize re-express them as plain Go values.
package pithhash

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"
)

// Status codes returned by the cdylib's C ABI.
const (
	// StatusOK: success.
	StatusOK int32 = 0
	// StatusInvalid: a caller argument is invalid (a null pointer, a
	// capacity too small for the fixed wire shape).
	StatusInvalid int32 = -1
	// StatusRejected: the core pipeline refused the input (decode
	// failure in any modality, a pending lane, a PDF/audio-layer
	// rejection, or a cross-modality match).
	StatusRejected int32 = -2
)

// Formats names the container formats by wire code
// (pith_digest::Format declaration order).
var Formats = [...]string{"png", "jpeg", "bmp", "zip", "mp4", "mp3", "wav", "flac", "pdf", "gif", "unknown"}

// Modalities names the content modalities by wire code (declaration
// order).
var Modalities = [...]string{"image", "audio", "text", "binary", "video"}

// MatchTags names the match-outcome tags by wire code (declaration
// order).
var MatchTags = [...]string{"image", "audio", "text", "binary", "video"}

// signatureTags names the signature-stream tag bytes (declaration
// order).
var signatureTags = [...]string{"image", "audio", "text", "binary", "video"}

// cdylibNames are the file names cargo may drop into the build
// directory, per platform (windows / linux / macOS).
var cdylibNames = []string{"pith_hash.dll", "libpith_hash.so", "libpith_hash.dylib"}

// cdylibSymbols are the exported symbol names, in resolution order.
var cdylibSymbols = []string{
	"pith_hash_detect",
	"pith_hash_signature",
	"pith_hash_describe",
	"pith_hash_match",
	"pith_hash_content_hash",
	"pith_hash_free",
}

// FfiError reports a non-zero status code from the cdylib.
type FfiError struct {
	// Op is the FFI operation name.
	Op string
	// Status is the raw status code the FFI returned.
	Status int32
}

func (e *FfiError) Error() string {
	kind := "unknown failure"
	switch e.Status {
	case StatusInvalid:
		kind = "invalid argument"
	case StatusRejected:
		kind = "input rejected"
	}
	return fmt.Sprintf("%s failed: %s (status %d)", e.Op, kind, e.Status)
}

// FindCdylib locates the cdylib through the suite's discovery chain.
func FindCdylib() (string, error) {
	if p := os.Getenv("PITH_CDYLIB"); p != "" {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return filepath.Abs(p)
		}
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("pithhash: cannot locate the package source directory")
	}
	pkgDir := filepath.Dir(thisFile)
	repoRoot := filepath.Dir(filepath.Dir(pkgDir)) // sdk/go -> sdk -> repo root

	var dirs []string
	if env := os.Getenv("PITH_CDYLIB_DIR"); env != "" {
		dirs = append(dirs, env)
		if !filepath.IsAbs(env) {
			dirs = append(dirs, filepath.Join(repoRoot, env))
		}
	}
	dirs = append(dirs, filepath.Join(repoRoot, "target", "release"))
	for _, dir := range dirs {
		for _, name := range cdylibNames {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf(
		"pithhash: no cdylib found (searched PITH_CDYLIB, PITH_CDYLIB_DIR and <repo>/target/release); run `cargo build --release` first",
	)
}

// locate resolves the cdylib path once per process.
var locate = sync.OnceValues(FindCdylib)

// Peak is one audio landmark: analysis-frame index and quantized
// frequency slot.
type Peak struct {
	// T is the analysis-frame index (sample position t * HOP).
	T uint32
	// F is the quantized frequency slot.
	F uint16
}

// Sig is a tier-2 signature, re-expressed from the signature stream.
// The count fields mirror reference.json's semantics: they are the
// byte length of the canonical payload the sub-digests cover.
type Sig struct {
	// Modality is the lane tag (image … video).
	Modality string
	// Phash is the image 64-bit perceptual hash.
	Phash uint64
	// PeakCount is the audio peak payload byte count.
	PeakCount int
	// Frames is the audio analysis-frame count.
	Frames uint32
	// Peaks are the parsed audio (t, f) landmarks.
	Peaks []Peak
	// PeaksBytes is the canonical peaks payload the digests cover.
	PeaksBytes []byte
	// WordCount is the text payload byte count.
	WordCount int
	// Words are the text MinHash words.
	Words []uint64
	// ChunkCount is the binary digest payload byte count.
	ChunkCount int
	// DigestBytes is the sorted unique chunk digests, concatenated.
	DigestBytes []byte
	// FrameCount is the video frame payload byte count.
	FrameCount int
	// Width and Height are the displayed video geometry.
	Width, Height uint32
	// DurationBits is the track duration as raw IEEE-754 bits.
	DurationBits uint64
	// FrameHashes is the frame-pHash chain.
	FrameHashes []uint64
	// Minhash is the MinHash over the chain's shingles.
	Minhash []uint64
}

// Detection is what Detect found, re-expressed from the wire codes.
type Detection struct {
	// Format is the sniffed container name (unknown for bare
	// text/binary).
	Format string
	// Modality is the lane that handles it.
	Modality string
	// Pending is true when the lane is named but not served yet.
	Pending bool
}

// Description is both tiers plus facts, re-expressed from the
// describe stream.
type Description struct {
	// Format is the sniffed container name.
	Format string
	// Modality is the lane that answered.
	Modality string
	// Tier1 is the hex of the 32-byte content digest.
	Tier1 string
	// Sig is the parsed signature stream.
	Sig *Sig
	// Facts are the modality facts keyed like reference.json
	// ("width", "sample_rate", "duration_bits", …).
	Facts map[string]uint64
}

// MatchResult is a match outcome, re-expressed from the slots.
type MatchResult struct {
	// Tag is the outcome tag (image … video).
	Tag string
	// Slots carries the outcome's fields: hamming; votes and delta_t
	// (the i64 two's-complement pattern); jaccard bits; score and
	// minhash-jaccard bits.
	Slots []uint64
	// Matched is the advisory verdict.
	Matched bool
}

// Detect sniffs data without decoding: format, modality, pending.
func Detect(data []byte) (Detection, error) {
	var format, modality, pending uint32
	var dataPtr *byte
	if len(data) > 0 {
		dataPtr = &data[0]
	}
	status, err := ffiDetect(libPath(), dataPtr, len(data), &format, &modality, &pending)
	if err != nil {
		return Detection{}, err
	}
	if status != StatusOK {
		return Detection{}, &FfiError{Op: "pith_hash_detect", Status: status}
	}
	return Detection{
		Format:   Formats[format],
		Modality: Modalities[modality],
		Pending:  pending == 1,
	}, nil
}

// SignatureStream computes the tier-2 signature of data and hands back
// the canonical signature stream. The returned slice is a Go copy; the
// handed-out cdylib buffer is released before returning.
func SignatureStream(data []byte) ([]byte, error) {
	return streamOp("pith_hash_signature", data)
}

// DescribeStream computes both tiers of data and hands back the
// canonical describe stream.
func DescribeStream(data []byte) ([]byte, error) {
	return streamOp("pith_hash_describe", data)
}

// Signature computes and parses the tier-2 signature of data.
func Signature(data []byte) (*Sig, error) {
	raw, err := SignatureStream(data)
	if err != nil {
		return nil, err
	}
	return ParseSignature(raw)
}

// Describe computes and parses both tiers of data.
func Describe(data []byte) (*Description, error) {
	raw, err := DescribeStream(data)
	if err != nil {
		return nil, err
	}
	return ParseDescribe(raw)
}

// MatchSignatures scores two raw inputs, slots flattened per the wire
// table. A cross-modality pair is StatusRejected (nothing written).
func MatchSignatures(a, b []byte) (MatchResult, error) {
	var tag, matched uint32
	slots := make([]uint64, 4)
	var aPtr, bPtr *byte
	if len(a) > 0 {
		aPtr = &a[0]
	}
	if len(b) > 0 {
		bPtr = &b[0]
	}
	status, err := ffiMatch(libPath(), aPtr, len(a), bPtr, len(b), &tag, &slots[0], uint64(len(slots)), &matched)
	if err != nil {
		return MatchResult{}, err
	}
	if status != StatusOK {
		return MatchResult{}, &FfiError{Op: "pith_hash_match", Status: status}
	}
	return MatchResult{Tag: MatchTags[tag], Slots: slots, Matched: matched == 1}, nil
}

// ContentHash computes the 32-byte tier-1 content digest of data.
func ContentHash(data []byte) ([]byte, error) {
	buf := make([]byte, 32)
	var outLen uint64
	var dataPtr *byte
	if len(data) > 0 {
		dataPtr = &data[0]
	}
	status, err := ffiContentHash(libPath(), dataPtr, len(data), &buf[0], uint64(len(buf)), &outLen)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &FfiError{Op: "pith_hash_content_hash", Status: status}
	}
	return buf[:outLen], nil
}

// Fnv1a64 is the 64-bit FNV-1a fold the reference sub-digests use.
func Fnv1a64(data []byte) uint64 {
	const offset = uint64(0xcbf29ce484222325)
	const prime = uint64(0x100000001b3)
	h := offset
	for _, b := range data {
		h ^= uint64(b)
		h *= prime
	}
	return h
}

// libPath resolves the cdylib once; panics are impossible (the error
// surfaces on first use).
func libPath() string {
	p, err := locate()
	if err != nil {
		// Re-derive to surface the error text where a caller can see it.
		p2, err2 := FindCdylib()
		_ = p2
		panic(err2)
	}
	return p
}

func streamOp(op string, data []byte) ([]byte, error) {
	var out *byte
	var outLen uint64
	var dataPtr *byte
	if len(data) > 0 {
		dataPtr = &data[0]
	}
	status, err := ffiStream(libPath(), op, dataPtr, len(data), &out, &outLen)
	if err != nil {
		return nil, err
	}
	if status != StatusOK {
		return nil, &FfiError{Op: op, Status: status}
	}
	buf := make([]byte, outLen)
	copy(buf, unsafe.Slice(out, outLen))
	ffiFree(libPath(), out, outLen)
	return buf, nil
}

func be32(b []byte, off int) uint32 {
	return binary.BigEndian.Uint32(b[off:])
}

func be64(b []byte, off int) uint64 {
	return binary.BigEndian.Uint64(b[off:])
}

func be16(b []byte, off int) uint16 {
	return binary.BigEndian.Uint16(b[off:])
}

// ParseSignature re-expresses the canonical signature stream.
func ParseSignature(raw []byte) (*Sig, error) {
	if len(raw) < 1 {
		return nil, fmt.Errorf("pithhash: signature stream is empty")
	}
	tag := raw[0]
	if int(tag) >= len(signatureTags) {
		return nil, fmt.Errorf("pithhash: unknown signature tag %d", tag)
	}
	modality := signatureTags[tag]
	switch modality {
	case "image":
		if len(raw) != 9 {
			return nil, fmt.Errorf("pithhash: image stream is not tag + u64")
		}
		return &Sig{Modality: modality, Phash: be64(raw, 1)}, nil
	case "audio":
		if len(raw) < 13 {
			return nil, fmt.Errorf("pithhash: audio stream is shorter than its 13-byte header")
		}
		peakCount := int(be64(raw, 1))
		frames := be32(raw, 9)
		payload := raw[13:]
		if peakCount != len(payload) || len(payload)%6 != 0 {
			return nil, fmt.Errorf("pithhash: audio peak count disagrees with the payload")
		}
		peaks := make([]Peak, 0, len(payload)/6)
		for i := 0; i < len(payload); i += 6 {
			peaks = append(peaks, Peak{T: binary.LittleEndian.Uint32(payload[i:]), F: binary.LittleEndian.Uint16(payload[i+4:])})
		}
		return &Sig{Modality: modality, PeakCount: peakCount, Frames: frames, Peaks: peaks, PeaksBytes: append([]byte(nil), payload...)}, nil
	case "text":
		if len(raw) < 9 {
			return nil, fmt.Errorf("pithhash: text stream is shorter than its 9-byte header")
		}
		wordCount := int(be64(raw, 1))
		payload := raw[9:]
		if wordCount != len(payload) || len(payload)%8 != 0 {
			return nil, fmt.Errorf("pithhash: text word count disagrees with the payload")
		}
		words := make([]uint64, 0, len(payload)/8)
		for i := 0; i < len(payload); i += 8 {
			words = append(words, be64(payload, i))
		}
		return &Sig{Modality: modality, WordCount: wordCount, Words: words}, nil
	case "binary":
		if len(raw) < 9 {
			return nil, fmt.Errorf("pithhash: binary stream is shorter than its 9-byte header")
		}
		chunkCount := int(be64(raw, 1))
		payload := raw[9:]
		if chunkCount != len(payload) || len(payload)%32 != 0 {
			return nil, fmt.Errorf("pithhash: binary chunk count disagrees with the payload")
		}
		return &Sig{Modality: modality, ChunkCount: chunkCount, DigestBytes: append([]byte(nil), payload...)}, nil
	default: // video
		if len(raw) < 21 {
			return nil, fmt.Errorf("pithhash: video stream is shorter than its 21-byte header")
		}
		frameCount := int(be32(raw, 1))
		width := be32(raw, 5)
		height := be32(raw, 9)
		durationBits := be64(raw, 13)
		rest := raw[21:]
		if frameCount > len(rest) || frameCount%8 != 0 {
			return nil, fmt.Errorf("pithhash: video frame count disagrees with the payload")
		}
		framesPayload := rest[:frameCount]
		minhashPayload := rest[frameCount:]
		if len(minhashPayload)%8 != 0 {
			return nil, fmt.Errorf("pithhash: video minhash payload is not whole words")
		}
		frameHashes := make([]uint64, 0, len(framesPayload)/8)
		for i := 0; i < len(framesPayload); i += 8 {
			frameHashes = append(frameHashes, binary.LittleEndian.Uint64(framesPayload[i:]))
		}
		minhash := make([]uint64, 0, len(minhashPayload)/8)
		for i := 0; i < len(minhashPayload); i += 8 {
			minhash = append(minhash, binary.LittleEndian.Uint64(minhashPayload[i:]))
		}
		return &Sig{
			Modality: modality, FrameCount: frameCount, Width: width, Height: height,
			DurationBits: durationBits, FrameHashes: frameHashes, Minhash: minhash,
		}, nil
	}
}

// factsLen is the byte size of each modality's facts block, which
// always terminates a describe stream.
func factsLen(modality string) int {
	switch modality {
	case "image":
		return 16
	case "audio":
		return 18
	case "text":
		return 16
	case "binary":
		return 16
	default: // video
		return 24
	}
}

// ParseDescribe re-expresses the canonical describe stream.
func ParseDescribe(raw []byte) (*Description, error) {
	if len(raw) < 35 {
		return nil, fmt.Errorf("pithhash: describe stream is shorter than its 35-byte header")
	}
	fmtCode, modCode := raw[0], raw[1]
	if int(fmtCode) >= len(Formats) || int(modCode) >= len(Modalities) {
		return nil, fmt.Errorf("pithhash: unknown describe codes %d/%d", fmtCode, modCode)
	}
	tier1 := fmt.Sprintf("%x", raw[2:34])
	modality := Modalities[modCode]
	// The facts block terminates the stream; its size is known from
	// the modality code, so the signature stream is the exact middle
	// slice (a bare ParseSignature would see the facts as payload).
	sigEnd := len(raw) - factsLen(modality)
	sig, err := ParseSignature(raw[34:sigEnd])
	if err != nil {
		return nil, err
	}
	factsRaw := raw[sigEnd:]
	facts := map[string]uint64{}
	need := func(n int) error {
		if len(factsRaw) != n {
			return fmt.Errorf("pithhash: facts block is %d bytes, want %d", len(factsRaw), n)
		}
		return nil
	}
	switch modality {
	case "image":
		if err := need(16); err != nil {
			return nil, err
		}
		facts["width"] = uint64(be32(factsRaw, 0))
		facts["height"] = uint64(be32(factsRaw, 4))
		facts["keypoints"] = be64(factsRaw, 8)
	case "audio":
		if err := need(18); err != nil {
			return nil, err
		}
		facts["sample_rate"] = uint64(be32(factsRaw, 0))
		facts["channels"] = uint64(be16(factsRaw, 4))
		facts["frames"] = uint64(be32(factsRaw, 6))
		facts["peaks"] = be64(factsRaw, 10)
	case "text":
		if err := need(16); err != nil {
			return nil, err
		}
		facts["words"] = be64(factsRaw, 0)
		facts["canonical_len"] = be64(factsRaw, 8)
	case "binary":
		if err := need(16); err != nil {
			return nil, err
		}
		facts["len"] = be64(factsRaw, 0)
		facts["chunks"] = be64(factsRaw, 8)
	default: // video
		if err := need(24); err != nil {
			return nil, err
		}
		facts["width"] = uint64(be32(factsRaw, 0))
		facts["height"] = uint64(be32(factsRaw, 4))
		facts["duration_bits"] = be64(factsRaw, 8)
		facts["frames_sampled"] = be64(factsRaw, 16)
	}
	return &Description{Format: Formats[fmtCode], Modality: modality, Tier1: tier1, Sig: sig, Facts: facts}, nil
}
