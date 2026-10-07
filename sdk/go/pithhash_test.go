// SPDX-License-Identifier: MIT
// Copyright (c) 2026 pith-hash

package pithhash

// Hex-exact conformance: the committed reference vectors through the
// loaded cdylib. Every one of the 45 vectors in the repository-root
// reference.json is replayed and compared against every recorded field
// — detect codes, tier-2 sub-digests (recomputed SDK-side with the
// same folds the generator uses), tier-1 digests, facts and match
// slots. The same vectors the Rust `gen-reference verify` gate and the
// Python/Node SDKs check.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mask64 = uint64(0xFFFFFFFFFFFFFFFF)

type refVector = map[string]any

var (
	repoRoot = filepath.Join("..", "..")
)

func reference(t *testing.T) []refVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "reference.json"))
	if err != nil {
		t.Fatalf("reference.json: %v", err)
	}
	var doc struct {
		Vectors []refVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("reference.json: %v", err)
	}
	return doc.Vectors
}

func vectorMap(t *testing.T) map[string]refVector {
	t.Helper()
	m := make(map[string]refVector)
	for _, v := range reference(t) {
		m[v["name"].(string)] = v
	}
	return m
}

// ---------------------------------------------------------------------
// The deterministic inline corpus (transcribed from tools/gen-reference)
// ---------------------------------------------------------------------

type splitmix64 struct{ s uint64 }

func (r *splitmix64) next() uint64 {
	r.s += 0x9E3779B97F4A7C15
	z := r.s
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func splitmixBytes(seed uint64, length int) []byte {
	r := splitmix64{s: seed}
	out := make([]byte, length)
	for i := range out {
		out[i] = byte(r.next())
	}
	return out
}

func blob48(seed uint64) []byte { return splitmixBytes(seed, 48*1024) }

var vocab = [...]string{
	"hash", "image", "audio", "signal", "codec", "block", "frame", "sample", "stream",
	"vector", "median", "kernel", "window", "raster", "pixel", "tone", "hash", "luma",
	"delta", "chunk", "radix", "filter", "table", "edge",
}

func prose(seed uint64, size int) string {
	r := splitmix64{s: seed}
	out := make([]byte, 0, size+16)
	for len(out) < size {
		out = append(out, vocab[r.next()%uint64(len(vocab))]...)
		out = append(out, ' ')
	}
	return string(out[:size])
}

func patternedPixels(seed uint64, w, h uint32) []byte {
	r := splitmix64{s: seed}
	fx := float64(r.next()%5 + 1)
	fy := float64(r.next()%5 + 1)
	p1 := float64(r.next()%628) / 100.0
	p2 := float64(r.next()%628) / 100.0
	px := make([]byte, 0, int(w*h)*3)
	for y := uint32(0); y < h; y++ {
		for x := uint32(0); x < w; x++ {
			u := float64(x) / float64(w)
			v := float64(y) / float64(h)
			rv := 127.5 + 120.0*math.Sin(u*fx*(2*math.Pi)+p1)
			gv := 127.5 + 120.0*math.Sin(v*fy*(2*math.Pi)+p2)
			bv := 127.5 + 120.0*math.Sin((u+v)*(fx+fy)+p1+p2)
			px = append(px, byte(int64(rv)), byte(int64(gv)), byte(int64(bv)))
		}
	}
	return px
}

func bmp24(w, h uint32, rgb []byte) []byte {
	if int(w*h)*3 != len(rgb) {
		panic("bmp24: pixel count")
	}
	row := (int(w)*3 + 3) / 4 * 4
	img := row * int(h)
	f := make([]byte, 0, 54+img)
	le := func(v uint32) { f = append(f, byte(v), byte(v>>8), byte(v>>16), byte(v>>24)) }
	f = append(f, 'B', 'M')
	le(uint32(54 + img))
	f = append(f, 0, 0, 0, 0)
	le(54)
	le(40)
	le(w)
	le(h)
	f = append(f, 1, 0, 24, 0)
	f = append(f, make([]byte, 24)...)
	for y := int(h) - 1; y >= 0; y-- {
		for x := uint32(0); x < w; x++ {
			i := (y*int(w) + int(x)) * 3
			f = append(f, rgb[i+2], rgb[i+1], rgb[i])
		}
		f = append(f, make([]byte, row-int(w)*3)...)
	}
	return f
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "tests", "fixtures", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return raw
}

func leWords(words []uint64) []byte {
	out := make([]byte, 0, len(words)*8)
	for _, w := range words {
		var b [8]byte
		encodeBinaryLittleEndian(w, b[:])
		out = append(out, b[:]...)
	}
	return out
}

func encodeBinaryLittleEndian(v uint64, out []byte) {
	for i := range out {
		out[i] = byte(v >> (8 * i))
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func recString(v refVector, key string) string { return v[key].(string) }
func recFloat(v refVector, key string) float64 { return v[key].(float64) }
func recBool(v refVector, key string) bool     { return v[key].(bool) }
func recString64(v refVector, key string) uint64 {
	s := v[key].(string)
	// Hash pins carry a `0x` prefix; bit-pattern pins do not.
	s = strings.TrimPrefix(s, "0x")
	n, err := strconvParseUint(s, 16)
	if err != nil {
		panic(err)
	}
	return n
}

func strconvParseUint(s string, base int) (uint64, error) {
	var v uint64
	for _, c := range []byte(s) {
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		default:
			return 0, fmt.Errorf("bad hex %q", s)
		}
		v = v*uint64(base) + d
	}
	return v, nil
}

// assertSignatureMatches compares a parsed stream against the recorded
// fold fields.
func assertSignatureMatches(t *testing.T, sig *Sig, rec refVector) {
	t.Helper()
	if sig.Modality != recString(rec, "modality") {
		t.Fatalf("modality %s, want %s", sig.Modality, recString(rec, "modality"))
	}
	switch sig.Modality {
	case "image":
		if sig.Phash != recString64(rec, "phash") {
			t.Fatalf("phash %#x, want %#x", sig.Phash, recString64(rec, "phash"))
		}
	case "audio":
		if sig.PeakCount != int(recFloat(rec, "peak_count")) {
			t.Fatalf("peak_count %d", sig.PeakCount)
		}
		if sig.Frames != uint32(recFloat(rec, "frames")) {
			t.Fatalf("frames %d", sig.Frames)
		}
		if Fnv1a64(sig.PeaksBytes) != recString64(rec, "peaks_fnv1a64") {
			t.Fatal("peaks fnv1a64 mismatch")
		}
		if sha256Hex(sig.PeaksBytes) != recString(rec, "peaks_sha256") {
			t.Fatal("peaks sha256 mismatch")
		}
	case "text":
		if sig.WordCount != int(recFloat(rec, "minhash_words")) {
			t.Fatalf("minhash_words %d", sig.WordCount)
		}
		fold := leWords(sig.Words)
		if len(fold) != sig.WordCount {
			t.Fatalf("word fold %d bytes, want %d", len(fold), sig.WordCount)
		}
		if Fnv1a64(fold) != recString64(rec, "minhash_fnv1a64") {
			t.Fatal("minhash fnv1a64 mismatch")
		}
	case "binary":
		if sig.ChunkCount != int(recFloat(rec, "chunk_count")) {
			t.Fatalf("chunk_count %d", sig.ChunkCount)
		}
		if Fnv1a64(sig.DigestBytes) != recString64(rec, "chunks_fnv1a64") {
			t.Fatal("chunks fnv1a64 mismatch")
		}
		if sha256Hex(sig.DigestBytes) != recString(rec, "chunks_sha256") {
			t.Fatal("chunks sha256 mismatch")
		}
	case "video":
		if sig.FrameCount != int(recFloat(rec, "frame_count")) {
			t.Fatalf("frame_count %d", sig.FrameCount)
		}
		framesFold := leWords(sig.FrameHashes)
		if Fnv1a64(framesFold) != recString64(rec, "frames_fnv1a64") {
			t.Fatal("frames fnv1a64 mismatch")
		}
		if sha256Hex(framesFold) != recString(rec, "frames_sha256") {
			t.Fatal("frames sha256 mismatch")
		}
		minhashFold := leWords(sig.Minhash)
		if len(minhashFold) != int(recFloat(rec, "minhash_words")) {
			t.Fatalf("minhash_words %d", len(minhashFold))
		}
		if Fnv1a64(minhashFold) != recString64(rec, "minhash_fnv1a64") {
			t.Fatal("minhash fnv1a64 mismatch")
		}
		if sig.Width != uint32(recFloat(rec, "width")) || sig.Height != uint32(recFloat(rec, "height")) {
			t.Fatalf("geometry %dx%d", sig.Width, sig.Height)
		}
		if fmt.Sprintf("%016x", sig.DurationBits) != recString(rec, "duration_bits") {
			t.Fatal("duration_bits mismatch")
		}
	}
}

// The corpus as gen-reference builds it.
type corpus struct {
	png48, gray40, pngBase, jpgBase        []byte
	wav, flac, mp3                         []byte
	mp4, mov, mp4v, pdf                    []byte
	bmpSynth, blob, blobShifted, blobOther []byte
	proseA, proseB                         []byte
}

func buildCorpus(t *testing.T) corpus {
	t.Helper()
	return corpus{
		png48:       fixture(t, "phash_rgb8_48x40.png"),
		gray40:      fixture(t, "phash_gray8_40x32.png"),
		pngBase:     fixture(t, "base_444.png"),
		jpgBase:     fixture(t, "base_444.jpg"),
		wav:         fixture(t, "tone.wav"),
		flac:        fixture(t, "tone.flac"),
		mp3:         fixture(t, "l3_short.mp3"),
		mp4:         fixture(t, "a_64x48.mp4"),
		mov:         fixture(t, "a_64x48.mov"),
		mp4v:        fixture(t, "e_mp4v.mp4"),
		pdf:         fixture(t, "text_page.pdf"),
		bmpSynth:    bmp24(48, 40, patternedPixels(0xBEEF0001, 48, 40)),
		blob:        blob48(0xD15E5EED),
		blobShifted: append([]byte{0xAA}, blob48(0xD15E5EED)...),
		blobOther:   blob48(0xBADC0FFE),
		proseA:      []byte(prose(0xD1, 4096)),
		proseB:      []byte(prose(0xD2, 4096)),
	}
}

func TestDetectVectors(t *testing.T) {
	vectors := vectorMap(t)
	c := buildCorpus(t)
	cases := []struct {
		name string
		data []byte
	}{
		{"detect-png", c.png48},
		{"detect-jpeg", c.jpgBase},
		{"detect-bmp", c.bmpSynth},
		{"detect-wav", c.wav},
		{"detect-flac", c.flac},
		{"detect-mp3", c.mp3},
		{"detect-mp4", c.mp4},
		{"detect-mov", c.mov},
		{"detect-pdf", c.pdf},
		{"detect-zip", []byte("PK\x03\x04\x14\x00\x00\x00\x00\x00")},
		{"detect-gif", []byte("GIF89a\x01\x00\x01\x00")},
		{"detect-text", []byte("just some words")},
		{"detect-binary", []byte{0x00, 0xff, 0x02, 0xfe}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := vectors[tc.name]
			d, err := Detect(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			if d.Format != recString(rec, "format") {
				t.Fatalf("format %s, want %s", d.Format, recString(rec, "format"))
			}
			if d.Modality != recString(rec, "modality") {
				t.Fatalf("modality %s, want %s", d.Modality, recString(rec, "modality"))
			}
			if d.Pending != recBool(rec, "pending") {
				t.Fatalf("pending %v", d.Pending)
			}
		})
	}
}

func TestSignatureVectors(t *testing.T) {
	vectors := vectorMap(t)
	c := buildCorpus(t)
	cases := []struct {
		name string
		data []byte
	}{
		{"sig-image-phash_rgb8_48x40", c.png48},
		{"sig-image-phash_gray8_40x32", c.gray40},
		{"sig-image-base_444-png", c.pngBase},
		{"sig-image-base_444-jpeg", c.jpgBase},
		{"sig-image-bmp-patterned-48x40", c.bmpSynth},
		{"sig-audio-tone-wav", c.wav},
		{"sig-audio-tone-flac", c.flac},
		{"sig-audio-l3_short-mp3", c.mp3},
		{"sig-text-prose-4kib", c.proseA},
		{"sig-binary-splitmix64-48kib", c.blob},
		{"sig-binary-splitmix64-48kib-prefix-insert", c.blobShifted},
		{"sig-binary-splitmix64-48kib-unrelated", c.blobOther},
		{"sig-video-a_64x48-mp4", c.mp4},
		{"sig-pdf-text_page", c.pdf},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := Signature(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			assertSignatureMatches(t, sig, vectors[tc.name])
		})
	}
}

func TestDescribeVectors(t *testing.T) {
	vectors := vectorMap(t)
	c := buildCorpus(t)
	cases := []struct {
		name string
		data []byte
	}{
		{"describe-image-phash_rgb8_48x40", c.png48},
		{"describe-image-bmp-patterned-48x40", c.bmpSynth},
		{"describe-audio-tone-wav", c.wav},
		{"describe-text-prose-4kib", c.proseA},
		{"describe-binary-splitmix64-48kib", c.blob},
		{"describe-video-a_64x48-mp4", c.mp4},
		{"describe-pdf-text_page", c.pdf},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := vectors[tc.name]
			d, err := Describe(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			if d.Format != recString(rec, "format") {
				t.Fatalf("format %s", d.Format)
			}
			if d.Modality != recString(rec, "modality") {
				t.Fatalf("modality %s", d.Modality)
			}
			if d.Tier1 != recString(rec, "tier1") {
				t.Fatalf("tier1 %s", d.Tier1)
			}
			assertSignatureMatches(t, d.Sig, rec)
			facts := rec["facts"].(map[string]any)
			for key, want := range facts {
				got, ok := d.Facts[key]
				if !ok {
					t.Fatalf("fact %s missing", key)
				}
				if key == "duration_bits" {
					if fmt.Sprintf("%016x", got) != want.(string) {
						t.Fatalf("fact %s = %016x, want %s", key, got, want)
					}
					continue
				}
				if got != uint64(want.(float64)) {
					t.Fatalf("fact %s = %d, want %v", key, got, want)
				}
			}
		})
	}
}

func TestMatchVectors(t *testing.T) {
	vectors := vectorMap(t)
	c := buildCorpus(t)
	cases := []struct {
		name string
		a, b []byte
		kind string
	}{
		{"match-image-self", c.png48, c.png48, "image"},
		{"match-image-distinct", c.png48, c.gray40, "image"},
		{"match-image-png-vs-jpeg-same-pixels", c.pngBase, c.jpgBase, "image"},
		{"match-audio-self", c.wav, c.wav, "audio"},
		{"match-text-self", c.proseA, c.proseA, "text"},
		{"match-text-distinct", c.proseA, c.proseB, "text"},
		{"match-binary-near-duplicate", c.blob, c.blobShifted, "binary"},
		{"match-binary-unrelated", c.blob, c.blobOther, "binary"},
		{"match-video-mp4-vs-mov", c.mp4, c.mov, "video"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := vectors[tc.name]
			r, err := MatchSignatures(tc.a, tc.b)
			if err != nil {
				t.Fatal(err)
			}
			if r.Tag != tc.kind {
				t.Fatalf("tag %s, want %s", r.Tag, tc.kind)
			}
			if r.Matched != recBool(rec, "matched") {
				t.Fatalf("matched %v", r.Matched)
			}
			switch tc.kind {
			case "image":
				if r.Slots[0] != uint64(recFloat(rec, "hamming")) {
					t.Fatalf("hamming %d", r.Slots[0])
				}
			case "audio":
				if votes, ok := rec["votes"]; ok && votes.(float64) != 0 {
					if r.Slots[0] != uint64(votes.(float64)) {
						t.Fatalf("votes %d", r.Slots[0])
					}
					if r.Slots[1] != uint64(recFloat(rec, "delta_t"))&mask64 {
						t.Fatalf("delta_t %d", r.Slots[1])
					}
				} else if r.Slots[0] != 0 {
					t.Fatalf("votes %d, want 0", r.Slots[0])
				}
			case "video":
				if fmt.Sprintf("%016x", r.Slots[0]) != recString(rec, "score_bits") {
					t.Fatal("score_bits mismatch")
				}
				if fmt.Sprintf("%016x", r.Slots[1]) != recString(rec, "minhash_jaccard_bits") {
					t.Fatal("minhash_jaccard_bits mismatch")
				}
			default: // text and binary both record jaccard bits
				if fmt.Sprintf("%016x", r.Slots[0]) != recString(rec, "jaccard_bits") {
					t.Fatal("jaccard_bits mismatch")
				}
			}
		})
	}
}

func TestPinnedRefusals(t *testing.T) {
	c := buildCorpus(t)

	// The cross-modality refusal is a pinned vector.
	if _, err := MatchSignatures(c.png48, c.proseA); err == nil {
		t.Fatal("cross-modality match must refuse")
	} else if ffi, ok := err.(*FfiError); !ok || ffi.Status != StatusRejected {
		t.Fatalf("cross-modality status %v", err)
	}

	// The non-AVC video track refusal is a pinned vector.
	if _, err := Signature(c.mp4v); err == nil {
		t.Fatal("mpeg4-part-2 must refuse")
	} else if ffi, ok := err.(*FfiError); !ok || ffi.Status != StatusRejected {
		t.Fatalf("mp4v status %v", err)
	}

	// Corrupt image and malformed pdf: rejected, never a crash.
	corrupt := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, []byte("garbage")...)
	if _, err := Signature(corrupt); err == nil {
		t.Fatal("corrupt png must refuse")
	}
	if _, err := Describe(corrupt); err == nil {
		t.Fatal("corrupt png describe must refuse")
	}
	if _, err := ContentHash(corrupt); err == nil {
		t.Fatal("corrupt png content hash must refuse")
	}
	if _, err := Signature([]byte("%PDF-1.4 garbage not a pdf")); err == nil {
		t.Fatal("malformed pdf must refuse")
	}
}

func TestContentHashLiteralPin(t *testing.T) {
	// text_page.pdf's tier-1 digest, derived once from the built cdylib
	// and pinned here so a wrongly regenerated reference.json cannot
	// mask drift. The same pin lives in the Python and Node harnesses.
	c := buildCorpus(t)
	digest, err := ContentHash(c.pdf)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 32 {
		t.Fatalf("digest %d bytes", len(digest))
	}
	const want = "849978a1682ba75372094611c8fc290b9c39b84d75641bf0b6129cdbaa880fa9"
	if hex.EncodeToString(digest) != want {
		t.Fatalf("pin %s, want %s", hex.EncodeToString(digest), want)
	}
}
