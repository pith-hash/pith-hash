package hash.pith;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/** Hex-exact conformance: all 45 committed reference vectors through
 * the real JVM and the suite cdylib — the Java port of the Python
 * {@code test_reference_vectors.py}, assertion for assertion.
 *
 * <p>detect (13 vectors): format/modality/pending codes. signature
 * (14): every fold recomputed SDK-side. describe (7): tier-1 hex,
 * signature re-assert and every facts field. match (9): tag, verdict
 * and per-kind slots, plus the pinned cross-modality refusal. Errors:
 * non-AVC video, corrupt PNG and malformed PDF refusals, and the
 * frozen tier-1 literal pin.
 */
class ReferenceVectorsTest {
    private static final Path REPO_ROOT = PithNative.repoRoot();

    private static final Map<String, JsonObject> VECTORS = vectors();

    private static Map<String, JsonObject> vectors() {
        Map<String, JsonObject> out = new LinkedHashMap<>();
        JsonObject reference;
        try {
            reference = JsonParser.parseString(
                    Files.readString(REPO_ROOT.resolve("reference.json"))).getAsJsonObject();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        for (JsonElement element : reference.getAsJsonArray("vectors")) {
            JsonObject vector = element.getAsJsonObject();
            out.put(vector.get("name").getAsString(), vector);
        }
        return out;
    }

    private static byte[] fixture(String name) {
        try {
            return Files.readAllBytes(REPO_ROOT.resolve("tests").resolve("fixtures").resolve(name));
        } catch (Exception e) {
            throw new IllegalStateException(name, e);
        }
    }

    private static String sha256Hex(byte[] data) {
        try {
            return PithHash.hex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------
    // The deterministic inline corpus (transcribed from tools/gen-reference)
    // ------------------------------------------------------------------

    /** The 64-bit generator behind every inline recipe. */
    private static final class SplitMix64 {
        private long state;

        SplitMix64(long seed) {
            this.state = seed;
        }

        long nextU64() {
            state += 0x9E3779B97F4A7C15L;
            long z = state;
            z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
            z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
            return z ^ (z >>> 31);
        }
    }

    private static byte[] splitmixBytes(long seed, int length) {
        SplitMix64 rng = new SplitMix64(seed);
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) rng.nextU64();
        }
        return out;
    }

    private static byte[] blob48(long seed) {
        return splitmixBytes(seed, 48 * 1024);
    }

    private static final String[] VOCAB = {
        "hash", "image", "audio", "signal", "codec", "block", "frame", "sample", "stream",
        "vector", "median", "kernel", "window", "raster", "pixel", "tone", "hash", "luma",
        "delta", "chunk", "radix", "filter", "table", "edge",
    };

    private static String prose(long seed, int size) {
        SplitMix64 rng = new SplitMix64(seed);
        StringBuilder out = new StringBuilder();
        while (out.length() < size) {
            out.append(VOCAB[(int) (Long.remainderUnsigned(rng.nextU64(), VOCAB.length))]);
            out.append(' ');
        }
        return out.substring(0, size);
    }

    private static byte[] patternedPixels(long seed, int w, int h) {
        SplitMix64 rng = new SplitMix64(seed);
        double fx = Math.floorMod(rng.nextU64(), 5) + 1;
        double fy = Math.floorMod(rng.nextU64(), 5) + 1;
        double p1 = Math.floorMod(rng.nextU64(), 628) / 100.0;
        double p2 = Math.floorMod(rng.nextU64(), 628) / 100.0;
        byte[] px = new byte[w * h * 3];
        int i = 0;
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                double u = (double) x / w;
                double v = (double) y / h;
                double r = 127.5 + 120.0 * StrictMath.sin(u * fx * (2 * Math.PI) + p1);
                double g = 127.5 + 120.0 * StrictMath.sin(v * fy * (2 * Math.PI) + p2);
                double b = 127.5 + 120.0 * StrictMath.sin((u + v) * (fx + fy) + p1 + p2);
                px[i++] = (byte) (int) r;
                px[i++] = (byte) (int) g;
                px[i++] = (byte) (int) b;
            }
        }
        return px;
    }

    /** Bottom-up 24-bit BMP — the suite's deterministic fixture encoder. */
    private static byte[] bmp24(int w, int h, byte[] rgb) {
        if (w * h * 3 != rgb.length) {
            throw new IllegalArgumentException("bmp24: pixel count");
        }
        int row = (w * 3 + 3) / 4 * 4;
        int img = row * h;
        byte[] f = new byte[54 + img];
        int o = 0;
        f[o++] = 'B';
        f[o++] = 'M';
        o = le32(f, o, 54 + img);
        o += 4; // reserved
        o = le32(f, o, 54);
        o = le32(f, o, 40);
        o = le32(f, o, w);
        o = le32(f, o, h);
        f[o++] = 1;
        f[o++] = 0;
        f[o++] = 24;
        f[o++] = 0;
        o += 24; // zeroed BI fields
        for (int y = h - 1; y >= 0; y--) {
            for (int x = 0; x < w; x++) {
                int i = (y * w + x) * 3;
                f[o++] = rgb[i + 2];
                f[o++] = rgb[i + 1];
                f[o++] = rgb[i];
            }
            o += row - w * 3;
        }
        return f;
    }

    private static int le32(byte[] f, int o, int v) {
        f[o] = (byte) v;
        f[o + 1] = (byte) (v >> 8);
        f[o + 2] = (byte) (v >> 16);
        f[o + 3] = (byte) (v >> 24);
        return o + 4;
    }

    private static final byte[] PNG48 = fixture("phash_rgb8_48x40.png");
    private static final byte[] GRAY40 = fixture("phash_gray8_40x32.png");
    private static final byte[] PNG_BASE = fixture("base_444.png");
    private static final byte[] JPG_BASE = fixture("base_444.jpg");
    private static final byte[] WAV = fixture("tone.wav");
    private static final byte[] FLAC = fixture("tone.flac");
    private static final byte[] MP3 = fixture("l3_short.mp3");
    private static final byte[] MP4 = fixture("a_64x48.mp4");
    private static final byte[] MOV = fixture("a_64x48.mov");
    private static final byte[] MP4V = fixture("e_mp4v.mp4");
    private static final byte[] PDF = fixture("text_page.pdf");

    private static final byte[] BMP_SYNTH = bmp24(48, 40, patternedPixels(0xBEEF0001L, 48, 40));
    private static final byte[] BLOB = blob48(0xD15E5EEDL);
    private static final byte[] BLOB_SHIFTED = concat(new byte[] {(byte) 0xaa}, blob48(0xD15E5EEDL));
    private static final byte[] BLOB_OTHER = blob48(0xBADC0FFEL);
    private static final byte[] PROSE_A = prose(0xD1, 4096).getBytes(StandardCharsets.UTF_8);
    private static final byte[] PROSE_B = prose(0xD2, 4096).getBytes(StandardCharsets.UTF_8);

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static final byte[] ZIP_MAGIC = {0x50, 0x4B, 0x03, 0x04, 0x14, 0, 0, 0, 0, 0};
    private static final byte[] GIF_MAGIC = {'G', 'I', 'F', '8', '9', 'a', 1, 0, 1, 0};
    private static final byte[] TEXT_BYTES = "just some words".getBytes(StandardCharsets.UTF_8);
    private static final byte[] BINARY_BYTES = {0x00, (byte) 0xff, 0x02, (byte) 0xfe};

    private static int formatCode(String format) {
        switch (format) {
            case "png": return PithHash.FORMAT_PNG;
            case "jpeg": return PithHash.FORMAT_JPEG;
            case "bmp": return PithHash.FORMAT_BMP;
            case "zip": return PithHash.FORMAT_ZIP;
            case "mp4": return PithHash.FORMAT_MP4;
            case "mp3": return PithHash.FORMAT_MP3;
            case "wav": return PithHash.FORMAT_WAV;
            case "flac": return PithHash.FORMAT_FLAC;
            case "pdf": return PithHash.FORMAT_PDF;
            case "gif": return PithHash.FORMAT_GIF;
            case "unknown": return PithHash.FORMAT_UNKNOWN;
            default: throw new IllegalArgumentException(format);
        }
    }

    private static int modalityCode(String modality) {
        switch (modality) {
            case "image": return PithHash.MODALITY_IMAGE;
            case "audio": return PithHash.MODALITY_AUDIO;
            case "text": return PithHash.MODALITY_TEXT;
            case "binary": return PithHash.MODALITY_BINARY;
            case "video": return PithHash.MODALITY_VIDEO;
            default: throw new IllegalArgumentException(modality);
        }
    }

    private static int matchCode(String outcome) {
        switch (outcome) {
            case "image": return PithHash.MATCH_IMAGE;
            case "audio": return PithHash.MATCH_AUDIO;
            case "text": return PithHash.MATCH_TEXT;
            case "binary": return PithHash.MATCH_BINARY;
            case "video": return PithHash.MATCH_VIDEO;
            default: throw new IllegalArgumentException(outcome);
        }
    }

    // ------------------------------------------------------------------
    // detect: 13 vectors, every recorded field
    // ------------------------------------------------------------------

    @Test
    void detectVectors() {
        Map<String, byte[]> inputs = new LinkedHashMap<>();
        inputs.put("detect-png", PNG48);
        inputs.put("detect-jpeg", JPG_BASE);
        inputs.put("detect-bmp", BMP_SYNTH);
        inputs.put("detect-wav", WAV);
        inputs.put("detect-flac", FLAC);
        inputs.put("detect-mp3", MP3);
        inputs.put("detect-mp4", MP4);
        inputs.put("detect-mov", MOV);
        inputs.put("detect-pdf", PDF);
        inputs.put("detect-zip", ZIP_MAGIC);
        inputs.put("detect-gif", GIF_MAGIC);
        inputs.put("detect-text", TEXT_BYTES);
        inputs.put("detect-binary", BINARY_BYTES);
        assertEquals(13, inputs.size());
        for (String name : new TreeSet<>(inputs.keySet())) {
            JsonObject rec = VECTORS.get(name);
            int[] codes = PithHash.detect(inputs.get(name));
            assertEquals(formatCode(rec.get("format").getAsString()), codes[0], name);
            assertEquals(modalityCode(rec.get("modality").getAsString()), codes[1], name);
            assertEquals(rec.get("pending").getAsBoolean(), codes[2] != 0, name);
            // The wire codes are the declaration orders the constants name.
            assertTrue(codes[0] >= PithHash.FORMAT_PNG && codes[0] <= PithHash.FORMAT_UNKNOWN, name);
            assertTrue(codes[1] >= PithHash.MODALITY_IMAGE && codes[1] <= PithHash.MODALITY_VIDEO,
                    name);
        }
    }

    // ------------------------------------------------------------------
    // signature: 14 vectors, every fold recomputed SDK-side
    // ------------------------------------------------------------------

    private void assertSignatureMatches(PithHash.Signature sig, JsonObject rec, String name) {
        assertEquals(modalityCode(rec.get("modality").getAsString()), sig.tag, name);
        switch (sig.tag) {
            case PithHash.MODALITY_IMAGE:
                assertEquals(Long.parseUnsignedLong(
                        rec.get("phash").getAsString().replaceFirst("^0x", ""), 16),
                        sig.phash, name);
                break;
            case PithHash.MODALITY_AUDIO:
                assertEquals(rec.get("peak_count").getAsLong(), sig.peakCount, name);
                assertEquals(rec.get("frames").getAsLong(), sig.frames, name);
                assertEquals(Long.parseUnsignedLong(rec.get("peaks_fnv1a64").getAsString(), 16),
                        PithHash.fnv1a64(sig.peaksBytes), name);
                assertEquals(rec.get("peaks_sha256").getAsString(),
                        sha256Hex(sig.peaksBytes), name);
                break;
            case PithHash.MODALITY_TEXT:
                assertEquals(rec.get("minhash_words").getAsLong(), sig.wordCount, name);
                byte[] fold = PithHash.leFold(sig.words);
                assertEquals(sig.wordCount, fold.length, name);
                assertEquals(Long.parseUnsignedLong(rec.get("minhash_fnv1a64").getAsString(), 16),
                        PithHash.fnv1a64(fold), name);
                break;
            case PithHash.MODALITY_BINARY:
                assertEquals(rec.get("chunk_count").getAsLong(), sig.chunkCount, name);
                assertEquals(Long.parseUnsignedLong(rec.get("chunks_fnv1a64").getAsString(), 16),
                        PithHash.fnv1a64(sig.digestBytes), name);
                assertEquals(rec.get("chunks_sha256").getAsString(),
                        sha256Hex(sig.digestBytes), name);
                break;
            case PithHash.MODALITY_VIDEO:
                assertEquals(rec.get("frame_count").getAsLong(), sig.frameCount, name);
                byte[] framesFold = PithHash.leFold(sig.frameHashes);
                assertEquals(sig.frameCount, framesFold.length, name);
                assertEquals(Long.parseUnsignedLong(rec.get("frames_fnv1a64").getAsString(), 16),
                        PithHash.fnv1a64(framesFold), name);
                assertEquals(rec.get("frames_sha256").getAsString(),
                        sha256Hex(framesFold), name);
                // minhash_words is recorded as the BYTE fold length.
                assertEquals(rec.get("minhash_words").getAsLong(), sig.minhash.length * 8L, name);
                assertEquals(Long.parseUnsignedLong(rec.get("minhash_fnv1a64").getAsString(), 16),
                        PithHash.fnv1a64(PithHash.leFold(sig.minhash)), name);
                assertEquals(rec.get("width").getAsLong(), sig.width, name);
                assertEquals(rec.get("height").getAsLong(), sig.height, name);
                assertEquals(rec.get("duration_bits").getAsString(),
                        PithHash.hex16(sig.durationBits), name);
                break;
            default:
                throw new IllegalArgumentException("unknown tag " + sig.tag);
        }
    }

    @Test
    void signatureVectors() {
        Map<String, byte[]> inputs = new LinkedHashMap<>();
        inputs.put("sig-image-phash_rgb8_48x40", PNG48);
        inputs.put("sig-image-phash_gray8_40x32", GRAY40);
        inputs.put("sig-image-base_444-png", PNG_BASE);
        inputs.put("sig-image-base_444-jpeg", JPG_BASE);
        inputs.put("sig-image-bmp-patterned-48x40", BMP_SYNTH);
        inputs.put("sig-audio-tone-wav", WAV);
        inputs.put("sig-audio-tone-flac", FLAC);
        inputs.put("sig-audio-l3_short-mp3", MP3);
        inputs.put("sig-text-prose-4kib", PROSE_A);
        inputs.put("sig-binary-splitmix64-48kib", BLOB);
        inputs.put("sig-binary-splitmix64-48kib-prefix-insert", BLOB_SHIFTED);
        inputs.put("sig-binary-splitmix64-48kib-unrelated", BLOB_OTHER);
        inputs.put("sig-video-a_64x48-mp4", MP4);
        inputs.put("sig-pdf-text_page", PDF);
        assertEquals(14, inputs.size());
        for (String name : new TreeSet<>(inputs.keySet())) {
            assertSignatureMatches(
                    PithHash.Signature.parse(PithHash.signature(inputs.get(name))),
                    VECTORS.get(name), name);
        }
    }

    // ------------------------------------------------------------------
    // describe: 7 vectors, tier 1 + folds + facts
    // ------------------------------------------------------------------

    @Test
    void describeVectors() {
        Map<String, byte[]> inputs = new LinkedHashMap<>();
        inputs.put("describe-image-phash_rgb8_48x40", PNG48);
        inputs.put("describe-image-bmp-patterned-48x40", BMP_SYNTH);
        inputs.put("describe-audio-tone-wav", WAV);
        inputs.put("describe-text-prose-4kib", PROSE_A);
        inputs.put("describe-binary-splitmix64-48kib", BLOB);
        inputs.put("describe-video-a_64x48-mp4", MP4);
        inputs.put("describe-pdf-text_page", PDF);
        assertEquals(7, inputs.size());
        for (String name : new TreeSet<>(inputs.keySet())) {
            JsonObject rec = VECTORS.get(name);
            PithHash.Description d =
                    PithHash.Description.parse(PithHash.describe(inputs.get(name)));
            assertEquals(formatCode(rec.get("format").getAsString()), d.format, name);
            assertEquals(modalityCode(rec.get("modality").getAsString()), d.modality, name);
            assertEquals(rec.get("tier1").getAsString(), PithHash.hex(d.tier1), name);
            assertSignatureMatches(d.signature, rec, name);
            JsonObject facts = rec.getAsJsonObject("facts");
            switch (d.modality) {
                case PithHash.MODALITY_IMAGE:
                    assertEquals(facts.get("width").getAsLong(), d.imageWidth, name);
                    assertEquals(facts.get("height").getAsLong(), d.imageHeight, name);
                    assertEquals(facts.get("keypoints").getAsLong(), d.keypoints, name);
                    break;
                case PithHash.MODALITY_AUDIO:
                    assertEquals(facts.get("sample_rate").getAsLong(), d.sampleRate, name);
                    assertEquals(facts.get("channels").getAsInt(), d.channels, name);
                    assertEquals(facts.get("frames").getAsLong(), d.audioFrames, name);
                    assertEquals(facts.get("peaks").getAsLong(), d.peaks, name);
                    break;
                case PithHash.MODALITY_TEXT:
                    assertEquals(facts.get("words").getAsLong(), d.textWords, name);
                    assertEquals(facts.get("canonical_len").getAsLong(), d.canonicalLen, name);
                    break;
                case PithHash.MODALITY_BINARY:
                    assertEquals(facts.get("len").getAsLong(), d.binaryLen, name);
                    assertEquals(facts.get("chunks").getAsLong(), d.chunks, name);
                    break;
                case PithHash.MODALITY_VIDEO:
                    assertEquals(facts.get("width").getAsLong(), d.videoWidth, name);
                    assertEquals(facts.get("height").getAsLong(), d.videoHeight, name);
                    assertEquals(facts.get("duration_bits").getAsString(),
                            PithHash.hex16(d.durationBits), name);
                    assertEquals(facts.get("frames_sampled").getAsLong(), d.framesSampled, name);
                    break;
                default:
                    throw new IllegalArgumentException("unknown modality " + d.modality);
            }
        }
    }

    // ------------------------------------------------------------------
    // match: 9 slot-exact outcome vectors + the cross-modality refusal
    // ------------------------------------------------------------------

    @Test
    void matchVectors() {
        Map<String, byte[][]> inputs = new LinkedHashMap<>();
        inputs.put("match-image-self", new byte[][] {PNG48, PNG48});
        inputs.put("match-image-distinct", new byte[][] {PNG48, GRAY40});
        inputs.put("match-image-png-vs-jpeg-same-pixels", new byte[][] {PNG_BASE, JPG_BASE});
        inputs.put("match-audio-self", new byte[][] {WAV, WAV});
        inputs.put("match-text-self", new byte[][] {PROSE_A, PROSE_A});
        inputs.put("match-text-distinct", new byte[][] {PROSE_A, PROSE_B});
        inputs.put("match-binary-near-duplicate", new byte[][] {BLOB, BLOB_SHIFTED});
        inputs.put("match-binary-unrelated", new byte[][] {BLOB, BLOB_OTHER});
        inputs.put("match-video-mp4-vs-mov", new byte[][] {MP4, MOV});
        assertEquals(9, inputs.size());
        for (String name : new TreeSet<>(inputs.keySet())) {
            JsonObject rec = VECTORS.get(name);
            PithHash.MatchResult r = PithHash.MatchResult.parse(
                    PithHash.match(inputs.get(name)[0], inputs.get(name)[1]));
            String outcome = rec.get("outcome").getAsString();
            if ("jaccard".equals(outcome)) {
                // Text and binary share the jaccard_bits record shape;
                // the wire tag names which one ran.
                assertTrue(r.tag == PithHash.MATCH_TEXT || r.tag == PithHash.MATCH_BINARY, name);
            } else {
                assertEquals(matchCode(outcome), r.tag, name);
            }
            assertEquals(rec.get("matched").getAsBoolean(), r.matched, name);
            switch (r.tag) {
                case PithHash.MATCH_IMAGE:
                    assertEquals(rec.get("hamming").getAsLong(), r.slots[0], name);
                    break;
                case PithHash.MATCH_AUDIO:
                    if (rec.has("votes") && rec.get("votes").getAsLong() != 0) {
                        assertEquals(rec.get("votes").getAsLong(), r.slots[0], name);
                        // delta_t rides as the two's-complement long.
                        assertEquals(rec.get("delta_t").getAsLong(), r.slots[1], name);
                    } else {
                        assertEquals(0L, r.slots[0], name);
                    }
                    break;
                case PithHash.MATCH_VIDEO:
                    assertEquals(rec.get("score_bits").getAsString(),
                            PithHash.hex16(r.slots[0]), name);
                    assertEquals(rec.get("minhash_jaccard_bits").getAsString(),
                            PithHash.hex16(r.slots[1]), name);
                    break;
                case PithHash.MATCH_TEXT:
                case PithHash.MATCH_BINARY:
                    assertEquals(rec.get("jaccard_bits").getAsString(),
                            PithHash.hex16(r.slots[0]), name);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag " + r.tag);
            }
        }
    }

    @Test
    void matchCrossModalityIsPinnedRefusal() {
        assertEquals("error", VECTORS.get("match-error-cross-modality").get("outcome").getAsString());
        PithFfiException thrown = assertThrows(PithFfiException.class,
                () -> PithHash.match(PNG48, PROSE_A));
        assertEquals(PithHash.PITH_E_REJECTED, thrown.getStatus());
    }

    // ------------------------------------------------------------------
    // error + refusals: rejected inputs never crash, they status
    // ------------------------------------------------------------------

    @Test
    void errorVideoNonAvcIsPinnedRefusal() {
        assertEquals("error", VECTORS.get("error-video-non-avc").get("outcome").getAsString());
        PithFfiException thrown = assertThrows(PithFfiException.class, () -> PithHash.signature(MP4V));
        assertEquals(PithHash.PITH_E_REJECTED, thrown.getStatus());
    }

    @Test
    void corruptImageIsRejected() {
        byte[] corrupt = concat(new byte[] {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
                "garbage".getBytes(StandardCharsets.UTF_8));
        assertEquals(PithHash.PITH_E_REJECTED,
                assertThrows(PithFfiException.class, () -> PithHash.signature(corrupt)).getStatus());
        assertEquals(PithHash.PITH_E_REJECTED,
                assertThrows(PithFfiException.class, () -> PithHash.describe(corrupt)).getStatus());
        assertEquals(PithHash.PITH_E_REJECTED,
                assertThrows(PithFfiException.class, () -> PithHash.contentHash(corrupt)).getStatus());
    }

    @Test
    void malformedPdfIsRejected() {
        assertEquals(PithHash.PITH_E_REJECTED,
                assertThrows(PithFfiException.class,
                        () -> PithHash.signature("%PDF-1.4 garbage not a pdf"
                                .getBytes(StandardCharsets.UTF_8))).getStatus());
    }

    // ------------------------------------------------------------------
    // The rust-derived literal pin: tier-1 of the smallest pinned fixture
    // ------------------------------------------------------------------

    @Test
    void contentHashLiteralPin() {
        assertEquals("1f7637f88725b1f3c1b60fb5559486349298b2a5525bac5fb1df196651e0cb74",
                PithHash.hex(PithHash.contentHash(PNG48)));
    }

    // ------------------------------------------------------------------

    @Test
    void cdylibIsDiscoverable() {
        assertTrue(Files.isRegularFile(Path.of(PithNative.findCdylib("pith_hash"))));
    }
}
