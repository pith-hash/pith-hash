package hash.pith;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/** Java bindings for {@code pith-hash}: the curator over the suite
 * cdylib — content sniffing ({@link #detect(byte[])}), tier-2
 * signatures ({@link #signature(byte[])}), tier-1 content hashes
 * ({@link #contentHash(byte[])}), similarity outcomes
 * ({@link #match(byte[], byte[])}) and descriptions
 * ({@link #describe(byte[])}).
 *
 * <p>The tier-2 signature and description return values are the
 * <dfn>canonical streams</dfn> the {@code reference.json} vectors are
 * defined over; the nested classes unpack them field by field.
 * Refusals throw {@link PithFfiException}, never crash the JVM.
 *
 * <p>The cdylib is resolved once per process — {@code PITH_CDYLIB}
 * (explicit file), {@code PITH_CDYLIB_DIR} (directory, relative
 * resolves against the working directory and its ancestors), then the
 * {@code target/release} of a repository checkout — and loaded with
 * {@link System#load}.
 */
public final class PithHash {
    /** Status: success. */
    public static final int PITH_OK = 0;
    /** Status: a caller argument is invalid. */
    public static final int PITH_E_INVALID = -1;
    /** Status: the core decoder refused the input. */
    public static final int PITH_E_REJECTED = -2;

    /** Format wire codes: the {@code pith_digest::Format} declaration order. */
    public static final int FORMAT_PNG = 0;
    /** See {@link #FORMAT_PNG}. */
    public static final int FORMAT_JPEG = 1;
    /** See {@link #FORMAT_PNG}. */
    public static final int FORMAT_BMP = 2;
    /** See {@link #FORMAT_PNG}. */
    public static final int FORMAT_ZIP = 3;
    /** See {@link #FORMAT_PNG}. */
    public static final int FORMAT_MP4 = 4;
    /** See {@link #FORMAT_PNG}. */
    public static final int FORMAT_MP3 = 5;
    /** See {@link #FORMAT_PNG}. */
    public static final int FORMAT_WAV = 6;
    /** See {@link #FORMAT_PNG}. */
    public static final int FORMAT_FLAC = 7;
    /** See {@link #FORMAT_PNG}. */
    public static final int FORMAT_PDF = 8;
    /** See {@link #FORMAT_PNG}. */
    public static final int FORMAT_GIF = 9;
    /** See {@link #FORMAT_PNG}. */
    public static final int FORMAT_UNKNOWN = 10;

    /** Modality wire codes: the declaration order. */
    public static final int MODALITY_IMAGE = 0;
    /** See {@link #MODALITY_IMAGE}. */
    public static final int MODALITY_AUDIO = 1;
    /** See {@link #MODALITY_IMAGE}. */
    public static final int MODALITY_TEXT = 2;
    /** See {@link #MODALITY_IMAGE}. */
    public static final int MODALITY_BINARY = 3;
    /** See {@link #MODALITY_IMAGE}. */
    public static final int MODALITY_VIDEO = 4;

    /** Match-outcome tags: the declaration order. */
    public static final int MATCH_IMAGE = 0;
    /** See {@link #MATCH_IMAGE}. */
    public static final int MATCH_AUDIO = 1;
    /** See {@link #MATCH_IMAGE}. */
    public static final int MATCH_TEXT = 2;
    /** See {@link #MATCH_IMAGE}. */
    public static final int MATCH_BINARY = 3;
    /** See {@link #MATCH_IMAGE}. */
    public static final int MATCH_VIDEO = 4;

    private static final String CDYLIB = PithNative.findCdylib("pith_hash");

    static {
        System.load(CDYLIB);
    }

    private PithHash() {
    }

    /** Sniffs the input for a known container magic and hands back the
     * wire triple {@code [format, modality, pending]}.
     *
     * @param input the complete file bytes
     * @return three ints: a {@code FORMAT_*} code, a {@code MODALITY_*}
     *         code, and {@code 1} when the format's crate has not landed
     * @throws PithFfiException {@code -1} on a null input array */
    public static native int[] detect(byte[] input);

    /** Signs the input into the canonical tier-2 stream.
     *
     * @param input the complete file bytes
     * @return the canonical signature stream ({@link Signature#parse}
     *         unpacks it)
     * @throws PithFfiException {@code -1} on a null input array,
     *         {@code -2} when the codec refuses the input */
    public static native byte[] signature(byte[] input);

    /** Describes the input: tier-1 digest, tier-2 signature and facts.
     *
     * @param input the complete file bytes
     * @return the canonical description stream ({@link Description#parse}
     *         unpacks it)
     * @throws PithFfiException {@code -1} on a null input array,
     *         {@code -2} when the codec refuses the input */
    public static native byte[] describe(byte[] input);

    /** Matches two signatures.
     *
     * @param a the first complete file bytes
     * @param b the second complete file bytes
     * @return six longs {@code [tag, s0, s1, s2, s3, matched]} — the
     *         {@code u64} slot bits ride through as two's-complement
     *         longs ({@link MatchResult#parse} unpacks them)
     * @throws PithFfiException {@code -1} on a null input array,
     *         {@code -2} when the core refuses the pair (including a
     *         cross-modality match) */
    public static native long[] match(byte[] a, byte[] b);

    /** Hashes the input into the tier-1 content digest.
     *
     * @param input the complete file bytes
     * @return the raw 32-byte digest
     * @throws PithFfiException {@code -1} on a null input array,
     *         {@code -2} when the codec refuses the input */
    public static native byte[] contentHash(byte[] input);

    /** The parsed tier-2 signature stream: fields per modality, exactly
     * what the {@code reference.json} signature vectors pin. */
    public static final class Signature {
        /** The {@code MATCH_*} tag naming the variant. */
        public final int tag;
        /** Image: the 64-bit pHash. */
        public final long phash;
        /** Audio: number of peak bytes in the fold. */
        public final long peakCount;
        /** Audio: number of decoded frames. */
        public final long frames;
        /** Audio: the raw peak fold bytes. */
        public final byte[] peaksBytes;
        /** Text: BYTE length of the MinHash word fold. */
        public final long wordCount;
        /** Text: the MinHash words. */
        public final long[] words;
        /** Binary: number of digest bytes in the fold. */
        public final long chunkCount;
        /** Binary: the raw chunk-digest fold bytes. */
        public final byte[] digestBytes;
        /** Video: BYTE length of the frame fold. */
        public final long frameCount;
        /** Video: the frame pHashes (BE words). */
        public final long[] frameHashes;
        /** Video: the MinHash words (LE on the wire). */
        public final long[] minhash;
        /** Video: encoded width. */
        public final long width;
        /** Video: encoded height. */
        public final long height;
        /** Video: duration as the raw f64 bit pattern. */
        public final long durationBits;

        private Signature(int tag, long phash, long peakCount, long frames, byte[] peaksBytes,
                long wordCount, long[] words, long chunkCount, byte[] digestBytes,
                long frameCount, long[] frameHashes, long[] minhash, long width, long height,
                long durationBits) {
            this.tag = tag;
            this.phash = phash;
            this.peakCount = peakCount;
            this.frames = frames;
            this.peaksBytes = peaksBytes;
            this.wordCount = wordCount;
            this.words = words;
            this.chunkCount = chunkCount;
            this.digestBytes = digestBytes;
            this.frameCount = frameCount;
            this.frameHashes = frameHashes;
            this.minhash = minhash;
            this.width = width;
            this.height = height;
            this.durationBits = durationBits;
        }

        /** Unpacks the canonical signature stream. */
        public static Signature parse(byte[] wire) {
            ByteBuffer be = ByteBuffer.wrap(wire).order(ByteOrder.BIG_ENDIAN);
            int tag = wire[0] & 0xFF;
            switch (tag) {
                case MATCH_IMAGE: {
                    return new Signature(tag, be.getLong(1), 0, 0, null, 0, null, 0, null,
                            0, null, null, 0, 0, 0);
                }
                case MATCH_AUDIO: {
                    long peakCount = be.getLong(1);
                    long frames = be.getInt(9) & 0xFFFFFFFFL;
                    byte[] peaks = Arrays.copyOfRange(wire, 13, 13 + (int) peakCount);
                    return new Signature(tag, 0, peakCount, frames, peaks, 0, null, 0, null,
                            0, null, null, 0, 0, 0);
                }
                case MATCH_TEXT: {
                    // word_count is the BYTE length of the fold, the
                    // same unit the reference.json minhash_words field
                    // records; the words themselves are foldLen / 8.
                    long foldLen = be.getLong(1);
                    int n = (int) (foldLen / 8);
                    long[] words = new long[n];
                    for (int i = 0; i < n; i++) {
                        words[i] = be.getLong(9 + 8 * i);
                    }
                    return new Signature(tag, 0, 0, 0, null, foldLen, words, 0, null,
                            0, null, null, 0, 0, 0);
                }
                case MATCH_BINARY: {
                    long digestLen = be.getLong(1);
                    byte[] digests = Arrays.copyOfRange(wire, 9, 9 + (int) digestLen);
                    return new Signature(tag, 0, 0, 0, null, 0, null, digestLen, digests,
                            0, null, null, 0, 0, 0);
                }
                case MATCH_VIDEO: {
                    long foldLen = be.getInt(1) & 0xFFFFFFFFL;
                    long width = be.getInt(5) & 0xFFFFFFFFL;
                    long height = be.getInt(9) & 0xFFFFFFFFL;
                    long durationBits = be.getLong(13);
                    int framesOffset = 21;
                    int minhashOffset = framesOffset + (int) foldLen;
                    int frameCount = (int) foldLen / 8;
                    long[] frames = new long[frameCount];
                    ByteBuffer le = ByteBuffer.wrap(
                            Arrays.copyOfRange(wire, framesOffset, minhashOffset))
                            .order(ByteOrder.LITTLE_ENDIAN);
                    for (int i = 0; i < frameCount; i++) {
                        frames[i] = le.getLong(8 * i);
                    }
                    ByteBuffer leMinhash = ByteBuffer.wrap(
                            Arrays.copyOfRange(wire, minhashOffset, wire.length))
                            .order(ByteOrder.LITTLE_ENDIAN);
                    int minhashWords = (wire.length - minhashOffset) / 8;
                    long[] minhash = new long[minhashWords];
                    for (int i = 0; i < minhashWords; i++) {
                        minhash[i] = leMinhash.getLong(8 * i);
                    }
                    return new Signature(tag, 0, 0, 0, null, 0, null, 0, null,
                            foldLen, frames, minhash, width, height, durationBits);
                }
                default:
                    throw new IllegalArgumentException("unknown signature tag " + tag);
            }
        }

        /** The little-endian fold of {@link #words}. */
        public byte[] wordsLeFold() {
            return leFold(words);
        }

        /** The little-endian fold of {@link #frameHashes}. */
        public byte[] framesLeFold() {
            return leFold(frameHashes);
        }

        /** The little-endian fold of {@link #minhash}. */
        public byte[] minhashLeFold() {
            return leFold(minhash);
        }
    }

    /** The parsed description stream: format, modality, tier-1 digest,
     * the tier-2 signature and the modality's facts block. */
    public static final class Description {
        /** The {@code FORMAT_*} code. */
        public final int format;
        /** The {@code MODALITY_*} code. */
        public final int modality;
        /** The raw 32-byte tier-1 content digest. */
        public final byte[] tier1;
        /** The tier-2 signature. */
        public final Signature signature;
        /** Image facts. */
        public final long imageWidth;
        /** See {@link #imageWidth}. */
        public final long imageHeight;
        /** See {@link #imageWidth}. */
        public final long keypoints;
        /** Audio facts. */
        public final long sampleRate;
        /** See {@link #sampleRate}. */
        public final int channels;
        /** See {@link #sampleRate}. */
        public final long audioFrames;
        /** See {@link #sampleRate}. */
        public final long peaks;
        /** Text facts. */
        public final long textWords;
        /** See {@link #textWords}. */
        public final long canonicalLen;
        /** Binary facts. */
        public final long binaryLen;
        /** See {@link #binaryLen}. */
        public final long chunks;
        /** Video facts. */
        public final long videoWidth;
        /** See {@link #videoWidth}. */
        public final long videoHeight;
        /** See {@link #videoWidth}: duration as the raw f64 bit pattern. */
        public final long durationBits;
        /** See {@link #videoWidth}. */
        public final long framesSampled;

        private Description(int format, int modality, byte[] tier1, Signature signature,
                long imageWidth, long imageHeight, long keypoints,
                long sampleRate, int channels, long audioFrames, long peaks,
                long textWords, long canonicalLen,
                long binaryLen, long chunks,
                long videoWidth, long videoHeight, long durationBits, long framesSampled) {
            this.format = format;
            this.modality = modality;
            this.tier1 = tier1;
            this.signature = signature;
            this.imageWidth = imageWidth;
            this.imageHeight = imageHeight;
            this.keypoints = keypoints;
            this.sampleRate = sampleRate;
            this.channels = channels;
            this.audioFrames = audioFrames;
            this.peaks = peaks;
            this.textWords = textWords;
            this.canonicalLen = canonicalLen;
            this.binaryLen = binaryLen;
            this.chunks = chunks;
            this.videoWidth = videoWidth;
            this.videoHeight = videoHeight;
            this.durationBits = durationBits;
            this.framesSampled = framesSampled;
        }

        /** Unpacks the canonical description stream. */
        public static Description parse(byte[] wire) {
            ByteBuffer be = ByteBuffer.wrap(wire).order(ByteOrder.BIG_ENDIAN);
            int format = wire[0] & 0xFF;
            int modality = wire[1] & 0xFF;
            byte[] tier1 = Arrays.copyOfRange(wire, 2, 34);
            // The facts block terminates the stream; its size is known
            // from the modality code, so the signature stream is the
            // exact middle slice (a bare parse would see the facts as
            // payload).
            int factsLen;
            switch (modality) {
                case MODALITY_AUDIO: factsLen = 18; break;
                case MODALITY_VIDEO: factsLen = 24; break;
                default: factsLen = 16; break;
            }
            int f = wire.length - factsLen;
            Signature signature = Signature.parse(Arrays.copyOfRange(wire, 34, f));
            switch (modality) {
                case MODALITY_IMAGE:
                    return new Description(format, modality, tier1, signature,
                            be.getInt(f) & 0xFFFFFFFFL, be.getInt(f + 4) & 0xFFFFFFFFL,
                            be.getLong(f + 8),
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                case MODALITY_AUDIO:
                    return new Description(format, modality, tier1, signature,
                            0, 0, 0,
                            be.getInt(f) & 0xFFFFFFFFL, be.getShort(f + 4) & 0xFFFF,
                            be.getInt(f + 6) & 0xFFFFFFFFL, be.getLong(f + 10),
                            0, 0, 0, 0, 0, 0, 0, 0);
                case MODALITY_TEXT:
                    return new Description(format, modality, tier1, signature,
                            0, 0, 0, 0, 0, 0, 0,
                            be.getLong(f), be.getLong(f + 8),
                            0, 0, 0, 0, 0, 0);
                case MODALITY_BINARY:
                    return new Description(format, modality, tier1, signature,
                            0, 0, 0, 0, 0, 0, 0, 0, 0,
                            be.getLong(f), be.getLong(f + 8),
                            0, 0, 0, 0);
                case MODALITY_VIDEO:
                    return new Description(format, modality, tier1, signature,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            be.getInt(f) & 0xFFFFFFFFL, be.getInt(f + 4) & 0xFFFFFFFFL,
                            be.getLong(f + 8), be.getLong(f + 16));
                default:
                    throw new IllegalArgumentException("unknown modality " + modality);
            }
        }
    }

    /** The flattened match outcome: tag, slot fields per kind, verdict. */
    public static final class MatchResult {
        /** The {@code MATCH_*} tag. */
        public final int tag;
        /** The raw slot bits (two's-complement longs). */
        public final long[] slots;
        /** The advisory verdict. */
        public final boolean matched;

        private MatchResult(int tag, long[] slots, boolean matched) {
            this.tag = tag;
            this.slots = slots;
            this.matched = matched;
        }

        /** Unpacks the six-long wire vector. */
        public static MatchResult parse(long[] wire) {
            if (wire.length != 6) {
                throw new IllegalArgumentException("match wire must carry 6 longs");
            }
            long[] slots = Arrays.copyOfRange(wire, 1, 5);
            return new MatchResult((int) wire[0], slots, wire[5] != 0);
        }
    }

    /** The standard FNV-1a 64-bit hash: offset basis
     * {@code 0xcbf29ce484222325}, prime {@code 0x100000001b3} — the
     * algorithm the recorded fold {@code *_fnv1a64} fields use. */
    public static long fnv1a64(byte[] data) {
        long hash = 0xCBF29CE484222325L;
        for (byte b : data) {
            hash = (hash ^ (b & 0xFF)) * 0x100000001B3L;
        }
        return hash;
    }

    /** The canonical word fold: little-endian words concatenated. */
    public static byte[] leFold(long[] words) {
        ByteBuffer le = ByteBuffer.allocate(words.length * 8).order(ByteOrder.LITTLE_ENDIAN);
        for (long word : words) {
            le.putLong(word);
        }
        return le.array();
    }

    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xF, 16));
            out.append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }

    static String hex16(long value) {
        return String.format("%016x", value);
    }
}
