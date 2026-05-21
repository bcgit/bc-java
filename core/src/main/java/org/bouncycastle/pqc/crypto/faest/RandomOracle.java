package org.bouncycastle.pqc.crypto.faest;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Memoable;

/**
 * FAEST v2.0 random-oracle wrapper over SHAKE128 / SHAKE256.
 * <p>
 * The reference implementation defines five distinct oracle entry points
 * ({@code H_0} &hellip; {@code H_4}) plus four sub-variants of {@code H_2}.
 * All nine share the same construction:
 * <ol>
 *   <li>Initialise SHAKE128 if {@code lambda == 128}, else SHAKE256.</li>
 *   <li>Absorb the caller's input data.</li>
 *   <li>Absorb a one-byte domain-separation tag.</li>
 *   <li>Squeeze the requested output length(s).</li>
 * </ol>
 * Domain-separation tags (faest-ref {@code random_oracle.c}:12-19):
 * <ul>
 *   <li>{@link #DOMAIN_H0} = 0</li>
 *   <li>{@link #DOMAIN_H1} = 1</li>
 *   <li>{@link #DOMAIN_H2_0} = 8, {@link #DOMAIN_H2_1} = 9,
 *       {@link #DOMAIN_H2_2} = 10, {@link #DOMAIN_H2_3} = 11</li>
 *   <li>{@link #DOMAIN_H3} = 3</li>
 *   <li>{@link #DOMAIN_H4} = 4</li>
 * </ul>
 * <p>
 * Source of truth: faest-ref {@code random_oracle.c}.
 * <p>
 * The {@code H0_x4} / {@code H0_x4_*} four-way parallel API from the reference
 * is intentionally not ported: the C code's x4 path only matters when an SIMD
 * Keccak permutation is available (OQS / AVX2), and PQClean falls back to four
 * sequential SHAKE invocations otherwise. The Java port runs four sequential
 * SHAKEs directly, which is what the reference does without x4 acceleration.
 */
final class RandomOracle
{
    static final byte DOMAIN_H0   = 0;
    static final byte DOMAIN_H1   = 1;
    static final byte DOMAIN_H2_0 = 8;
    static final byte DOMAIN_H2_1 = 9;
    static final byte DOMAIN_H2_2 = 10;
    static final byte DOMAIN_H2_3 = 11;
    static final byte DOMAIN_H3   = 3;
    static final byte DOMAIN_H4   = 4;

    private final SHAKEDigest shake;

    /** Create a new oracle. {@code lambda} must be 128, 192 or 256. */
    RandomOracle(int lambda)
    {
        // faest-ref hash_shake.h: SHAKE128 only for lambda == 128, else SHAKE256.
        this.shake = new SHAKEDigest(lambda == 128 ? 128 : 256);
    }

    private RandomOracle(SHAKEDigest seed)
    {
        this.shake = seed;
    }

    /** Absorb {@code src[off..off+len]} into the sponge. */
    void absorb(byte[] src, int off, int len)
    {
        shake.update(src, off, len);
    }

    /** Convenience: absorb the entire array. */
    void absorb(byte[] src)
    {
        shake.update(src, 0, src.length);
    }

    /** Absorb a single byte (typically a domain-separation tag). */
    void absorbByte(byte b)
    {
        shake.update(b);
    }

    /**
     * Incrementally squeeze {@code len} bytes into {@code dst[off..off+len]}.
     * The first squeeze call implicitly finalises the absorb phase. Subsequent
     * calls continue the squeeze (the SHAKE state is preserved).
     */
    void squeeze(byte[] dst, int off, int len)
    {
        shake.doOutput(dst, off, len);
    }

    /**
     * Return an independent oracle whose absorbed state is identical to this
     * one's. Used by the reference's {@code H2_copy} pattern, where the same
     * partial transcript is squeezed under four different domain separators.
     * The returned oracle and this one are independent thereafter.
     */
    RandomOracle copy()
    {
        return new RandomOracle((SHAKEDigest)((Memoable)shake).copy());
    }

    // ----- One-shot helpers matching faest-ref random_oracle.c entry points. -----

    /**
     * H_0: absorb {@code src}, then squeeze a {@code seed} and a {@code commitment}.
     * <pre>
     *   H_0(lambda, src) = (seed || commitment)
     * </pre>
     * faest-ref: {@code H0_init} / {@code H0_update} / {@code H0_final}.
     */
    static void H0(int lambda, byte[] src, int srcOff, int srcLen,
                   byte[] seed, int seedOff, int seedLen,
                   byte[] commitment, int commitOff, int commitLen)
    {
        RandomOracle ro = new RandomOracle(lambda);
        ro.absorb(src, srcOff, srcLen);
        ro.absorbByte(DOMAIN_H0);
        ro.squeeze(seed, seedOff, seedLen);
        ro.squeeze(commitment, commitOff, commitLen);
    }

    /**
     * H_1: absorb {@code src}, squeeze {@code digest}.
     * faest-ref: {@code H1_init} / {@code H1_update} / {@code H1_final}.
     */
    static void H1(int lambda, byte[] src, int srcOff, int srcLen,
                   byte[] digest, int digestOff, int digestLen)
    {
        RandomOracle ro = new RandomOracle(lambda);
        ro.absorb(src, srcOff, srcLen);
        ro.absorbByte(DOMAIN_H1);
        ro.squeeze(digest, digestOff, digestLen);
    }

    /**
     * H_3: absorb {@code src}, squeeze {@code digest} and a fresh {@code iv}
     * ({@link FaestParameters#IV_SIZE} bytes).
     * faest-ref: {@code H3_init} / {@code H3_update} / {@code H3_final}.
     */
    static void H3(int lambda, byte[] src, int srcOff, int srcLen,
                   byte[] digest, int digestOff, int digestLen,
                   byte[] iv, int ivOff)
    {
        RandomOracle ro = new RandomOracle(lambda);
        ro.absorb(src, srcOff, srcLen);
        ro.absorbByte(DOMAIN_H3);
        ro.squeeze(digest, digestOff, digestLen);
        ro.squeeze(iv, ivOff, FaestParameters.IV_SIZE);
    }

    /**
     * H_4: absorb a pre-IV ({@link FaestParameters#IV_SIZE} bytes), squeeze
     * the post-IV.
     * faest-ref: {@code H4_init} / {@code H4_update} / {@code H4_final}.
     */
    static void H4(int lambda, byte[] preIv, int preIvOff, byte[] iv, int ivOff)
    {
        RandomOracle ro = new RandomOracle(lambda);
        ro.absorb(preIv, preIvOff, FaestParameters.IV_SIZE);
        ro.absorbByte(DOMAIN_H4);
        ro.squeeze(iv, ivOff, FaestParameters.IV_SIZE);
    }
}
