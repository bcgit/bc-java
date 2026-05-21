package org.bouncycastle.pqc.crypto.faest;

/**
 * Universal hashing for FAEST v2.0.
 * <p>
 * Three families of hash, all parameterised by &lambda; &isin; {128, 192, 256}:
 * <ul>
 *   <li><b>vole_hash</b> &mdash; a polynomial universal hash over the witness
 *       used for VOLE-in-the-Head consistency checks. Output: &lambda;-bit
 *       digest plus a {@link FaestParameters#UNIVERSAL_HASH_B}-byte tail.</li>
 *   <li><b>zk_hash</b> &mdash; a streaming polynomial accumulator used inside
 *       the zero-knowledge proof. Init / Update / Finalize state machine.</li>
 *   <li><b>leaf_hash</b> &mdash; a single-input hash over the BAVC leaves,
 *       using the extended GF(2<sup>3&lambda;</sup>) field.</li>
 * </ul>
 * <p>
 * Source of truth: {@code universal_hashing.c}.
 */
final class UniversalHashing
{
    private UniversalHashing()
    {
    }

    // ===== vole_hash =====

    /**
     * Lambda-dispatched vole_hash. Writes (&lambda;/8 + {@link FaestParameters#UNIVERSAL_HASH_B})
     * bytes into {@code h}. faest-ref: {@code vole_hash}, universal_hashing.c:145.
     */
    static void voleHash(byte[] h, int hOff, byte[] sd, int sdOff,
                         byte[] x, int xOff, int ell, int lambda)
    {
        switch (lambda)
        {
        case 256:
            voleHash256(h, hOff, sd, sdOff, x, xOff, ell);
            break;
        case 192:
            voleHash192(h, hOff, sd, sdOff, x, xOff, ell);
            break;
        default:
            voleHash128(h, hOff, sd, sdOff, x, xOff, ell);
            break;
        }
    }

    /** faest-ref: {@code vole_hash_128}, universal_hashing.c:40. */
    static void voleHash128(byte[] h, int hOff, byte[] sd, int sdOff,
                            byte[] x, int xOff, int ell)
    {
        final int bytes = BF128.BYTES;
        // sd layout: r0||r1||r2||r3||s||t
        long[] r0 = new long[BF128.LIMBS]; BF128.load(r0, 0, sd, sdOff + 0 * bytes);
        long[] r1 = new long[BF128.LIMBS]; BF128.load(r1, 0, sd, sdOff + 1 * bytes);
        long[] r2 = new long[BF128.LIMBS]; BF128.load(r2, 0, sd, sdOff + 2 * bytes);
        long[] r3 = new long[BF128.LIMBS]; BF128.load(r3, 0, sd, sdOff + 3 * bytes);
        long[] s  = new long[BF128.LIMBS]; BF128.load(s,  0, sd, sdOff + 4 * bytes);
        long t  = BF64.load(sd, sdOff + 5 * bytes);
        int x1Off = xOff + (ell + 2 * bytes * 8) / 8;

        final int lambdaBits = bytes * 8;
        final int lengthLambda = (ell + 3 * lambdaBits - 1) / lambdaBits;

        // Zero-padded tail block.
        byte[] tmp = new byte[bytes];
        int tailLen = (ell + lambdaBits) % lambdaBits == 0
            ? bytes
            : ((ell + lambdaBits) % lambdaBits) / 8;
        System.arraycopy(x, xOff + (lengthLambda - 1) * bytes, tmp, 0, tailLen);

        long[] h0 = new long[BF128.LIMBS]; BF128.load(h0, 0, tmp, 0);

        long[] runningS = new long[BF128.LIMBS]; System.arraycopy(s, 0, runningS, 0, BF128.LIMBS);
        long[] block    = new long[BF128.LIMBS];
        long[] tmpMul   = new long[BF128.LIMBS];

        for (int i = 1; i != lengthLambda; ++i)
        {
            BF128.load(block, 0, x, xOff + (lengthLambda - 1 - i) * bytes);
            BF128.mul(tmpMul, 0, runningS, 0, block, 0);
            BF128.addInPlace(h0, 0, tmpMul, 0);
            // advance running_s *= s for next iteration
            BF128.mul(runningS, 0, runningS, 0, s, 0);
        }

        long h1 = computeH1(t, x, xOff, lambdaBits, ell);

        // h2 = r0 * h0  +  r1 * h1
        long[] h2 = new long[BF128.LIMBS];
        BF128.mul(h2, 0, r0, 0, h0, 0);
        BF128.mul64(tmpMul, 0, r1, 0, h1);
        BF128.addInPlace(h2, 0, tmpMul, 0);

        // h3 = r2 * h0  +  r3 * h1
        long[] h3 = new long[BF128.LIMBS];
        BF128.mul(h3, 0, r2, 0, h0, 0);
        BF128.mul64(tmpMul, 0, r3, 0, h1);
        BF128.addInPlace(h3, 0, tmpMul, 0);

        BF128.store(h, hOff, h2, 0);
        BF128.store(tmp, 0, h3, 0);
        System.arraycopy(tmp, 0, h, hOff + bytes, FaestParameters.UNIVERSAL_HASH_B);
        xorInto(h, hOff, x, x1Off, bytes + FaestParameters.UNIVERSAL_HASH_B);
    }

    /** faest-ref: {@code vole_hash_192}, universal_hashing.c:75. */
    static void voleHash192(byte[] h, int hOff, byte[] sd, int sdOff,
                            byte[] x, int xOff, int ell)
    {
        final int bytes = BF192.BYTES;
        long[] r0 = new long[BF192.LIMBS]; BF192.load(r0, 0, sd, sdOff + 0 * bytes);
        long[] r1 = new long[BF192.LIMBS]; BF192.load(r1, 0, sd, sdOff + 1 * bytes);
        long[] r2 = new long[BF192.LIMBS]; BF192.load(r2, 0, sd, sdOff + 2 * bytes);
        long[] r3 = new long[BF192.LIMBS]; BF192.load(r3, 0, sd, sdOff + 3 * bytes);
        long[] s  = new long[BF192.LIMBS]; BF192.load(s,  0, sd, sdOff + 4 * bytes);
        long t  = BF64.load(sd, sdOff + 5 * bytes);
        int x1Off = xOff + (ell + 2 * bytes * 8) / 8;

        final int lambdaBits = bytes * 8;
        final int lengthLambda = (ell + 3 * lambdaBits - 1) / lambdaBits;

        byte[] tmp = new byte[bytes];
        int tailLen = (ell + lambdaBits) % lambdaBits == 0
            ? bytes
            : ((ell + lambdaBits) % lambdaBits) / 8;
        System.arraycopy(x, xOff + (lengthLambda - 1) * bytes, tmp, 0, tailLen);

        long[] h0 = new long[BF192.LIMBS]; BF192.load(h0, 0, tmp, 0);
        long[] runningS = new long[BF192.LIMBS]; System.arraycopy(s, 0, runningS, 0, BF192.LIMBS);
        long[] block    = new long[BF192.LIMBS];
        long[] tmpMul   = new long[BF192.LIMBS];

        for (int i = 1; i != lengthLambda; ++i)
        {
            BF192.load(block, 0, x, xOff + (lengthLambda - 1 - i) * bytes);
            BF192.mul(tmpMul, 0, runningS, 0, block, 0);
            BF192.addInPlace(h0, 0, tmpMul, 0);
            BF192.mul(runningS, 0, runningS, 0, s, 0);
        }

        long h1 = computeH1(t, x, xOff, lambdaBits, ell);

        long[] h2 = new long[BF192.LIMBS];
        BF192.mul(h2, 0, r0, 0, h0, 0);
        BF192.mul64(tmpMul, 0, r1, 0, h1);
        BF192.addInPlace(h2, 0, tmpMul, 0);

        long[] h3 = new long[BF192.LIMBS];
        BF192.mul(h3, 0, r2, 0, h0, 0);
        BF192.mul64(tmpMul, 0, r3, 0, h1);
        BF192.addInPlace(h3, 0, tmpMul, 0);

        BF192.store(h, hOff, h2, 0);
        BF192.store(tmp, 0, h3, 0);
        System.arraycopy(tmp, 0, h, hOff + bytes, FaestParameters.UNIVERSAL_HASH_B);
        xorInto(h, hOff, x, x1Off, bytes + FaestParameters.UNIVERSAL_HASH_B);
    }

    /** faest-ref: {@code vole_hash_256}, universal_hashing.c:110. */
    static void voleHash256(byte[] h, int hOff, byte[] sd, int sdOff,
                            byte[] x, int xOff, int ell)
    {
        final int bytes = BF256.BYTES;
        long[] r0 = new long[BF256.LIMBS]; BF256.load(r0, 0, sd, sdOff + 0 * bytes);
        long[] r1 = new long[BF256.LIMBS]; BF256.load(r1, 0, sd, sdOff + 1 * bytes);
        long[] r2 = new long[BF256.LIMBS]; BF256.load(r2, 0, sd, sdOff + 2 * bytes);
        long[] r3 = new long[BF256.LIMBS]; BF256.load(r3, 0, sd, sdOff + 3 * bytes);
        long[] s  = new long[BF256.LIMBS]; BF256.load(s,  0, sd, sdOff + 4 * bytes);
        long t  = BF64.load(sd, sdOff + 5 * bytes);
        int x1Off = xOff + (ell + 2 * bytes * 8) / 8;

        final int lambdaBits = bytes * 8;
        final int lengthLambda = (ell + 3 * lambdaBits - 1) / lambdaBits;

        byte[] tmp = new byte[bytes];
        int tailLen = (ell + lambdaBits) % lambdaBits == 0
            ? bytes
            : ((ell + lambdaBits) % lambdaBits) / 8;
        System.arraycopy(x, xOff + (lengthLambda - 1) * bytes, tmp, 0, tailLen);

        long[] h0 = new long[BF256.LIMBS]; BF256.load(h0, 0, tmp, 0);
        long[] runningS = new long[BF256.LIMBS]; System.arraycopy(s, 0, runningS, 0, BF256.LIMBS);
        long[] block    = new long[BF256.LIMBS];
        long[] tmpMul   = new long[BF256.LIMBS];

        for (int i = 1; i != lengthLambda; ++i)
        {
            BF256.load(block, 0, x, xOff + (lengthLambda - 1 - i) * bytes);
            BF256.mul(tmpMul, 0, runningS, 0, block, 0);
            BF256.addInPlace(h0, 0, tmpMul, 0);
            BF256.mul(runningS, 0, runningS, 0, s, 0);
        }

        long h1 = computeH1(t, x, xOff, lambdaBits, ell);

        long[] h2 = new long[BF256.LIMBS];
        BF256.mul(h2, 0, r0, 0, h0, 0);
        BF256.mul64(tmpMul, 0, r1, 0, h1);
        BF256.addInPlace(h2, 0, tmpMul, 0);

        long[] h3 = new long[BF256.LIMBS];
        BF256.mul(h3, 0, r2, 0, h0, 0);
        BF256.mul64(tmpMul, 0, r3, 0, h1);
        BF256.addInPlace(h3, 0, tmpMul, 0);

        BF256.store(h, hOff, h2, 0);
        BF256.store(tmp, 0, h3, 0);
        System.arraycopy(tmp, 0, h, hOff + bytes, FaestParameters.UNIVERSAL_HASH_B);
        xorInto(h, hOff, x, x1Off, bytes + FaestParameters.UNIVERSAL_HASH_B);
    }

    /**
     * Polynomial-in-t hash of the witness as a sequence of 64-bit blocks,
     * walking the witness in reverse and zero-padding the final partial block.
     * faest-ref: {@code compute_h1}, universal_hashing.c:16.
     */
    private static long computeH1(long t, byte[] x, int xOff, int lambdaBits, int ell)
    {
        final int lambdaBytes = lambdaBits / 8;
        final int lengthLambda = (ell + 3 * lambdaBits - 1) / lambdaBits;

        byte[] tmp = new byte[FaestParameters.MAX_LAMBDA / 8];
        int tailLen = (ell + lambdaBits) % lambdaBits == 0
            ? lambdaBytes
            : ((ell + lambdaBits) % lambdaBits) / 8;
        System.arraycopy(x, xOff + (lengthLambda - 1) * lambdaBytes, tmp, 0, tailLen);

        long h1 = 0L;
        long runningT = 1L;     // bf64_one
        int i = 0;

        // walk the zero-padded "last block" first (reverse order, 8-byte chunks)
        for (; i < lambdaBytes; i += 8)
        {
            long block = BF64.load(tmp, lambdaBytes - i - 8);
            h1 ^= BF64.mul(runningT, block);
            runningT = BF64.mul(runningT, t);
        }
        // then the remaining blocks of x, in reverse
        for (; i < lengthLambda * lambdaBytes; i += 8)
        {
            long block = BF64.load(x, xOff + lengthLambda * lambdaBytes - i - 8);
            h1 ^= BF64.mul(runningT, block);
            runningT = BF64.mul(runningT, t);
        }
        return h1;
    }

    // ===== zk_hash =====

    /**
     * Streaming polynomial accumulator over GF(2<sup>&lambda;</sup>) for FAEST's
     * zero-knowledge proof. State: {@code (h0, h1)} BF&lambda; accumulators
     * driven by multipliers {@code s} (BF&lambda;) and {@code t} (bf64); the
     * seed {@code sd} provides {@code r0, r1} at finalization.
     * <p>
     * faest-ref: {@code zk_hash_128_ctx} / {@code zk_hash_128_init} / update /
     * finalize, universal_hashing.c:159-182. The 192/256 variants are inlined
     * subclasses that override only the limb count and the field statics they
     * dispatch to.
     */
    static final class ZkHash128
    {
        final long[] h0 = new long[BF128.LIMBS];
        final long[] h1 = new long[BF128.LIMBS];
        final long[] s  = new long[BF128.LIMBS];
        final long t;
        final byte[] sd;
        final int sdOff;
        private final long[] tmp = new long[BF128.LIMBS];

        ZkHash128(byte[] sd, int sdOff)
        {
            this.sd = sd;
            this.sdOff = sdOff;
            // sd layout for zk_hash: r0 || r1 || s || t (the vole_hash also packs
            // r2 || r3 after that, but zk_hash only needs the first four).
            BF128.zero(h0, 0);
            BF128.zero(h1, 0);
            BF128.load(s, 0, sd, sdOff + 2 * BF128.BYTES);
            this.t = BF64.load(sd, sdOff + 3 * BF128.BYTES);
        }

        /** Absorb one element {@code v}: h0 := h0*s + v; h1 := h1*t + v. */
        void update(long[] v, int vOff)
        {
            BF128.mul(tmp, 0, h0, 0, s, 0);
            BF128.add(h0, 0, tmp, 0, v, vOff);
            BF128.mul64(tmp, 0, h1, 0, t);
            BF128.add(h1, 0, tmp, 0, v, vOff);
        }

        /** Squeeze: h = r0*h0 + r1*h1 + x1. */
        void finalize(byte[] h, int hOff, long[] x1, int x1Off)
        {
            long[] r0 = new long[BF128.LIMBS]; BF128.load(r0, 0, sd, sdOff);
            long[] r1 = new long[BF128.LIMBS]; BF128.load(r1, 0, sd, sdOff + BF128.BYTES);

            long[] out = new long[BF128.LIMBS];
            BF128.mul(out, 0, r0, 0, h0, 0);
            long[] t2 = new long[BF128.LIMBS];
            BF128.mul(t2, 0, r1, 0, h1, 0);
            BF128.addInPlace(out, 0, t2, 0);
            BF128.addInPlace(out, 0, x1, x1Off);
            BF128.store(h, hOff, out, 0);
        }
    }

    static final class ZkHash192
    {
        final long[] h0 = new long[BF192.LIMBS];
        final long[] h1 = new long[BF192.LIMBS];
        final long[] s  = new long[BF192.LIMBS];
        final long t;
        final byte[] sd;
        final int sdOff;
        private final long[] tmp = new long[BF192.LIMBS];

        ZkHash192(byte[] sd, int sdOff)
        {
            this.sd = sd;
            this.sdOff = sdOff;
            BF192.zero(h0, 0);
            BF192.zero(h1, 0);
            BF192.load(s, 0, sd, sdOff + 2 * BF192.BYTES);
            this.t = BF64.load(sd, sdOff + 3 * BF192.BYTES);
        }

        void update(long[] v, int vOff)
        {
            BF192.mul(tmp, 0, h0, 0, s, 0);
            BF192.add(h0, 0, tmp, 0, v, vOff);
            BF192.mul64(tmp, 0, h1, 0, t);
            BF192.add(h1, 0, tmp, 0, v, vOff);
        }

        void finalize(byte[] h, int hOff, long[] x1, int x1Off)
        {
            long[] r0 = new long[BF192.LIMBS]; BF192.load(r0, 0, sd, sdOff);
            long[] r1 = new long[BF192.LIMBS]; BF192.load(r1, 0, sd, sdOff + BF192.BYTES);

            long[] out = new long[BF192.LIMBS];
            BF192.mul(out, 0, r0, 0, h0, 0);
            long[] t2 = new long[BF192.LIMBS];
            BF192.mul(t2, 0, r1, 0, h1, 0);
            BF192.addInPlace(out, 0, t2, 0);
            BF192.addInPlace(out, 0, x1, x1Off);
            BF192.store(h, hOff, out, 0);
        }
    }

    static final class ZkHash256
    {
        final long[] h0 = new long[BF256.LIMBS];
        final long[] h1 = new long[BF256.LIMBS];
        final long[] s  = new long[BF256.LIMBS];
        final long t;
        final byte[] sd;
        final int sdOff;
        private final long[] tmp = new long[BF256.LIMBS];

        ZkHash256(byte[] sd, int sdOff)
        {
            this.sd = sd;
            this.sdOff = sdOff;
            BF256.zero(h0, 0);
            BF256.zero(h1, 0);
            BF256.load(s, 0, sd, sdOff + 2 * BF256.BYTES);
            this.t = BF64.load(sd, sdOff + 3 * BF256.BYTES);
        }

        void update(long[] v, int vOff)
        {
            BF256.mul(tmp, 0, h0, 0, s, 0);
            BF256.add(h0, 0, tmp, 0, v, vOff);
            BF256.mul64(tmp, 0, h1, 0, t);
            BF256.add(h1, 0, tmp, 0, v, vOff);
        }

        void finalize(byte[] h, int hOff, long[] x1, int x1Off)
        {
            long[] r0 = new long[BF256.LIMBS]; BF256.load(r0, 0, sd, sdOff);
            long[] r1 = new long[BF256.LIMBS]; BF256.load(r1, 0, sd, sdOff + BF256.BYTES);

            long[] out = new long[BF256.LIMBS];
            BF256.mul(out, 0, r0, 0, h0, 0);
            long[] t2 = new long[BF256.LIMBS];
            BF256.mul(t2, 0, r1, 0, h1, 0);
            BF256.addInPlace(out, 0, t2, 0);
            BF256.addInPlace(out, 0, x1, x1Off);
            BF256.store(h, hOff, out, 0);
        }
    }

    // ===== leaf_hash =====

    /**
     * Lambda-dispatched leaf_hash. faest-ref: {@code leaf_hash},
     * universal_hashing.c:299.
     */
    static void leafHash(byte[] h, int hOff, byte[] sd, int sdOff,
                         byte[] x, int xOff, int lambda)
    {
        switch (lambda)
        {
        case 256:
            leafHash256(h, hOff, sd, sdOff, x, xOff);
            break;
        case 192:
            leafHash192(h, hOff, sd, sdOff, x, xOff);
            break;
        default:
            leafHash128(h, hOff, sd, sdOff, x, xOff);
            break;
        }
    }

    /** faest-ref: {@code leaf_hash_128}, universal_hashing.c:263. */
    static void leafHash128(byte[] h, int hOff, byte[] sd, int sdOff,
                            byte[] x, int xOff)
    {
        long[] u = new long[BF384.LIMBS]; BF384.load(u, 0, sd, sdOff);
        long[] x0 = new long[BF128.LIMBS]; BF128.load(x0, 0, x, xOff);
        long[] x1 = new long[BF384.LIMBS]; BF384.load(x1, 0, x, xOff + BF128.BYTES);

        long[] out = new long[BF384.LIMBS];
        BF384.mul128(out, 0, u, 0, x0, 0);
        BF384.addInPlace(out, 0, x1, 0);
        BF384.store(h, hOff, out, 0);
    }

    /** faest-ref: {@code leaf_hash_192}, universal_hashing.c:275. */
    static void leafHash192(byte[] h, int hOff, byte[] sd, int sdOff,
                            byte[] x, int xOff)
    {
        long[] u = new long[BF576.LIMBS]; BF576.load(u, 0, sd, sdOff);
        long[] x0 = new long[BF192.LIMBS]; BF192.load(x0, 0, x, xOff);
        long[] x1 = new long[BF576.LIMBS]; BF576.load(x1, 0, x, xOff + BF192.BYTES);

        long[] out = new long[BF576.LIMBS];
        BF576.mul192(out, 0, u, 0, x0, 0);
        BF576.addInPlace(out, 0, x1, 0);
        BF576.store(h, hOff, out, 0);
    }

    /** faest-ref: {@code leaf_hash_256}, universal_hashing.c:287. */
    static void leafHash256(byte[] h, int hOff, byte[] sd, int sdOff,
                            byte[] x, int xOff)
    {
        long[] u = new long[BF768.LIMBS]; BF768.load(u, 0, sd, sdOff);
        long[] x0 = new long[BF256.LIMBS]; BF256.load(x0, 0, x, xOff);
        long[] x1 = new long[BF768.LIMBS]; BF768.load(x1, 0, x, xOff + BF256.BYTES);

        long[] out = new long[BF768.LIMBS];
        BF768.mul256(out, 0, u, 0, x0, 0);
        BF768.addInPlace(out, 0, x1, 0);
        BF768.store(h, hOff, out, 0);
    }

    // ===== helpers =====

    /** {@code dst[off..off+len] ^= src[srcOff..srcOff+len]}. */
    private static void xorInto(byte[] dst, int off, byte[] src, int srcOff, int len)
    {
        for (int i = 0; i < len; i++)
        {
            dst[off + i] ^= src[srcOff + i];
        }
    }
}
