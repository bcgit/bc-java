package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * 64-bit-limb CIOS Montgomery arithmetic kernel — Phase I successor to the
 * 32-bit-limb {@link FpMontHelper}. Operates on {@code long[]} arrays with
 * each limb representing 64 unsigned bits.
 *
 * <p><b>Why 64-bit?</b> On a 64-bit JVM, {@code long * long} is a single
 * machine multiply instruction. Java 9 added {@link Math#multiplyHigh(long, long)},
 * which the HotSpot JIT intrinsifies to a single hardware instruction
 * (MULX on x86-64 BMI2, MULQ on x86-64 legacy, UMULH on ARM64). Together
 * these give a 128-bit product from two 64-bit operands at near-zero cost.
 * Each limb of CIOS goes from 32 bits to 64 bits, halving the limb count
 * (lvl1: 8→4, lvl3: 12→6, lvl5: 16→8) and roughly halving the work.
 * Standalone bench measured 2.25× speedup over the 32-bit kernel on the
 * lvl1 prime.</p>
 *
 * <p><b>p_prime = 1 still holds.</b> All three SQIsign primes satisfy
 * {@code p ≡ -1 (mod 2^64)} (since the top constant times 2^k with k≥64 is
 * 0 mod 2^64, leaving the -1 term), so the CIOS reduction's per-limb
 * multiplier {@code m = t[0]} directly — saving one 64×64 mul per outer
 * iteration.</p>
 *
 * <p>Sign correction for {@link Math#multiplyHigh}: that intrinsic returns
 * the high 64 bits of the *signed* 128-bit product. For unsigned operands
 * (which is how we use limbs), we correct via the identity
 * {@code unsignedHigh = signedHigh + (a>>63 & b) + (b>>63 & a)}.</p>
 */
final class FpMontHelper64
{
    static final long[] ZEROS_LONG = new long[8];

    private FpMontHelper64()
    {
    }

    /**
     * Unsigned 64×64 → high 64 of 128-bit product. Delegates to
     * {@link FpMul64#umulHi} — a tiny class whose Java 9+ Multi-Release
     * overlay uses {@code Math.multiplyHigh} while the Java 8 base uses a
     * software 32-bit-split fallback. Keeping the JDK-version-specific code
     * in {@code FpMul64} lets this whole kernel stay Java 8 source-compatible.
     */
    private static long umulHi(long a, long b)
    {
        return FpMul64.umulHi(a, b);
    }

    // ------------------------------------------------------------------
    // BigInteger ↔ longs converters
    // ------------------------------------------------------------------

    static void toLimbs(int N, BigInteger v, long[] out)
    {
        // Fast path: BigInteger.toByteArray (big-endian, signed) + manual repack
        // to little-endian 64-bit limbs. Mirrors the 32-bit version's trick.
        java.util.Arrays.fill(out, 0, N, 0L);
        byte[] bytes = v.toByteArray();
        int len = bytes.length;
        long limbBuf = 0L;
        int shift = 0;
        int limbIdx = 0;
        for (int i = len - 1; i >= 0 && limbIdx < N; i--)
        {
            if (i == 0 && bytes[0] == 0 && len > 1)
            {
                break; // skip sign byte
            }
            limbBuf |= ((long)(bytes[i] & 0xff)) << shift;
            shift += 8;
            if (shift == 64)
            {
                out[limbIdx++] = limbBuf;
                limbBuf = 0L;
                shift = 0;
            }
        }
        if (shift > 0)
        {
            out[limbIdx] = limbBuf;
        }
    }

    static BigInteger fromLimbs(int N, long[] limbs)
    {
        // Build big-endian byte[] then hand to BigInteger(1, bytes). Same shape
        // as the 32-bit version.
        byte[] bytes = new byte[N * 8];
        for (int i = 0; i < N; i++)
        {
            long limb = limbs[N - 1 - i];
            int j = i * 8;
            bytes[j]     = (byte)(limb >>> 56);
            bytes[j + 1] = (byte)(limb >>> 48);
            bytes[j + 2] = (byte)(limb >>> 40);
            bytes[j + 3] = (byte)(limb >>> 32);
            bytes[j + 4] = (byte)(limb >>> 24);
            bytes[j + 5] = (byte)(limb >>> 16);
            bytes[j + 6] = (byte)(limb >>> 8);
            bytes[j + 7] = (byte)limb;
        }
        return new BigInteger(1, bytes);
    }

    // ------------------------------------------------------------------
    // Modular add / sub on canonical 64-bit limb arrays
    // ------------------------------------------------------------------

    static void addModP(int N, long[] P_LIMBS, long[] out, long[] a, long[] b)
    {
        // 64-bit ripple-add with BRANCHLESS carry tracking via the textbook
        // identity carry_out = ((a & b) | ((a | b) & ~s)) >>> 63.
        // ~2× faster than the Long.compareUnsigned ternary on hot paths
        // because the JIT emits pure ALU ops with no comparison or cmov.
        //
        // Writes directly to {@code out} — alias-safe even when out == a or
        // out == b, because limb i reads a[i]/b[i] before writing out[i], and
        // the carry only flows forward. Removes the per-call long[N] temp +
        // arraycopy that showed hot in the Phase I profile.
        long carry = 0;
        for (int i = 0; i < N; i++)
        {
            long ai = a[i];
            long bi = b[i];
            long s1 = ai + bi;
            long c1 = ((ai & bi) | ((ai | bi) & ~s1)) >>> 63;
            long s2 = s1 + carry;
            long c2 = ((s1 & carry) | ((s1 | carry) & ~s2)) >>> 63;
            out[i] = s2;
            carry = c1 + c2;
        }
        if (carry != 0 || compareLimbsToP(N, P_LIMBS, out) >= 0)
        {
            subPInPlace(N, P_LIMBS, out);
        }
    }

    static void subModP(int N, long[] P_LIMBS, long[] out, long[] a, long[] b)
    {
        // 64-bit ripple-sub with branchless borrow via the textbook identity
        // borrow_out = ((~a & b) | (~(a ^ b) & s)) >>> 63 — dual of add carry.
        // Writes directly to {@code out}; alias-safe (see addModP).
        long borrow = 0;
        for (int i = 0; i < N; i++)
        {
            long ai = a[i];
            long bi = b[i];
            long s1 = ai - bi;
            long b1 = ((~ai & bi) | (~(ai ^ bi) & s1)) >>> 63;
            long s2 = s1 - borrow;
            long b2 = ((~s1 & borrow) | (~(s1 ^ borrow) & s2)) >>> 63;
            out[i] = s2;
            borrow = b1 + b2;
        }
        if (borrow != 0)
        {
            addPInPlace(N, P_LIMBS, out);
        }
    }

    // ------------------------------------------------------------------
    // CIOS Montgomery multiplication (64-bit limbs, p_prime = 1)
    // ------------------------------------------------------------------

    static void mulMont(int N, long[] P_LIMBS, long[] c, long[] a, long[] b)
    {
        long[] t = new long[N + 2];

        for (int i = 0; i < N; i++)
        {
            long bi = b[i];

            // Step 1: t += a * b[i]  (each iteration accumulates one column).
            long carry = 0;
            for (int j = 0; j < N; j++)
            {
                long aj = a[j];
                long lo = aj * bi;                // low 64
                long hi = umulHi(aj, bi);         // high 64

                // sum = t[j] + lo + carry, tracking 64-bit overflows into hi.
                long tj = t[j];
                long s1 = tj + lo;
                long c1 = ((tj & lo) | ((tj | lo) & ~s1)) >>> 63;
                long s2 = s1 + carry;
                long c2 = ((s1 & carry) | ((s1 | carry) & ~s2)) >>> 63;
                t[j] = s2;
                carry = hi + c1 + c2;
            }
            long tN = t[N];
            long sumN = tN + carry;
            long cN = ((tN & carry) | ((tN | carry) & ~sumN)) >>> 63;
            t[N] = sumN;
            t[N + 1] += cN;

            // Step 2: m = t[0] (p_prime = 1 because p ≡ -1 mod 2^64).
            long m = t[0];

            // Step 3: t = (t + m * p) >> 64. The low limb of (t + m*p) is
            // identically 0 mod 2^64 by the CIOS invariant; we shift it out.
            carry = 0;
            for (int j = 0; j < N; j++)
            {
                long pj = P_LIMBS[j];
                long lo = m * pj;
                long hi = umulHi(m, pj);

                long s1 = t[j] + lo;
                // Branchless carry-out (matching the same idiom used at the
                // end of this function below): c = 1 iff t[j] + lo wraps.
                long c1 = ((t[j] & lo) | ((t[j] | lo) & ~s1)) >>> 63;
                long s2 = s1 + carry;
                long c2 = ((s1 & carry) | ((s1 | carry) & ~s2)) >>> 63;
                if (j != 0)
                {
                    t[j - 1] = s2;
                }
                carry = hi + c1 + c2;
            }
            long tN2 = t[N];
            long sumNred = tN2 + carry;
            long cNred = ((tN2 & carry) | ((tN2 | carry) & ~sumNred)) >>> 63;
            t[N - 1] = sumNred;
            t[N] = cNred + t[N + 1];
            t[N + 1] = 0;
        }

        // Final conditional subtract — CIOS bound is t < 2p.
        if (t[N] != 0 || compareLimbsToP(N, P_LIMBS, t) >= 0)
        {
            subPInPlace(N, P_LIMBS, t);
        }

        System.arraycopy(t, 0, c, 0, N);
    }

    // ------------------------------------------------------------------
    // Lazy-reduction (SOS) primitives — Phase J #4
    // ------------------------------------------------------------------

    /**
     * Full 2N-limb schoolbook product {@code out = a * b}, NO Montgomery
     * reduction. {@code out} has length ≥ 2N and is fully overwritten.
     * Row-by-row (operand scanning): for each {@code b[i]}, accumulate
     * {@code a * b[i]} into {@code out} shifted by i limbs, propagating the
     * carry into {@code out[i+N]} (its first write). The (lo, hi) product
     * structure bounds {@code hi + c1 + c2 ≤ 2^64-1}, so the running carry
     * never overflows.
     */
    static void mulFull(int N, long[] out, long[] a, long[] b)
    {
        for (int i = 0; i < 2 * N; i++)
        {
            out[i] = 0L;
        }
        for (int i = 0; i < N; i++)
        {
            long bi = b[i];
            long carry = 0;
            for (int j = 0; j < N; j++)
            {
                long aj = a[j];
                long lo = aj * bi;
                long hi = umulHi(aj, bi);
                long oj = out[i + j];
                long s1 = oj + lo;
                long c1 = ((oj & lo) | ((oj | lo) & ~s1)) >>> 63;
                long s2 = s1 + carry;
                long c2 = ((s1 & carry) | ((s1 | carry) & ~s2)) >>> 63;
                out[i + j] = s2;
                carry = hi + c1 + c2;
            }
            out[i + N] = carry; // first write of this limb (rows i'>i accumulate)
        }
    }

    /** Build {@code 2·p²} as a {@code (2N+2)}-limb little-endian long array,
     *  the non-negativity bias for the lazy-reduction Fp2 multiply. */
    static long[] bias2P2(int N, BigInteger p)
    {
        BigInteger v = p.multiply(p).shiftLeft(1);
        long[] out = new long[2 * N + 2];
        BigInteger mask = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        for (int i = 0; i < out.length; i++)
        {
            out[i] = v.and(mask).longValue();
            v = v.shiftRight(64);
        }
        return out;
    }

    /**
     * Lazy-reduction GF(p²) multiply on Mont-form limb arrays. Shared by all
     * levels (parameterised by N, P_LIMBS, BIAS). Computes the Karatsuba
     * sub-products as full 2N-limb integers, combines with the {@code 2p²}
     * bias, and does only two Montgomery reductions. See
     * {@code FpLvl1Mont64.fp2Mul} for the derivation. Outputs may alias inputs.
     */
    static void fp2Mul(int N, long[] P_LIMBS, long[] bias,
                       long[] outRe, long[] outIm,
                       long[] aRe, long[] aIm, long[] bRe, long[] bIm)
    {
        long[] sumA = new long[N];
        long[] sumB = new long[N];
        addModP(N, P_LIMBS, sumA, aRe, aIm);
        addModP(N, P_LIMBS, sumB, bRe, bIm);

        long[] pac = new long[2 * N + 2];
        long[] pbd = new long[2 * N + 2];
        long[] psum = new long[2 * N + 2];
        mulFull(N, pac, aRe, bRe);
        mulFull(N, pbd, aIm, bIm);
        mulFull(N, psum, sumA, sumB);

        long[] re = new long[2 * N + 2];
        sub2N(re, pac, pbd);
        add2N(re, re, bias);

        long[] im = new long[2 * N + 2];
        sub2N(im, psum, pac);
        sub2N(im, im, pbd);
        add2N(im, im, bias);

        montReduce(N, P_LIMBS, outRe, re);
        montReduce(N, P_LIMBS, outIm, im);
    }

    /** Unsigned wide add over the full array length: {@code out = a + b mod 2^(64·len)}. */
    static void add2N(long[] out, long[] a, long[] b)
    {
        long carry = 0;
        for (int i = 0; i < out.length; i++)
        {
            long ai = a[i];
            long bi = b[i];
            long s1 = ai + bi;
            long c1 = ((ai & bi) | ((ai | bi) & ~s1)) >>> 63;
            long s2 = s1 + carry;
            long c2 = ((s1 & carry) | ((s1 | carry) & ~s2)) >>> 63;
            out[i] = s2;
            carry = c1 + c2;
        }
    }

    /** Unsigned wide sub over the full array length (two's-complement wrap):
     *  {@code out = a - b mod 2^(64·len)}. */
    static void sub2N(long[] out, long[] a, long[] b)
    {
        long borrow = 0;
        for (int i = 0; i < out.length; i++)
        {
            long ai = a[i];
            long bi = b[i];
            long s1 = ai - bi;
            long b1 = ((~ai & bi) | (~(ai ^ bi) & s1)) >>> 63;
            long s2 = s1 - borrow;
            long b2 = ((~s1 & borrow) | (~(s1 ^ borrow) & s2)) >>> 63;
            out[i] = s2;
            borrow = b1 + b2;
        }
    }

    /**
     * Montgomery reduction of a {@code 2N}-limb value {@code t} (length ≥ 2N+2,
     * upper limbs used for carry headroom) to {@code out} in {@code [0, p)}.
     * {@code t} is consumed/modified in place. Requires {@code t < p·R} on
     * entry (caller guarantees via the bias trick); output {@code = t·R^{-1}
     * mod p}. Uses {@code p_prime = 1} (so {@code m = t[i]} directly).
     */
    static void montReduce(int N, long[] P_LIMBS, long[] out, long[] t)
    {
        for (int i = 0; i < N; i++)
        {
            long m = t[i]; // p_prime = 1
            long carry = 0;
            for (int j = 0; j < N; j++)
            {
                long pj = P_LIMBS[j];
                long lo = m * pj;
                long hi = umulHi(m, pj);
                long tij = t[i + j];
                long s1 = tij + lo;
                long c1 = ((tij & lo) | ((tij | lo) & ~s1)) >>> 63;
                long s2 = s1 + carry;
                long c2 = ((s1 & carry) | ((s1 | carry) & ~s2)) >>> 63;
                t[i + j] = s2; // t[i] becomes 0 after this (m·p[0] cancels it)
                carry = hi + c1 + c2;
            }
            // Propagate the remaining carry above the j-loop window.
            int k = i + N;
            while (carry != 0)
            {
                long tk = t[k];
                long s = tk + carry;
                carry = ((tk & carry) | ((tk | carry) & ~s)) >>> 63;
                t[k] = s;
                k++;
            }
        }
        // Result = t[N .. 2N-1], with a possible top carry in t[2N].
        // Standard REDC bound: result < 2p, so one conditional subtract.
        // Subtract p iff result >= p: true if the top carry is set, or the
        // N-limb slice compares >= P (MSB-first; equal also subtracts → 0).
        boolean ge = t[2 * N] != 0;
        if (!ge)
        {
            int cmp = 0;
            for (int i = N - 1; i >= 0; i--)
            {
                long ti = t[N + i];
                long pi = P_LIMBS[i];
                if (ti != pi)
                {
                    cmp = Long.compareUnsigned(ti, pi);
                    break;
                }
            }
            ge = cmp >= 0;
        }
        if (ge)
        {
            long borrow = 0;
            for (int j = 0; j < N; j++)
            {
                long aj = t[N + j];
                long pj = P_LIMBS[j];
                long s1 = aj - pj;
                long b1 = ((~aj & pj) | (~(aj ^ pj) & s1)) >>> 63;
                long s2 = s1 - borrow;
                long b2 = ((~s1 & borrow) | (~(s1 ^ borrow) & s2)) >>> 63;
                out[j] = s2;
                borrow = b1 + b2;
            }
        }
        else
        {
            System.arraycopy(t, N, out, 0, N);
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    private static int compareLimbsToP(int N, long[] P_LIMBS, long[] t)
    {
        for (int i = N - 1; i >= 0; i--)
        {
            if (t[i] != P_LIMBS[i])
            {
                return Long.compareUnsigned(t[i], P_LIMBS[i]);
            }
        }
        return 0;
    }

    private static void subPInPlace(int N, long[] P_LIMBS, long[] t)
    {
        long borrow = 0;
        for (int j = 0; j < N; j++)
        {
            long aj = t[j];
            long pj = P_LIMBS[j];
            long s1 = aj - pj;
            long b1 = ((~aj & pj) | (~(aj ^ pj) & s1)) >>> 63;
            long s2 = s1 - borrow;
            long b2 = ((~s1 & borrow) | (~(s1 ^ borrow) & s2)) >>> 63;
            t[j] = s2;
            borrow = b1 + b2;
        }
    }

    private static void addPInPlace(int N, long[] P_LIMBS, long[] t)
    {
        long carry = 0;
        for (int j = 0; j < N; j++)
        {
            long tj = t[j];
            long pj = P_LIMBS[j];
            long s1 = tj + pj;
            long c1 = ((tj & pj) | ((tj | pj) & ~s1)) >>> 63;
            long s2 = s1 + carry;
            long c2 = ((s1 & carry) | ((s1 | carry) & ~s2)) >>> 63;
            t[j] = s2;
            carry = c1 + c2;
        }
    }
}
