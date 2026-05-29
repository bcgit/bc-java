package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

import org.bouncycastle.util.Properties;

/**
 * Level-independent kernel for SQIsign's limb-array CIOS Montgomery
 * arithmetic. All operations take {@code N} (number of 32-bit limbs)
 * and {@code P_LIMBS} (the prime modulus as a little-endian limb array)
 * as parameters, so the three SQIsign primes share one implementation:
 *
 * <ul>
 *   <li>lvl1: {@code p = 5 * 2^248 - 1}, N = 8.</li>
 *   <li>lvl3: {@code p = 65 * 2^376 - 1}, N = 12.</li>
 *   <li>lvl5: {@code p = 27 * 2^500 - 1}, N = 16.</li>
 * </ul>
 *
 * <p>All three primes satisfy {@code p ≡ -1 (mod 2^32)}, hence
 * {@code p_prime = -p^{-1} mod 2^32 = 1} and the CIOS reduction's
 * per-limb multiplier {@code m = t[0]} directly — saving one 32×32 mul
 * per outer iteration. This is enforced (per-level) by the wrapper
 * classes ({@link FpLvl1Mont}, {@link FpLvl3Mont}, {@link FpLvl5Mont})
 * which compute and freeze the prime's limb array at class load.</p>
 *
 * <p>Per-call workspace: one {@code long[N+2]} for {@link #mulMont} and
 * one {@code long[N]} for {@link #addModP} / {@link #subModP}. No
 * per-class state.</p>
 *
 * <p>Verified against the BigInteger oracle for all three levels via
 * the per-level {@code FpLvl{1,3,5}MontTest} suites.</p>
 */
final class FpMontHelper
{
    /**
     * Shared system-property gate read once at class init from
     * {@link Properties#SQISIGN_FP_LIMBS}. When {@code true},
     * {@link Fp}'s level-independent helpers maintain the Montgomery
     * cache and {@code FpLvlN.mul} / {@code sqr} read / write it
     * directly. When {@code false}, the cache is unused and all
     * coherence-maintenance branches in {@link Fp} / {@link Fp2} compile
     * down to no-ops (the JIT eliminates the constant-false branch).
     */
    static final boolean LIMBS_ENABLED = Properties.isOverrideSet(Properties.SQISIGN_FP_LIMBS);

    /**
     * Phase I: when this flag is true, FpLvlN ops dispatch through
     * {@link FpMontHelper64} (64-bit limb CIOS). Requires all of:
     * <ul>
     *   <li>{@link #LIMBS_ENABLED} (the {@code sqisign.fp.limbs} opt-in);</li>
     *   <li>{@link FpMul64#isHardware} — true only when the Java 9+
     *       Multi-Release overlay supplying {@code Math.multiplyHigh} is
     *       loaded. On a Java 8 runtime the base {@code FpMul64} reports
     *       false, so the 64-bit path stays disabled and the 32-bit-limb
     *       kernel ({@link FpMontHelper}) is used — no Java 8 regression;</li>
     *   <li>the {@code org.bouncycastle.sqisign.fp.limbs32} property is NOT
     *       set (it forces the 32-bit path for A/B testing even on Java 9+).</li>
     * </ul>
     */
    static final boolean USE_HW_MONT64 = LIMBS_ENABLED
        && FpMul64.isHardware()
        && !Properties.isOverrideSet("org.bouncycastle.sqisign.fp.limbs32");

    /**
     * Phase J #4: lazy-reduction (SOS) Karatsuba Fp2 multiply on the 64-bit
     * path. <b>Off by default — it is a net loss at SQIsign's limb counts.</b>
     * Although the SOS form does ~17% fewer limb-multiplies (3 products + 2
     * Montgomery reductions vs the reduce-per-product Karatsuba's 3+3), at
     * N=4..8 limbs that saving is outweighed by its memory traffic: it
     * allocates several {@code 2N+2}-limb scratch arrays per call and passes
     * the wide product between {@code mulFull}/{@code montReduce} across method
     * boundaries (not scalarizable), whereas interleaved CIOS keeps one tight
     * register-friendly accumulator. A/B benchmark on the lvl1 prime measured
     * the SOS path ~12% slower (306 vs 273 ms/iter steady-state). SOS only
     * wins at much larger operand sizes. The kernel ({@link FpMontHelper64}
     * {@code mulFull}/{@code montReduce}/{@code fp2Mul}) is verified correct
     * and kept behind this opt-in flag for
     * reference / potential reuse, but production stays on the faster
     * reduce-per-product Karatsuba. Enable with
     * {@code org.bouncycastle.sqisign.fp.lazyfp2} only for experimentation.
     */
    static final boolean USE_LAZY_FP2 = USE_HW_MONT64
        && Properties.isOverrideSet("org.bouncycastle.sqisign.fp.lazyfp2");

    /**
     * All-zero limb constant sized to the widest level (16 limbs). Used as
     * the minuend in Mont-domain negation: {@code subModP(out, ZEROS, a)}
     * computes {@code -a mod p} correctly for any level (the lvl-specific
     * {@code subModP(N, …)} only reads the first {@code N} limbs).
     */
    static final int[] ZEROS = new int[16];

    private FpMontHelper()
    {
    }

    // ------------------------------------------------------------------
    // BigInteger ↔ limbs converters
    // ------------------------------------------------------------------

    static void toLimbs(int N, BigInteger v, int[] out)
    {
        // Fast path: convert via toByteArray + manual repack into little-endian
        // 32-bit limbs. One byte[] allocation per call (~32 bytes for lvl1) and
        // a tight byte loop, vs the previous BigInteger.and / shiftRight chain
        // which allocated 2N intermediate BigIntegers per call. Measured ~5×
        // faster at lvl1 (JFR profile showed this hot in Phase F).
        //
        // Caller invariant: v is non-negative in [0, p) — true throughout
        // SQIsign at the toMont conversion boundary.
        java.util.Arrays.fill(out, 0, N, 0);
        byte[] bytes = v.toByteArray();
        int len = bytes.length;
        int limbBuf = 0;
        int shift = 0;
        int limbIdx = 0;
        for (int i = len - 1; i >= 0 && limbIdx < N; i--)
        {
            // Skip the sign byte (BigInteger.toByteArray() prepends a 0 if the
            // high bit of the magnitude's MSB would otherwise be set, so the
            // two's-complement representation is positive).
            if (i == 0 && bytes[0] == 0 && len > 1)
            {
                break;
            }
            limbBuf |= (bytes[i] & 0xff) << shift;
            shift += 8;
            if (shift == 32)
            {
                out[limbIdx++] = limbBuf;
                limbBuf = 0;
                shift = 0;
            }
        }
        if (shift > 0 && limbIdx < N)
        {
            out[limbIdx] = limbBuf;
        }
    }

    static BigInteger fromLimbs(int N, int[] limbs)
    {
        // Build a big-endian byte[] and hand it to BigInteger(int signum, byte[]).
        // Faster than the BigInteger.shiftLeft / .or chain: avoids creating N
        // intermediate BigInteger objects and uses BigInteger's native byte path.
        byte[] bytes = new byte[N * 4];
        for (int i = 0; i < N; i++)
        {
            int limb = limbs[N - 1 - i];
            int j = i * 4;
            bytes[j]     = (byte)(limb >>> 24);
            bytes[j + 1] = (byte)(limb >>> 16);
            bytes[j + 2] = (byte)(limb >>> 8);
            bytes[j + 3] = (byte)limb;
        }
        return new BigInteger(1, bytes);
    }

    // ------------------------------------------------------------------
    // Modular add / sub on canonical limb arrays
    // ------------------------------------------------------------------

    /** {@code out = (a + b) mod p}; inputs/outputs canonical limbs in {@code [0, p)}. */
    static void addModP(int N, int[] P_LIMBS, int[] out, int[] a, int[] b)
    {
        long carry = 0;
        long[] t = new long[N];
        for (int i = 0; i < N; i++)
        {
            long sum = (a[i] & 0xFFFFFFFFL) + (b[i] & 0xFFFFFFFFL) + carry;
            t[i] = sum & 0xFFFFFFFFL;
            carry = sum >>> 32;
        }
        if (carry != 0 || compareLimbsToP(N, P_LIMBS, t) >= 0)
        {
            subPInPlace(N, P_LIMBS, t);
        }
        for (int i = 0; i < N; i++)
        {
            out[i] = (int)t[i];
        }
    }

    /** {@code out = (a - b) mod p}; inputs/outputs canonical limbs in {@code [0, p)}. */
    static void subModP(int N, int[] P_LIMBS, int[] out, int[] a, int[] b)
    {
        long borrow = 0;
        long[] t = new long[N];
        for (int i = 0; i < N; i++)
        {
            long diff = (a[i] & 0xFFFFFFFFL) - (b[i] & 0xFFFFFFFFL) - borrow;
            t[i] = diff & 0xFFFFFFFFL;
            borrow = (diff >> 32) & 1L;
        }
        if (borrow != 0)
        {
            addPInPlace(N, P_LIMBS, t);
        }
        for (int i = 0; i < N; i++)
        {
            out[i] = (int)t[i];
        }
    }

    // ------------------------------------------------------------------
    // CIOS Montgomery multiplication (with p_prime = 1)
    // ------------------------------------------------------------------

    /**
     * Montgomery multiplication: {@code c = a * b * R^{-1} mod p} with
     * {@code R = 2^{32N}}. Inputs and output in Montgomery form, fully
     * reduced to {@code [0, p)}.
     *
     * <p>Standard CIOS (Koc/Acar/Kaliski 1996) with the per-loop
     * reduction multiplier {@code m = t[0]} (since {@code p_prime = 1}
     * for all three SQIsign primes).</p>
     */
    /**
     * Montgomery exponentiation: {@code out = base^exp mod p}. {@code base}
     * and {@code out} are in Montgomery form (i.e. they encode their
     * canonical value times R mod p); {@code exp} is a canonical
     * non-negative BigInteger. Uses left-to-right square-and-multiply.
     *
     * <p>For an n-bit exponent with k set bits, this performs n
     * squarings + k multiplications via {@link #mulMont}. For SQIsign
     * primes (lvl1 ~250 bits, lvl3 ~380 bits, lvl5 ~500 bits) and typical
     * exponents like {@code p-2}, {@code (p+1)/4}, {@code (p-1)/2} that's
     * ~1.5n mulMonts.</p>
     *
     * <p>Replaces calls to {@link java.math.BigInteger#modPow} /
     * {@link java.math.BigInteger#modInverse} in {@code FpLvlN.sqrt},
     * {@code progenitor}, {@code isSquare}, and {@code inv} — keeping
     * all operands in Mont domain avoids the per-call toMont/fromMont
     * round-trip that those BigInteger-bound paths used to pay.</p>
     */
    static void mulMontPow(int N, int[] P_LIMBS, int[] ONE_MONT,
                           int[] out, int[] base, BigInteger exp)
    {
        int[] result = new int[N];
        int[] tmp = new int[N];
        System.arraycopy(ONE_MONT, 0, result, 0, N); // result = 1 in Mont form

        int bitLen = exp.bitLength();
        for (int i = bitLen - 1; i >= 0; i--)
        {
            // result = result^2 (in Mont form)
            mulMont(N, P_LIMBS, tmp, result, result);
            int[] swap = result; result = tmp; tmp = swap;

            if (exp.testBit(i))
            {
                // result = result * base
                mulMont(N, P_LIMBS, tmp, result, base);
                int[] s2 = result; result = tmp; tmp = s2;
            }
        }
        System.arraycopy(result, 0, out, 0, N);
    }

    static void mulMont(int N, int[] P_LIMBS, int[] c, int[] a, int[] b)
    {
        long[] t = new long[N + 2];

        for (int i = 0; i < N; i++)
        {
            long bi = b[i] & 0xFFFFFFFFL;

            // Step 1: t += a * b[i]
            long carry = 0;
            for (int j = 0; j < N; j++)
            {
                long aj = a[j] & 0xFFFFFFFFL;
                long sum = t[j] + aj * bi + carry;
                t[j] = sum & 0xFFFFFFFFL;
                carry = sum >>> 32;
            }
            long sumN = t[N] + carry;
            t[N] = sumN & 0xFFFFFFFFL;
            t[N + 1] += sumN >>> 32;

            // Step 2: m = t[0] (p_prime = 1)
            long m = t[0] & 0xFFFFFFFFL;

            // Step 3: t = (t + m * p) >> 32
            carry = 0;
            for (int j = 0; j < N; j++)
            {
                long pj = P_LIMBS[j] & 0xFFFFFFFFL;
                long sum = t[j] + m * pj + carry;
                if (j == 0)
                {
                    carry = sum >>> 32;
                }
                else
                {
                    t[j - 1] = sum & 0xFFFFFFFFL;
                    carry = sum >>> 32;
                }
            }
            long sumNred = t[N] + carry;
            t[N - 1] = sumNred & 0xFFFFFFFFL;
            t[N] = (sumNred >>> 32) + t[N + 1];
            t[N + 1] = 0;
        }

        // Final conditional subtract — CIOS bound is t < 2p.
        if (t[N] != 0 || compareLimbsToP(N, P_LIMBS, t) >= 0)
        {
            subPInPlace(N, P_LIMBS, t);
        }

        for (int i = 0; i < N; i++)
        {
            c[i] = (int)t[i];
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    private static int compareLimbsToP(int N, int[] P_LIMBS, long[] t)
    {
        for (int i = N - 1; i >= 0; i--)
        {
            long ti = t[i] & 0xFFFFFFFFL;
            long pi = P_LIMBS[i] & 0xFFFFFFFFL;
            if (ti != pi)
            {
                return ti > pi ? 1 : -1;
            }
        }
        return 0;
    }

    private static void subPInPlace(int N, int[] P_LIMBS, long[] t)
    {
        long borrow = 0;
        for (int j = 0; j < N; j++)
        {
            long diff = t[j] - (P_LIMBS[j] & 0xFFFFFFFFL) - borrow;
            if (diff < 0)
            {
                t[j] = diff + (1L << 32);
                borrow = 1;
            }
            else
            {
                t[j] = diff;
                borrow = 0;
            }
        }
    }

    private static void addPInPlace(int N, int[] P_LIMBS, long[] t)
    {
        long carry = 0;
        for (int j = 0; j < N; j++)
        {
            long sum = t[j] + (P_LIMBS[j] & 0xFFFFFFFFL) + carry;
            t[j] = sum & 0xFFFFFFFFL;
            carry = sum >>> 32;
        }
    }
}
