package org.bouncycastle.pqc.crypto.haetae;

import org.bouncycastle.crypto.digests.SHAKEDigest;

public class HAETAEEngine
{
    private final HAETAEParameters params;
    private static final int SHAKE128_RATE = 168; // bytes per block
    private static final int SHAKE256_RATE = 136; // bytes per block
    private static final int QINV = 940508161;
    // f = mont^2 / 256  where mont = 2^32 mod Q
    // For HAETAE Q=64513, f is given as -29720
    private static final int F = -29720;

    // QREC = ceil(2^32 / HAETAE_Q) used in freeze()
    private static final int QREC = 66575;

    private static final int[] ZETAS = {
        0, 26964, -16505, 22229, 30746, 20243, 19064, -31218, 9395,
        -30985, 22859, -8851, 32144, 13744, 21408, 17599, -16039, -22946,
        6241, -19553, 10681, 22935, 22431, -29104, 28147, -27527, -29133,
        -20035, 20143, -11361, 30820, 25252, -22562, -6789, -10049, 9383,
        16304, -12296, 16446, 18239, -1296, -19725, -32076, 11782, -17941,
        29643, -8577, 7893, -21464, -19646, -15130, -2391, 30608, -23970,
        -16608, 19616, -7941, 26533, -19129, 27690, 7597, -11459, 10615,
        -9430, 11591, 7814, 12697, 32114, -3761, -9604, 19813, 20353,
        17456, -16267, -19555, 598, -29942, 4538, 835, 15546, 3970,
        -27685, 1488, 8311, -12442, 31352, -17631, 1806, -5342, 9790,
        29068, 16507, -29051, 22131, 6759, 15510, -14941, 28710, 1160,
        -31327, 24985, 11261, -10623, -27727, 21502, 18731, -16186, -4127,
        -18832, 12050, -14501, 7929, 29563, -31064, 5913, 5322, -16405,
        2844, 29439, 5876, -9522, -18586, -9874, 23844, 30362, -21442,
        9560, 17671, -27989, 3350, 787, -13857, 1657, -21224, -7374,
        -9190, 2464, 25555, -3529, -28772, 16588, -15739, 23475, 13666,
        5764, 30980, 13633, -7401, -30317, 28847, 7682, -11808, -8796,
        14864, -24162, -19194, 689, -1311, -31332, -16319, 1025, 10971,
        -23016, -2648, -21900, -12543, -25921, 28254, 28521, -16160, 12380,
        -12882, -30332, -16630, 23439, 7742, 17182, 17494, 5920, 13642,
        7382, -18166, 21422, -30274, -28190, 13283, -20316, -9939, 10672,
        21454, 6080, -17374, -29735, -25912, -10170, 3808, 10639, -26985,
        -10865, 25636, 17261, -26851, -8253, -3304, 18282, -2202, -31368,
        -22243, 13882, 12069, -11242, -7729, -10226, 1761, -27298, -4800,
        -17737, -22805, -3528, 65, 10770, 8908, -23751, 26934, 21921,
        -27010, -21944, 8889, -1035, 23224, -9488, -5823, -994, -20206,
        7655, -16251, -22820, -27740, 15822, 23078, 13803, -8099, 2931,
        9217, -21126, -14203, 25492, -12831, 7947, 17463, -12979, 29003,
        31612, 26554, 8241, -20175};

    public HAETAEEngine(HAETAEParameters params)
    {
        this.params = params;
    }

    /**
     * Expands matrix A of size K x M using seed rho.
     * matA[i][j] is a polynomial (int array of length N).
     *
     * @param matA output array: [K][M][N]
     * @param rho  seed of length SEED_BYTES
     */
    public void polymatkm_expand_matA(int[][][] matA, byte[] rho)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < params.getM(); j++)
            {
                poly_uniform(matA[i][j], rho, (short)((i << 8) + j));
            }
        }
    }

    /**
     * Fills polynomial a with coefficients uniformly in [0, Q-1].
     *
     * @param a     output polynomial (length N)
     * @param seed  seed of length SEED_BYTES
     * @param nonce 16-bit domain separator
     */
    public void poly_uniform(int[] a, byte[] seed, short nonce)
    {
        // Initialize SHAKE-128 with seed and nonce
        SHAKEDigest shake = new SHAKEDigest(128);
        shake.update(seed, 0, HAETAEParameters.SEED_BYTES);
        // nonce as 2 bytes little-endian
        shake.update((byte)(nonce & 0xFF));
        shake.update((byte)((nonce >> 8) & 0xFF));

        // Buffer to hold one block plus leftover bytes
        byte[] buf = new byte[SHAKE128_RATE + 2];
        int bufPos = 0;
        int bufLen = 0;
        int ctr = 0;

        while (ctr < HAETAEParameters.N)
        {
            // If not enough bytes for next coefficient, refill buffer
            if (bufLen - bufPos < 2)
            {
                // Move remaining bytes to start of buffer
                int rem = bufLen - bufPos;
                if (rem > 0)
                {
                    System.arraycopy(buf, bufPos, buf, 0, rem);
                }
                // Squeeze one full block (SHAKE128_RATE bytes) after the remainder
                shake.doOutput(buf, rem, SHAKE128_RATE);
                bufPos = 0;
                bufLen = rem + SHAKE128_RATE;
            }

            // Read 16-bit little-endian value
            int t = (buf[bufPos++] & 0xFF) | ((buf[bufPos++] & 0xFF) << 8);
            if (t < HAETAEParameters.Q)
            {
                a[ctr++] = t;
            }
        }
    }

    /**
     * Rejection sampling helper (used internally).
     * Returns number of accepted coefficients.
     */
    private int rej_uniform(int[] a, int start, int len, byte[] buf, int buflen)
    {
        int ctr = 0;
        int pos = 0;
        while (ctr < len && pos + 1 < buflen)
        {
            int t = (buf[pos++] & 0xFF) | ((buf[pos++] & 0xFF) << 8);
            if (t < HAETAEParameters.Q)
            {
                a[start + ctr] = t;
                ctr++;
            }
        }
        return ctr;
    }


    /**
     * Expands secret vectors u (size M) and v (size K) using SHAKE-256.
     *
     * @param u     output vector u: [M][N]
     * @param v     output vector v: [K][N]
     * @param seed  seed of length CRH_BYTES (64 bytes)
     * @param nonce starting nonce (incremented for each polynomial)
     */
    public void polyvecmk_expand_S(int[][] u, int[][] v, byte[] seed, short nonce)
    {
        int n = nonce & 0xFFFF;
        for (int i = 0; i < params.getM(); i++)
        {
            poly_uniform_eta(u[i], seed, (short)n++);
        }
        for (int i = 0; i < params.getK(); i++)
        {
            poly_uniform_eta(v[i], seed, (short)n++);
        }
    }

    /**
     * Fills polynomial a with coefficients in {-1, 0, 1} using rejection sampling.
     *
     * @param a     output polynomial (length N)
     * @param seed  seed of length CRH_BYTES
     * @param nonce 16-bit domain separator
     */
    public void poly_uniform_eta(int[] a, byte[] seed, short nonce)
    {
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(seed, 0, HAETAEParameters.CRH_BYTES);
        shake.update((byte)(nonce & 0xFF));
        shake.update((byte)((nonce >> 8) & 0xFF));

        // Buffer large enough for one block plus leftover bytes
        byte[] buf = new byte[SHAKE256_RATE + 4];
        int bufPos = 0;
        int bufLen = 0;
        int ctr = 0;

        while (ctr < HAETAEParameters.N)
        {
            // If buffer is empty or nearly exhausted, refill
            if (bufLen - bufPos < 1)
            {
                // Move any remaining bytes to the start
                int rem = bufLen - bufPos;
                if (rem > 0)
                {
                    System.arraycopy(buf, bufPos, buf, 0, rem);
                }
                // Squeeze one full block (SHAKE256_RATE bytes)
                shake.doOutput(buf, rem, SHAKE256_RATE);
                bufPos = 0;
                bufLen = rem + SHAKE256_RATE;
            }

            int t = buf[bufPos++] & 0xFF;
            if (t < 243)
            {
                // Process up to 5 coefficients from this byte
                // First coefficient
                a[ctr++] = mod3(t);
                if (ctr >= HAETAEParameters.N)
                {
                    break;
                }

                // Second coefficient
                int t2 = (t * 171) >>> 9;  // equivalent to (t * 171) >> 9
                a[ctr++] = mod3(t2);
                if (ctr >= HAETAEParameters.N)
                {
                    break;
                }

                // Third coefficient
                t2 = (t2 * 171) >>> 9;
                a[ctr++] = mod3_leq26(t2);
                if (ctr >= HAETAEParameters.N)
                {
                    break;
                }

                // Fourth coefficient
                t2 = (t2 * 171) >>> 9;
                a[ctr++] = mod3_leq8(t2);
                if (ctr >= HAETAEParameters.N)
                {
                    break;
                }

                // Fifth coefficient
                t2 = (t2 * 171) >>> 9;
                a[ctr++] = t2 - 3 * (t2 >>> 1);
            }
        }
    }

    /**
     * Reduce an unsigned byte modulo 3 (value may be up to 255).
     * Returns a value in {0, 1, 2}.
     */
    private static int mod3(int t)
    {
        int r = (t >>> 4) + (t & 0xF);
        r = (r >>> 2) + (r & 3);
        r = (r >>> 2) + (r & 3);
        r = (r >>> 2) + (r & 3);
        return r - 3 * (r >>> 1);
    }

    /**
     * Reduce a value t ≤ 26 modulo 3.
     */
    private static int mod3_leq26(int t)
    {
        int r = (t >>> 4) + (t & 0xF);
        r = (r >>> 2) + (r & 3);
        r = (r >>> 2) + (r & 3);
        return r - 3 * (r >>> 1);
    }

    /**
     * Reduce a value t ≤ 8 modulo 3.
     */
    private static int mod3_leq8(int t)
    {
        int r = (t >>> 2) + (t & 3);
        r = (r >>> 2) + (r & 3);
        return r - 3 * (r >>> 1);
    }

    /**
     * Montgomery reduction: maps a 64‑bit value to [0, Q-1].
     * <p>
     * Computes (a * QINV) mod 2^32, multiplies by Q, subtracts from a,
     * and takes the upper 32 bits.
     * </p>
     *
     * @param a 64‑bit signed integer (product of two ints)
     * @return reduced value modulo Q in [0, Q-1]
     */
    private static int montgomeryReduce(long a)
    {
        int t = (int)a * QINV;          // low 32 bits of a * QINV
        long tt = a - ((long)t * HAETAEParameters.Q);
        return (int)(tt >> 32);
    }

    /**
     * In‑place forward NTT on an array of length N = 256.
     *
     * @param a input/output array (modified in place)
     */
    private void ntt(int[] a)
    {
        int k = 0, j;
        for (int len = 128; len > 0; len >>= 1)
        {
            for (int start = 0; start < HAETAEParameters.N; start = j + len)
            {
                int zeta = ZETAS[++k];
                for (j = start; j < start + len; ++j)
                {
                    int t = montgomeryReduce((long)zeta * a[j + len]);
                    a[j + len] = a[j] - t;
                    a[j] = a[j] + t;
                }
            }
        }
    }

    /**
     * Applies NTT to a single polynomial.
     *
     * @param a polynomial (int array of length N)
     */
    public void polyNtt(int[] a)
    {
        ntt(a);
    }

    /**
     * Applies NTT to a polynomial vector of length M.
     *
     * @param x vector of M polynomials (2D int array: [M][N])
     */
    public void polyvecmNtt(int[][] x)
    {
        for (int i = 0; i < params.getM(); i++)
        {
            polyNtt(x[i]);
        }
    }

    /**
     * Applies NTT to a polynomial vector of length K.
     *
     * @param x vector of K polynomials (2D int array: [K][N])
     */
    public void polyveckNtt(int[][] x)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyNtt(x[i]);
        }
    }

    /**
     * Computes t = mat * v  (matrix-vector product in NTT domain).
     *
     * @param t   output vector of length K (each polynomial of length N)
     * @param mat matrix of size K x M (each entry is a polynomial)
     * @param v   input vector of length M
     */
    public void polymatkmPointwiseMontgomery(int[][] t, int[][][] mat, int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyvecmPointwiseAccMontgomery(t[i], mat[i], v);
        }
    }

    /**
     * Accumulates pointwise products of two polynomial vectors u and v into w.
     * w = sum_{j=0}^{M-1} (u_j ∘ v_j)   (pointwise multiplication)
     *
     * @param w output polynomial (length N)
     * @param u first vector (M polynomials)
     * @param v second vector (M polynomials)
     */
    private void polyvecmPointwiseAccMontgomery(int[] w, int[][] u, int[][] v)
    {
        // w = u[0] ∘ v[0]
        polyPointwiseMontgomery(w, u[0], v[0]);

        // temporary polynomial for intermediate results
        int[] t = new int[HAETAEParameters.N];

        for (int j = 1; j < params.getM(); j++)
        {
            polyPointwiseMontgomery(t, u[j], v[j]);
            polyAdd(w, w, t);
        }
    }

    /**
     * Pointwise multiplication of two polynomials: c[i] = a[i] * b[i] mod Q.
     * Coefficients are assumed to be in Montgomery domain.
     *
     * @param c output polynomial (length N)
     * @param a first input polynomial
     * @param b second input polynomial
     */
    private void polyPointwiseMontgomery(int[] c, int[] a, int[] b)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            c[i] = montgomeryReduce((long)a[i] * b[i]);
        }
    }

    /**
     * Adds two polynomials: c = a + b.
     * No modular reduction is performed; coefficients may exceed Q.
     * (Used internally in accumulation.)
     *
     * @param c result polynomial (may alias a or b)
     * @param a first polynomial
     * @param b second polynomial
     */
    private void polyAdd(int[] c, int[] a, int[] b)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            c[i] = a[i] + b[i];
        }
    }

    /**
     * Inverse NTT and multiplication by Montgomery factor 2^32.
     * In-place. Input coefficients are expected to be small enough.
     *
     * @param a polynomial coefficients (length N)
     */
    private void invnttTomont(int[] a)
    {
        int k = 256, j;
        for (int len = 1; len < HAETAEParameters.N; len <<= 1)
        {
            for (int start = 0; start < HAETAEParameters.N; start = j + len)
            {
                int zeta = -ZETAS[--k];
                for (j = start; j < start + len; j++)
                {
                    int t = a[j];
                    a[j] = t + a[j + len];
                    a[j + len] = t - a[j + len];
                    a[j + len] = montgomeryReduce((long)zeta * a[j + len]);
                }
            }
        }

        // Multiply by f = mont^2 / 256
        for (j = 0; j < HAETAEParameters.N; j++)
        {
            a[j] = montgomeryReduce((long)F * a[j]);
        }
    }

    /**
     * Applies inverse NTT + Montgomery factor to a single polynomial.
     *
     * @param a polynomial (length N)
     */
    public void polyInvnttTomont(int[] a)
    {
        invnttTomont(a);
    }

    /**
     * Applies inverse NTT + Montgomery factor to a polynomial vector of length K.
     *
     * @param x vector of K polynomials (K x N)
     */
    public void polyveckInvnttTomont(int[][] x)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyInvnttTomont(x[i]);
        }
    }

    /**
     * Vector addition: w = u + v (element-wise, no reduction).
     *
     * @param w result vector (may alias u or v)
     * @param u first operand
     * @param v second operand
     */
    public void polyveckAdd(int[][] w, int[][] u, int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyAdd(w[i], u[i], v[i]);
        }
    }

    /**
     * Freezes a polynomial vector: reduces each coefficient to [0, Q-1].
     *
     * @param v vector of K polynomials
     */
    public void polyveckFreeze(int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyFreeze(v[i]);
        }
    }

    /**
     * Freezes a polynomial: reduces each coefficient to [0, Q-1].
     *
     * @param a polynomial (length N)
     */
    public void polyFreeze(int[] a)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            a[i] = freeze(a[i]);
        }
    }

    /**
     * Standard representative r = a mod^+ Q.
     * Assumes input is in range [-2Q, 2Q] (or similar).
     *
     * @param a finite field element
     * @return r in [0, Q-1]
     */
    private int freeze(int a)
    {
        // t = (a * QREC) >> 32  (approximate division by Q)
        long t = ((long)a * QREC) >> 32;
        long r = a - t * HAETAEParameters.Q;          // -2Q < r < 2Q
        r += (r >> 31) & HAETAEParameters.DQ;         // 0 <= r < 2Q
        r -= ~((r - HAETAEParameters.Q) >> 31) & HAETAEParameters.Q; // 0 <= r < Q
        return (int)r;
    }
}
