package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

public class NTRUPlusEngine
{
    // TODO: Define these constants from the C code
    public static int NTRUPLUS_N = 768;
    public static short NTRUPLUS_Q = 12289;
    public static short NTRUPLUS_QINV = -12287;
    public static short NTRUPLUS_OMEGA = 49;
    public static short NTRUPLUS_Rinv = 0; // TODO: Set correct value
    public static short[] zetas = new short[192]; // TODO: Fill with actual values


    // Java representation of poly struct
    public static class Poly
    {
        public short[] coeffs; // Using short for int16_t

        public Poly()
        {
            // TODO: Replace with actual NTRUPLUS_N
            coeffs = new short[768]; // NTRUPLUS_N
        }
    }

    /*************************************************
     * Name:        genf_derand
     *
     * Description: Deterministically generates a secret polynomial f and its
     *              multiplicative inverse finv in the NTT domain.
     *
     * Returns 0 on success; non-zero if f is not invertible in the NTT domain.
     **************************************************/
    public static int genf_derand(Poly f, Poly finv, byte[] coins)
    {
        // coins should be 32 bytes
        byte[] buf = new byte[NTRUPLUS_N / 4];

        // TODO: Implement shake256 using BouncyCastle
        // shake256(buf, buf.length, coins, 32);

        poly_cbd1(f, buf);
        poly_triple(f, f);
        f.coeffs[0] += 1;

        poly_ntt(f, f);

        return poly_baseinv(finv, f);
    }

    /*************************************************
     * Name:        poly_cbd1
     *
     * Description: Sample a polynomial deterministically from a random,
     *              with output polynomial close to centered binomial distribution
     **************************************************/
    public static void poly_cbd1(Poly r, byte[] buf)
    {
        // buf should be of length NTRUPLUS_N/4 bytes
        int t1, t2;

        for (int i = 0; i < NTRUPLUS_N / 8; i++)
        {
            t1 = buf[i] & 0xFF;  // Convert to unsigned
            t2 = buf[i + NTRUPLUS_N / 8] & 0xFF;

            for (int j = 0; j < 8; j++)
            {
                r.coeffs[8 * i + j] = (short)((t1 & 0x1) - (t2 & 0x1));
                t1 >>= 1;
                t2 >>= 1;
            }
        }
    }

    /*************************************************
     * Name:        poly_triple
     *
     * Description: Multiply polynomial by 3; no modular reduction is performed
     **************************************************/
    public static void poly_triple(Poly r, Poly a)
    {
        for (int i = 0; i < NTRUPLUS_N; ++i)
        {
            r.coeffs[i] = (short)(3 * a.coeffs[i]);
        }
    }

    /*************************************************
     * Name:        poly_ntt
     *
     * Description: Computes number-theoretic transform (NTT)
     **************************************************/
    public static void poly_ntt(Poly r, Poly a)
    {
        ntt(r.coeffs, a.coeffs);
    }

    /*************************************************
     * Name:        ntt
     *
     * Description: Number-theoretic transform (NTT) in R_q.
     **************************************************/
    public static void ntt(short[] r, short[] a)
    {
        short t1, t2, t3;
        short zeta1, zeta2;
        int k = 1;

        zeta1 = zetas[k++];

        for (int i = 0; i < NTRUPLUS_N / 2; i++)
        {
            t1 = fqmul(zeta1, a[i + NTRUPLUS_N / 2]);

            r[i + NTRUPLUS_N / 2] = (short)(a[i] + a[i + NTRUPLUS_N / 2] - t1);
            r[i] = (short)(a[i] + t1);
        }

        for (int start = 0; start < NTRUPLUS_N; start += 384)
        {
            zeta1 = zetas[k++];
            zeta2 = zetas[k++];

            for (int i = start; i < start + 128; i++)
            {
                t1 = fqmul(zeta1, r[i + 128]);
                t2 = fqmul(zeta2, r[i + 256]);
                t3 = fqmul(NTRUPLUS_OMEGA, (short)(t1 - t2));

                r[i + 256] = (short)(r[i] - t1 - t3);
                r[i + 128] = (short)(r[i] - t2 + t3);
                r[i] = (short)(r[i] + t1 + t2);
            }
        }

        for (int step = 64; step >= 4; step >>= 1)
        {
            for (int start = 0; start < NTRUPLUS_N; start += (step << 1))
            {
                zeta1 = zetas[k++];

                for (int i = start; i < start + step; i++)
                {
                    t1 = fqmul(zeta1, r[i + step]);

                    r[i + step] = barrett_reduce((short)(r[i] - t1));
                    r[i] = barrett_reduce((short)(r[i] + t1));
                }
            }
        }
    }

    /*************************************************
     * Name:        fqmul
     *
     * Description: Multiplication followed by Montgomery reduction.
     *
     * Returns:     16-bit integer congruent to a*b*R^-1 mod q.
     **************************************************/
    public static short fqmul(short a, short b)
    {
        return montgomery_reduce((int)a * b);
    }

    /*************************************************
     * Name:        montgomery_reduce
     *
     * Description: Montgomery reduction; given a 32-bit integer a, computes
     *              a 16-bit integer congruent to a * R^-1 mod q,
     *              where R = 2^16.
     **************************************************/
    public static short montgomery_reduce(int a)
    {
        short t;

        t = (short)(a * NTRUPLUS_QINV);
        t = (short)((a - (int)t * NTRUPLUS_Q) >> 16);
        return t;
    }

    /*************************************************
     * Name:        barrett_reduce
     *
     * Description: Barrett reduction; given a 16-bit integer a, computes a
     *              centered representative congruent to a mod q.
     **************************************************/
    public static short barrett_reduce(short a)
    {
        short t;
        final short v = (short)(((1 << 26) + NTRUPLUS_Q / 2) / NTRUPLUS_Q);

        t = (short)(((int)v * a + (1 << 25)) >> 26);
        t *= NTRUPLUS_Q;
        return (short)(a - t);
    }

    /*************************************************
     * Name:        poly_baseinv
     *
     * Description: Inversion of polynomial in NTT domain
     **************************************************/
    public static int poly_baseinv(Poly r, Poly a)
    {
        for (int i = 0; i < NTRUPLUS_N / 8; ++i)
        {
            short[] r_temp = new short[4];
            short[] a_temp = Arrays.copyOfRange(a.coeffs, 8 * i, 8 * i + 4);

            if (baseinv(r_temp, a_temp, zetas[96 + i]) != 0)
            {
                Arrays.fill(r.coeffs, (short)0);
                return 1;
            }
            System.arraycopy(r_temp, 0, r.coeffs, 8 * i, 4);

            a_temp = Arrays.copyOfRange(a.coeffs, 8 * i + 4, 8 * i + 8);
            if (baseinv(r_temp, a_temp, (short)-zetas[96 + i]) != 0)
            {
                Arrays.fill(r.coeffs, (short)0);
                return 1;
            }
            System.arraycopy(r_temp, 0, r.coeffs, 8 * i + 4, 4);
        }

        return 0;
    }

    /*************************************************
     * Name:        baseinv
     *
     * Description: Inversion of a polynomial in Zq[X]/(X^4 - zeta)
     *
     * Returns:     0 if a is invertible, 1 otherwise.
     **************************************************/
    public static int baseinv(short[] r, short[] a, short zeta)
    {
        short t0, t1, t2, t3;

        t0 = montgomery_reduce(a[2] * a[2] - 2 * a[1] * a[3]);
        t1 = montgomery_reduce(a[3] * a[3]);
        t0 = montgomery_reduce(a[0] * a[0] + t0 * zeta);
        t1 = montgomery_reduce(a[1] * a[1] + t1 * zeta - 2 * a[0] * a[2]);
        t2 = montgomery_reduce(t1 * zeta);

        t3 = montgomery_reduce(t0 * t0 - t1 * t2);

        if (t3 == 0)
        {
            return 1;
        }

        r[0] = montgomery_reduce(a[0] * t0 + a[2] * t2);
        r[1] = montgomery_reduce(a[3] * t2 + a[1] * t0);
        r[2] = montgomery_reduce(a[2] * t0 + a[0] * t1);
        r[3] = montgomery_reduce(a[1] * t1 + a[3] * t0);

         t3 = fqinv(t3);
         t3 = montgomery_reduce(t3 * NTRUPLUS_Rinv);

        r[0] = montgomery_reduce(r[0] * t3);
        r[1] = (short)-montgomery_reduce(r[1] * t3);
        r[2] = montgomery_reduce(r[2] * t3);
        r[3] = (short)-montgomery_reduce(r[3] * t3);

        return 0;
    }

    public static void shake256(byte[] output, int outLen, byte[] input, int inLen) {
        // Initialize the SHAKE256 digest with the desired output length.
        // Important: Specifying the output length here is necessary for correct functionality[citation:2].
        SHAKEDigest shakeDigest = new SHAKEDigest(256);

        // Feed the input data into the digest.
        // The API uses (data, offset, length). We use offset 0.
        shakeDigest.update(input, 0, inLen);

        // Finalize the hash and write the output.
        // The doFinal method performs the final calculation and resets the digest.
        shakeDigest.doFinal(output, 0, outLen);
    }

    /**
     * Computes the multiplicative inverse of a value in the finite field Z_q,
     * using Montgomery arithmetic.
     *
     * The input is an ordinary field element x (no scaling), and the function
     * returns x^{-1} scaled by R^2 modulo q, where R = 2^16 is the Montgomery radix.
     *
     * @param a The input value a = x mod q, as a signed 16-bit integer.
     * @return A 16-bit integer congruent to x^{-1} * R^2 mod q.
     */
    public static short fqinv(short a) {
        short t1, t2, t3;

        // Follow the exact exponentiation sequence from the original C code
        // This efficiently computes a^(q-2) mod q using a fixed addition chain.
        t1 = fqmul(a, a);      // a^2
        t2 = fqmul(t1, t1);    // a^4
        t2 = fqmul(t2, t2);    // a^8
        t3 = fqmul(t2, t2);    // a^16

        t1 = fqmul(t1, t2);    // a^10

        t2 = fqmul(t1, t3);    // a^26
        t2 = fqmul(t2, t2);    // a^52
        t2 = fqmul(t2, a);     // a^53

        t1 = fqmul(t1, t2);    // a^63

        t2 = fqmul(t2, t2);    // a^106
        t2 = fqmul(t2, t2);    // a^212
        t2 = fqmul(t2, t2);    // a^424
        t2 = fqmul(t2, t2);    // a^848
        t2 = fqmul(t2, t2);    // a^1696
        t2 = fqmul(t2, t2);    // a^3392
        t2 = fqmul(t2, t1);    // a^3455

        return t2;
    }
}
