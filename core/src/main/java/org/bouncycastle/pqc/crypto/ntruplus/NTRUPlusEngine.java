package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

public class NTRUPlusEngine
{
    // TODO: Define these constants from the C code
    public int NTRUPLUS_N;
    public short NTRUPLUS_Q;
    public short NTRUPLUS_QINV;
    public short NTRUPLUS_OMEGA;
    public short NTRUPLUS_Rinv;
    public short NTRUPLUS_POLYBYTES;
    public short NTRUPLUS_Rsq;
    public short[] zetas;
    private NTRUPlusParameters params;

    public NTRUPlusEngine(NTRUPlusParameters params)
    {
        this.params = params;
        this.NTRUPLUS_N = params.getN();
        this.NTRUPLUS_Q = (short)params.getQ();
        this.NTRUPLUS_QINV = (short)params.getQInv();
        this.NTRUPLUS_OMEGA = (short)params.getOmega();
        this.NTRUPLUS_Rinv = (short)params.getRInv();
        this.NTRUPLUS_POLYBYTES = (short)params.getPolyBytes();
        this.NTRUPLUS_Rsq = (short)params.getRSquared();
        this.zetas = params.getZetas();
    }

    // Java representation of poly struct
    public static class Poly
    {
        public short[] coeffs; // Using short for int16_t

        public Poly(int NTRUPLUS_N)
        {
            coeffs = new short[NTRUPLUS_N]; // NTRUPLUS_N
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
    public int genf_derand(Poly f, Poly finv, byte[] coins)
    {
        // coins should be 32 bytes
        byte[] buf = new byte[NTRUPLUS_N / 4];

        shake256(buf, 0, buf.length, coins, 32);

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
    public void poly_cbd1(Poly r, byte[] buf)
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
    public void poly_triple(Poly r, Poly a)
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
    public void poly_ntt(Poly r, Poly a)
    {
        ntt(r.coeffs, a.coeffs);
    }

    /**
     * Number-theoretic transform (NTT) in R_q.
     * Transforms the coefficient representation into NTT representation.
     * <p>
     * This merged function supports N=768 (4-coefficient blocks),
     * N=864 (3-coefficient blocks), and N=1152 (4-coefficient blocks).
     *
     * @param r Output vector in NTT representation
     * @param a Input vector of coefficients in R_q
     */
    private void ntt(short[] r, short[] a)
    {
        int n = params.getN();
        int q = params.getQ();
        short omega = (short)params.getOmega();

        short t1, t2, t3;
        short zeta1, zeta2;
        int k = 1;

        // Copy input to output for all cases
        if (a != r)
        {
            System.arraycopy(a, 0, r, 0, n);
        }

        // Initial butterfly: all N values use this
        zeta1 = zetas[k++];

        for (int i = 0; i < n / 2; i++)
        {
            t1 = fqmul(zeta1, a[i + n / 2]);
            r[i + n / 2] = (short)(a[i] + a[i + n / 2] - t1);
            r[i] = (short)(a[i] + t1);
        }

        // Process based on N value
        if (n == 768)
        {
            // N=768: process 384-coefficient blocks
            for (int start = 0; start < n; start += 384)
            {
                zeta1 = zetas[k++];
                zeta2 = zetas[k++];

                for (int i = start; i < start + 128; i++)
                {
                    t1 = fqmul(zeta1, r[i + 128]);
                    t2 = fqmul(zeta2, r[i + 256]);
                    t3 = fqmul(omega, (short)(t1 - t2));

                    r[i + 256] = (short)(r[i] - t1 - t3);
                    r[i + 128] = (short)(r[i] - t2 + t3);
                    r[i] = (short)(r[i] + t1 + t2);
                }
            }

            // Final butterflies: step from 64 down to 4
            for (int step = 64; step >= 4; step >>= 1)
            {
                for (int start = 0; start < n; start += (step << 1))
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
        else if (n == 864)
        {
            // N=864: process with 3-coefficient blocks
            for (int step = n / 6; step >= 48; step /= 3)
            {
                for (int start = 0; start < n; start += 3 * step)
                {
                    zeta1 = zetas[k++];
                    zeta2 = zetas[k++];

                    for (int i = start; i < start + step; i++)
                    {
                        t1 = fqmul(zeta1, r[i + step]);
                        t2 = fqmul(zeta2, r[i + 2 * step]);
                        t3 = fqmul(omega, (short)(t1 - t2));

                        r[i + 2 * step] = (short)(r[i] - t1 - t3);
                        r[i + step] = (short)(r[i] - t2 + t3);
                        r[i] = (short)(r[i] + t1 + t2);
                    }
                }
            }

            // Final butterflies: step from 24 down to 3
            for (int step = 24; step >= 3; step >>= 1)
            {
                for (int start = 0; start < n; start += (step << 1))
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
        else if (n == 1152)
        {
            // N=1152: process with division by 3
            for (int step = n / 6; step >= 64; step /= 3)
            {
                for (int start = 0; start < n; start += 3 * step)
                {
                    zeta1 = zetas[k++];
                    zeta2 = zetas[k++];

                    for (int i = start; i < start + step; i++)
                    {
                        t1 = fqmul(zeta1, r[i + step]);
                        t2 = fqmul(zeta2, r[i + 2 * step]);
                        t3 = fqmul(omega, (short)(t1 - t2));

                        r[i + 2 * step] = (short)(r[i] - t1 - t3);
                        r[i + step] = (short)(r[i] - t2 + t3);
                        r[i] = (short)(r[i] + t1 + t2);
                    }
                }
            }

            // Final butterflies: step from 32 down to 4
            for (int step = 32; step >= 4; step >>= 1)
            {
                for (int start = 0; start < n; start += (step << 1))
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
        else
        {
            throw new IllegalArgumentException("Unsupported N value: " + n);
        }
    }

    /*************************************************
     * Name:        fqmul
     *
     * Description: Multiplication followed by Montgomery reduction.
     *
     * Returns:     16-bit integer congruent to a*b*R^-1 mod q.
     **************************************************/
    public short fqmul(short a, short b)
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
    public short montgomery_reduce(int a)
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
    public short barrett_reduce(short a)
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
    private int poly_baseinv(Poly r, Poly a)
    {
        int n = params.getN();

        if (n == 864)
        {
            // Special handling for N=864 with 3-coefficient blocks
            for (int i = 0; i < n / 6; ++i)
            {
                // Use baseinv3 for 3-coefficient blocks
                if (baseinv3(r.coeffs, 6 * i, a.coeffs, 6 * i, zetas[144 + i]) == 1)
                {
                    Arrays.fill(r.coeffs, (short)0);
                    return 1;
                }

                if (baseinv3(r.coeffs, 6 * i + 3, a.coeffs, 6 * i + 3,
                    (short)-zetas[144 + i]) == 1)
                {
                    Arrays.fill(r.coeffs, (short)0);
                    return 1;
                }
            }
        }
        else
        {
            // Use existing logic for N=768 and N=1152
            int blockSize = 8;
            int numBlocks = n / 8;
            int zetaOffset = (n == 768) ? 96 : 144;

            for (int i = 0; i < numBlocks; ++i)
            {
                if (baseinv(r.coeffs, 8 * i, a.coeffs, 8 * i,
                    zetas[zetaOffset + i]) == 1)
                {
                    Arrays.fill(r.coeffs, (short)0);
                    return 1;
                }

                if (baseinv(r.coeffs, 8 * i + 4, a.coeffs, 8 * i + 4,
                    (short)-zetas[zetaOffset + i]) == 1)
                {
                    Arrays.fill(r.coeffs, (short)0);
                    return 1;
                }
            }
        }

        return 0;
    }

    /**
     * Inversion of a polynomial in Zq[X]/(X^3 - zeta), used as
     * a building block for inversion of elements in R_q in the NTT domain.
     * This version is specifically for N=864 with 3-coefficient blocks.
     *
     * @param r    Output polynomial array (3 elements)
     * @param rPos Starting position in r array
     * @param a    Input polynomial array (3 elements)
     * @param aPos Starting position in a array
     * @param zeta Parameter defining X^3 - zeta
     * @return 0 if a is invertible, 1 otherwise
     */
    private int baseinv3(short[] r, int rPos, short[] a, int aPos, short zeta)
    {
        short t;

        // Extract coefficients from input array
        short a0 = a[aPos];
        short a1 = a[aPos + 1];
        short a2 = a[aPos + 2];

        // Step 1: Compute initial values with Montgomery reduction
        // r[0] = montgomery_reduce(a[1]*a[2]);
        r[rPos] = montgomery_reduce(a1 * a2);

        // r[1] = montgomery_reduce(a[2]*a[2]);
        r[rPos + 1] = montgomery_reduce(a2 * a2);

        // r[2] = montgomery_reduce(a[1]*a[1] - a[0]*a[2]);
        r[rPos + 2] = montgomery_reduce(a1 * a1 - a0 * a2);

        // Step 2: Apply zeta transformations
        // r[0] = montgomery_reduce(a[0]*a[0] - r[0]*zeta);
        r[rPos] = montgomery_reduce(a0 * a0 - r[rPos] * zeta);

        // r[1] = montgomery_reduce(r[1]*zeta - a[0]*a[1]);
        r[rPos + 1] = montgomery_reduce(r[rPos + 1] * zeta - a0 * a1);

        // Step 3: Compute determinant (t)
        // t = montgomery_reduce(r[2]*a[1] + r[1]*a[2]);
        t = montgomery_reduce(r[rPos + 2] * a1 + r[rPos + 1] * a2);

        // t = montgomery_reduce(t*zeta + r[0]*a[0]);
        t = montgomery_reduce(t * zeta + r[rPos] * a0);

        // Step 4: Check if invertible
        if (t == 0)
        {
            return 1; // Not invertible
        }

        // Step 5: Compute inverse scaling
        // t = fqinv(t);
        t = fqinv(t);

        // t = montgomery_reduce(t * NTRUPLUS_Rinv);
        t = montgomery_reduce(t * params.getRInv());

        // Step 6: Apply final scaling
        // r[0] = montgomery_reduce(r[0] * t);
        r[rPos] = montgomery_reduce(r[rPos] * t);

        // r[1] = montgomery_reduce(r[1] * t);
        r[rPos + 1] = montgomery_reduce(r[rPos + 1] * t);

        // r[2] = montgomery_reduce(r[2] * t);
        r[rPos + 2] = montgomery_reduce(r[rPos + 2] * t);

        return 0; // Success
    }

    /*************************************************
     * Name:        baseinv
     *
     * Description: Inversion of a polynomial in Zq[X]/(X^4 - zeta)
     *
     * Returns:     0 if a is invertible, 1 otherwise.
     **************************************************/
    public int baseinv(short[] r, int rOff, short[] a, int aOff, short zeta)
    {
        short t0, t1, t2, t3;

        t0 = montgomery_reduce(a[aOff + 2] * a[aOff + 2] - 2 * a[aOff + 1] * a[aOff + 3]);
        t1 = montgomery_reduce(a[aOff + 3] * a[aOff + 3]);
        t0 = montgomery_reduce(a[aOff + 0] * a[aOff + 0] + t0 * zeta);
        t1 = montgomery_reduce(a[aOff + 1] * a[aOff + 1] + t1 * zeta - 2 * a[aOff + 0] * a[aOff + 2]);
        t2 = montgomery_reduce(t1 * zeta);

        t3 = montgomery_reduce(t0 * t0 - t1 * t2);

        if (t3 == 0)
        {
            return 1;
        }

        r[rOff + 0] = montgomery_reduce(a[aOff + 0] * t0 + a[aOff + 2] * t2);
        r[rOff + 1] = montgomery_reduce(a[aOff + 3] * t2 + a[aOff + 1] * t0);
        r[rOff + 2] = montgomery_reduce(a[aOff + 2] * t0 + a[aOff + 0] * t1);
        r[rOff + 3] = montgomery_reduce(a[aOff + 1] * t1 + a[aOff + 3] * t0);

        t3 = fqinv(t3);
        t3 = montgomery_reduce(t3 * NTRUPLUS_Rinv);

        r[rOff + 0] = montgomery_reduce(r[rOff + 0] * t3);
        r[rOff + 1] = (short)-montgomery_reduce(r[rOff + 1] * t3);
        r[rOff + 2] = montgomery_reduce(r[rOff + 2] * t3);
        r[rOff + 3] = (short)-montgomery_reduce(r[rOff + 3] * t3);

        return 0;
    }

    public static void shake256(byte[] output, int outOff, int outLen, byte[] input, int inLen)
    {
        // Initialize the SHAKE256 digest with the desired output length.
        // Important: Specifying the output length here is necessary for correct functionality[citation:2].
        SHAKEDigest shakeDigest = new SHAKEDigest(256);

        // Feed the input data into the digest.
        // The API uses (data, offset, length). We use offset 0.
        shakeDigest.update(input, 0, inLen);

        // Finalize the hash and write the output.
        // The doFinal method performs the final calculation and resets the digest.
        shakeDigest.doFinal(output, outOff, outLen);
    }

    /**
     * Computes the multiplicative inverse of a value in the finite field Z_q,
     * using Montgomery arithmetic.
     * <p>
     * The input is an ordinary field element x (no scaling), and the function
     * returns x^{-1} scaled by R^2 modulo q, where R = 2^16 is the Montgomery radix.
     *
     * @param a The input value a = x mod q, as a signed 16-bit integer.
     * @return A 16-bit integer congruent to x^{-1} * R^2 mod q.
     */
    public short fqinv(short a)
    {
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

    /**
     * Multiplication of two polynomials in NTT domain
     */
    /**
     * Multiplication of two polynomials in NTT domain.
     * This merged function supports all three parameter sets:
     * - N=768: 8-coefficient blocks, zeta offset 96
     * - N=864: 6-coefficient blocks, zeta offset 144
     * - N=1152: 8-coefficient blocks, zeta offset 144
     * <p>
     * All cases perform: r = a * b (in NTT domain)
     *
     * @param r Output polynomial
     * @param a First input polynomial
     * @param b Second input polynomial
     */
    private void poly_basemul(Poly r, Poly a, Poly b)
    {
        int n = params.getN();

        if (n == 768)
        {
            // N=768: 8-coefficient blocks divided into two 4-coefficient parts
            // Zeta offset: 96
            for (int i = 0; i < n / 8; ++i)
            {
                // First half of block with positive zeta
                basemul(r.coeffs, 8 * i,
                    a.coeffs, 8 * i,
                    b.coeffs, 8 * i,
                    zetas[96 + i]);

                // Second half of block with negative zeta
                basemul(r.coeffs, 8 * i + 4,
                    a.coeffs, 8 * i + 4,
                    b.coeffs, 8 * i + 4,
                    (short)-zetas[96 + i]);
            }

        }
        else if (n == 864)
        {
            // N=864: 6-coefficient blocks divided into two 3-coefficient parts
            // Zeta offset: 144
            for (int i = 0; i < n / 6; ++i)
            {
                // First half of block with positive zeta
                basemul(r.coeffs, 6 * i,
                    a.coeffs, 6 * i,
                    b.coeffs, 6 * i,
                    zetas[144 + i]);

                // Second half of block with negative zeta
                basemul(r.coeffs, 6 * i + 3,
                    a.coeffs, 6 * i + 3,
                    b.coeffs, 6 * i + 3,
                    (short)-zetas[144 + i]);
            }

        }
        else if (n == 1152)
        {
            // N=1152: 8-coefficient blocks divided into two 4-coefficient parts
            // Zeta offset: 144
            for (int i = 0; i < n / 8; ++i)
            {
                // First half of block with positive zeta
                basemul(r.coeffs, 8 * i,
                    a.coeffs, 8 * i,
                    b.coeffs, 8 * i,
                    zetas[144 + i]);

                // Second half of block with negative zeta
                basemul(r.coeffs, 8 * i + 4,
                    a.coeffs, 8 * i + 4,
                    b.coeffs, 8 * i + 4,
                    (short)-zetas[144 + i]);
            }

        }
        else
        {
            throw new IllegalArgumentException("Unsupported N value: " + n);
        }
    }

    /**
     * Multiplication of polynomials in Zq[X]/(X^4 - zeta),
     * used for multiplication of elements in R_q in the NTT domain.
     * <p>
     * This function multiplies two 4-element polynomials modulo X^4 - zeta
     * using Montgomery arithmetic.
     *
     * @param r    Output polynomial array (4 elements)
     * @param a    First factor polynomial array (4 elements)
     * @param b    Second factor polynomial array (4 elements)
     * @param zeta Parameter defining X^4 - zeta
     */
    /**
     * Multiplication of polynomials in Zq[X]/(X^d - zeta)
     */
    private void basemul(short[] r, int rPos, short[] a, int aPos,
                         short[] b, int bPos, short zeta)
    {
        int n = params.getN();
        int blockSize = (n == 864) ? 3 : 4;

        if (blockSize == 4)
        {
            // 4-coefficient multiplication
            short a0 = a[aPos], a1 = a[aPos + 1], a2 = a[aPos + 2], a3 = a[aPos + 3];
            short b0 = b[bPos], b1 = b[bPos + 1], b2 = b[bPos + 2], b3 = b[bPos + 3];

            int temp = (int)a1 * b3 + (int)a2 * b2 + (int)a3 * b1;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)a2 * b3 + (int)a3 * b2;
            r[rPos + 1] = montgomery_reduce(temp);

            temp = (int)a3 * b3;
            r[rPos + 2] = montgomery_reduce(temp);

            temp = (int)r[rPos] * zeta + (int)a0 * b0;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)r[rPos + 1] * zeta + (int)a0 * b1 + (int)a1 * b0;
            r[rPos + 1] = montgomery_reduce(temp);

            temp = (int)r[rPos + 2] * zeta + (int)a0 * b2 + (int)a1 * b1 + (int)a2 * b0;
            r[rPos + 2] = montgomery_reduce(temp);

            temp = (int)a0 * b3 + (int)a1 * b2 + (int)a2 * b1 + (int)a3 * b0;
            r[rPos + 3] = montgomery_reduce(temp);

            short rsq = (short)params.getRSquared();
            r[rPos] = montgomery_reduce((int)r[rPos] * rsq);
            r[rPos + 1] = montgomery_reduce((int)r[rPos + 1] * rsq);
            r[rPos + 2] = montgomery_reduce((int)r[rPos + 2] * rsq);
            r[rPos + 3] = montgomery_reduce((int)r[rPos + 3] * rsq);
        }
        else
        {
            // 3-coefficient multiplication for N=864
            short a0 = a[aPos], a1 = a[aPos + 1], a2 = a[aPos + 2];
            short b0 = b[bPos], b1 = b[bPos + 1], b2 = b[bPos + 2];

            int temp = (int)a2 * b1 + (int)a1 * b2;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)a2 * b2;
            r[rPos + 1] = montgomery_reduce(temp);

            temp = (int)r[rPos] * zeta + (int)a0 * b0;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)r[rPos + 1] * zeta + (int)a0 * b1 + (int)a1 * b0;
            r[rPos + 1] = montgomery_reduce(temp);

            temp = (int)a2 * b0 + (int)a1 * b1 + (int)a0 * b2;
            r[rPos + 2] = montgomery_reduce(temp);

            short rsq = (short)params.getRSquared();
            r[rPos] = montgomery_reduce((int)r[rPos] * rsq);
            r[rPos + 1] = montgomery_reduce((int)r[rPos + 1] * rsq);
            r[rPos + 2] = montgomery_reduce((int)r[rPos + 2] * rsq);
        }
    }

    /**
     * Serialization of a polynomial
     *
     * @param r Output byte array (must have space for NTRUPLUS_POLYBYTES bytes)
     * @param a Input polynomial
     */
    public void poly_tobytes(byte[] r, int rOff, Poly a)
    {
        int t0, t1;

        for (int i = 0; i < NTRUPLUS_N / 2; i++)
        {
            // Handle negative coefficients by adding q if coefficient is negative
            t0 = a.coeffs[2 * i];
            t0 += (t0 >> 15) & NTRUPLUS_Q;

            t1 = a.coeffs[2 * i + 1];
            t1 += (t1 >> 15) & NTRUPLUS_Q;

            // Pack two 13-bit coefficients into three bytes
            r[rOff + 3 * i] = (byte)(t0 >> 0);  // Lower 8 bits of first coefficient
            r[rOff + 3 * i + 1] = (byte)((t0 >> 8) | (t1 << 4));  // Upper 5 bits of t0, lower 4 bits of t1
            r[rOff + 3 * i + 2] = (byte)(t1 >> 4);  // Upper 8 bits of t1
        }
    }

    /**
     * Hash function for generating a deterministic buffer from a message
     *
     * @param buf Output buffer (32 bytes)
     * @param msg Input message (NTRUPLUS_POLYBYTES bytes)
     */
    public void hash_f(byte[] buf, int bufOff, byte[] msg)
    {
        byte[] data = new byte[1 + NTRUPLUS_POLYBYTES];

        data[0] = 0x00;
        System.arraycopy(msg, 0, data, 1, NTRUPLUS_POLYBYTES);

        // Use the shake256 implementation with Bouncy Castle
        shake256(buf, bufOff, 32, data, NTRUPLUS_POLYBYTES + 1);
    }

    /**
     * Deterministically generates a secret polynomial g and its
     * multiplicative inverse ginv in the NTT domain.
     *
     * @param g     Output polynomial g (in NTT domain)
     * @param ginv  Output multiplicative inverse of g in the NTT domain
     * @param coins 32-byte deterministic seed
     * @return 0 on success; non-zero if g is not invertible in the NTT domain
     */
    public int geng_derand(Poly g, Poly ginv, byte[] coins)
    {

        // Allocate buffer for SHAKE256 output
        byte[] buf = new byte[params.getN() / 4]; // NTRUPLUS_N / 4

        // Generate random bytes using SHAKE256
        shake256(buf, 0, buf.length, coins, 32);

        // Generate polynomial g from the random bytes using centered binomial distribution
        poly_cbd1(g, buf);

        // Multiply polynomial g by 3 (no modular reduction)
        poly_triple(g, g);

        // Convert g to NTT domain
        poly_ntt(g, g);

        // Compute the inverse of g in NTT domain
        return poly_baseinv(ginv, g);
    }

    /**
     * Computes the deterministic public and secret key pair from
     * the secret polynomials f and g and their multiplicative
     * inverses finv and ginv in the NTT domain.
     *
     * @param pk   Output public key (must have length params.getPublicKeyBytes())
     * @param sk   Output secret key (must have length params.getSecretKeyBytes())
     * @param f    Secret polynomial f (in NTT domain)
     * @param finv Multiplicative inverse of f (in NTT domain)
     * @param g    Secret polynomial g (in NTT domain)
     * @param ginv Multiplicative inverse of g (in NTT domain)
     */
    public void crypto_kem_keypair_derand(byte[] pk, byte[] sk,
                                          Poly f, Poly finv,
                                          Poly g, Poly ginv)
    {

        // Create temporary polynomials for computation
        Poly h = new Poly(NTRUPLUS_N);
        Poly hinv = new Poly(NTRUPLUS_N);

        // Compute h = g * finv (in NTT domain)
        poly_basemul(h, g, finv);

        // Compute hinv = f * ginv (in NTT domain)
        poly_basemul(hinv, f, ginv);

        // Serialize h to get the public key
        poly_tobytes(pk, 0, h);

        // Serialize f to the first part of the secret key
        poly_tobytes(sk, 0, f);

        // Serialize hinv to the second part of the secret key (offset by NTRUPLUS_POLYBYTES)
        poly_tobytes(sk, NTRUPLUS_POLYBYTES, hinv);

        // Compute hash of public key and store in the third part of secret key
        // Offset: 2 * NTRUPLUS_POLYBYTES
        hash_f(sk, 2 * NTRUPLUS_POLYBYTES, pk);
    }

    /**
     * Hash function H
     */
    private void hash_h(byte[] buf, int bufPos, byte[] msg, int msgPos)
    {
        int dataLen = 1 + params.getN() / 8 + params.getSymBytes();
        byte[] data = new byte[dataLen];
        data[0] = 0x02;

        for (int i = 0; i < params.getN() / 8 + params.getSymBytes(); i++)
        {
            data[i + 1] = msg[msgPos + i];
        }

        int outLen = params.getSsBytes() + params.getN() / 4;
        shake256(buf, bufPos, outLen, data, 0, dataLen);
    }

    /**
     * Centered Binomial Distribution sampling
     */
    private void poly_cbd1(Poly r, byte[] buf, int bufPos)
    {
        int n = params.getN();
        int quarterN = n / 8;

        for (int i = 0; i < quarterN; i++)
        {
            int t1 = buf[bufPos + i] & 0xFF; // Convert to unsigned
            int t2 = buf[bufPos + i + quarterN] & 0xFF;

            for (int j = 0; j < 8; j++)
            {
                r.coeffs[8 * i + j] = (short)((t1 & 0x1) - (t2 & 0x1));
                t1 >>= 1;
                t2 >>= 1;
            }
        }
    }

    /**
     * Hash function G
     */
    private void hash_g(byte[] buf, int bufPos, byte[] msg, int msgPos)
    {
        byte[] data = new byte[1 + params.getPolyBytes()];
        data[0] = 0x01;
        System.arraycopy(msg, msgPos, data, 1, params.getPolyBytes());

        int outLen = params.getN() / 4;
        shake256(buf, bufPos, outLen, data, 0, params.getPolyBytes() + 1);
    }

    /**
     * SOTP encoding
     */
    private void poly_sotp_encode(Poly r, byte[] msg, int msgPos, byte[] buf, int bufPos)
    {
        int n = params.getN();
        int eighthN = n / 8;
        int quarterN = n / 4;

        byte[] tmp = new byte[quarterN];

        for (int i = 0; i < eighthN; i++)
        {
            tmp[i] = (byte)(buf[bufPos + i] ^ msg[msgPos + i]);
        }

        for (int i = eighthN; i < quarterN; i++)
        {
            tmp[i] = buf[bufPos + i];
        }

        poly_cbd1(r, tmp, 0);
    }

    /**
     * Deserialization of a polynomial from bytes
     */
    private void poly_frombytes(Poly r, byte[] a, int aPos)
    {
        int n = params.getN();
        for (int i = 0; i < n / 2; i++)
        {
            r.coeffs[2 * i] = (short)(((a[aPos + 3 * i] & 0xFF) | ((a[aPos + 3 * i + 1] & 0xFF) << 8)) & 0xFFF);
            r.coeffs[2 * i + 1] = (short)(((a[aPos + 3 * i + 1] & 0xFF) >> 4 | ((a[aPos + 3 * i + 2] & 0xFF) << 4)) & 0xFFF);
        }
    }

    /**
     * Multiplication then addition of three polynomials in NTT domain.
     * This merged function supports all three parameter sets:
     * - N=768: 8-coefficient blocks, zeta offset 96
     * - N=864: 6-coefficient blocks, zeta offset 144
     * - N=1152: 8-coefficient blocks, zeta offset 144
     * <p>
     * All cases perform: r = a * b + c (in NTT domain)
     *
     * @param r Output polynomial
     * @param a First input polynomial
     * @param b Second input polynomial
     * @param c Third input polynomial to add
     */
    private void poly_basemul_add(Poly r, Poly a, Poly b, Poly c)
    {
        int n = params.getN();

        if (n == 768)
        {
            // N=768: 8-coefficient blocks divided into two 4-coefficient parts
            // Zeta offset: 96
            for (int i = 0; i < n / 8; ++i)
            {
                // First half of block with positive zeta
                basemul_add(r.coeffs, 8 * i,
                    a.coeffs, 8 * i,
                    b.coeffs, 8 * i,
                    c.coeffs, 8 * i,
                    zetas[96 + i], 4);

                // Second half of block with negative zeta
                basemul_add(r.coeffs, 8 * i + 4,
                    a.coeffs, 8 * i + 4,
                    b.coeffs, 8 * i + 4,
                    c.coeffs, 8 * i + 4,
                    (short)-zetas[96 + i], 4);
            }

        }
        else if (n == 864)
        {
            // N=864: 6-coefficient blocks divided into two 3-coefficient parts
            // Zeta offset: 144
            for (int i = 0; i < n / 6; ++i)
            {
                // First half of block with positive zeta
                basemul_add(r.coeffs, 6 * i,
                    a.coeffs, 6 * i,
                    b.coeffs, 6 * i,
                    c.coeffs, 6 * i,
                    zetas[144 + i], 3);

                // Second half of block with negative zeta
                basemul_add(r.coeffs, 6 * i + 3,
                    a.coeffs, 6 * i + 3,
                    b.coeffs, 6 * i + 3,
                    c.coeffs, 6 * i + 3,
                    (short)-zetas[144 + i], 3);
            }

        }
        else if (n == 1152)
        {
            // N=1152: 8-coefficient blocks divided into two 4-coefficient parts
            // Zeta offset: 144
            for (int i = 0; i < n / 8; ++i)
            {
                // First half of block with positive zeta
                basemul_add(r.coeffs, 8 * i,
                    a.coeffs, 8 * i,
                    b.coeffs, 8 * i,
                    c.coeffs, 8 * i,
                    zetas[144 + i], 4);

                // Second half of block with negative zeta
                basemul_add(r.coeffs, 8 * i + 4,
                    a.coeffs, 8 * i + 4,
                    b.coeffs, 8 * i + 4,
                    c.coeffs, 8 * i + 4,
                    (short)-zetas[144 + i], 4);
            }

        }
        else
        {
            throw new IllegalArgumentException("Unsupported N value: " + n);
        }
    }

    /**
     * Multiplication then addition in Zq[X]/(X^4 - zeta)
     */
    /**
     * Multiplication then addition of polynomials in Zq[X]/(X^d - zeta),
     * used for multiplication of elements in R_q in the NTT domain.
     * <p>
     * Supports:
     * - 4-coefficient blocks (d=4) for N=768, 1152
     * - 3-coefficient blocks (d=3) for N=864
     */
    private void basemul_add(short[] r, int rPos, short[] a, int aPos,
                             short[] b, int bPos, short[] c, int cPos,
                             short zeta, int blockSize)
    {
        int n = params.getN();
        int rValue = 1 << 16; // NTRUPLUS_R = 2^16 = 65536

        if (blockSize == 4)
        {
            // 4-coefficient version for N=768 and N=1152

            // Extract coefficients
            short a0 = a[aPos], a1 = a[aPos + 1], a2 = a[aPos + 2], a3 = a[aPos + 3];
            short b0 = b[bPos], b1 = b[bPos + 1], b2 = b[bPos + 2], b3 = b[bPos + 3];
            short c0 = c[cPos], c1 = c[cPos + 1], c2 = c[cPos + 2], c3 = c[cPos + 3];

            // Step 1: Compute initial multiplication terms
            int temp = (int)a1 * b3 + (int)a2 * b2 + (int)a3 * b1;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)a2 * b3 + (int)a3 * b2;
            r[rPos + 1] = montgomery_reduce(temp);

            temp = (int)a3 * b3;
            r[rPos + 2] = montgomery_reduce(temp);

            // Step 2: Apply zeta and add lower-degree terms
            temp = (int)r[rPos] * zeta + (int)a0 * b0;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)r[rPos + 1] * zeta + (int)a0 * b1 + (int)a1 * b0;
            r[rPos + 1] = montgomery_reduce(temp);

            temp = (int)r[rPos + 2] * zeta + (int)a0 * b2 + (int)a1 * b1 + (int)a2 * b0;
            r[rPos + 2] = montgomery_reduce(temp);

            temp = (int)a0 * b3 + (int)a1 * b2 + (int)a2 * b1 + (int)a3 * b0;
            r[rPos + 3] = montgomery_reduce(temp);

            // Step 3: Add c and apply scaling
            short rsq = (short)params.getRSquared();

            // r[0] = montgomery_reduce(c[0]*R + r[0]*R^2)
            temp = c0 * rValue + (int)r[rPos] * rsq;
            r[rPos] = montgomery_reduce(temp);

            // r[1] = montgomery_reduce(c[1]*R + r[1]*R^2)
            temp = c1 * rValue + (int)r[rPos + 1] * rsq;
            r[rPos + 1] = montgomery_reduce(temp);

            // r[2] = montgomery_reduce(c[2]*R + r[2]*R^2)
            temp = c2 * rValue + (int)r[rPos + 2] * rsq;
            r[rPos + 2] = montgomery_reduce(temp);

            // r[3] = montgomery_reduce(c[3]*R + r[3]*R^2)
            temp = c3 * rValue + (int)r[rPos + 3] * rsq;
            r[rPos + 3] = montgomery_reduce(temp);

        }
        else if (blockSize == 3)
        {
            // 3-coefficient version for N=864

            // Extract coefficients
            short a0 = a[aPos], a1 = a[aPos + 1], a2 = a[aPos + 2];
            short b0 = b[bPos], b1 = b[bPos + 1], b2 = b[bPos + 2];
            short c0 = c[cPos], c1 = c[cPos + 1], c2 = c[cPos + 2];

            // Step 1: Compute initial multiplication terms
            int temp = (int)a2 * b1 + (int)a1 * b2;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)a2 * b2;
            r[rPos + 1] = montgomery_reduce(temp);

            // Step 2: Apply zeta and add lower-degree terms
            temp = (int)r[rPos] * zeta + (int)a0 * b0;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)r[rPos + 1] * zeta + (int)a0 * b1 + (int)a1 * b0;
            r[rPos + 1] = montgomery_reduce(temp);

            temp = (int)a2 * b0 + (int)a1 * b1 + (int)a0 * b2;
            r[rPos + 2] = montgomery_reduce(temp);

            // Step 3: Add c and apply scaling
            short rsq = (short)params.getRSquared();

            // r[0] = montgomery_reduce(c[0]*R + r[0]*R^2)
            temp = c0 * rValue + (int)r[rPos] * rsq;
            r[rPos] = montgomery_reduce(temp);

            // r[1] = montgomery_reduce(c[1]*R + r[1]*R^2)
            temp = c1 * rValue + (int)r[rPos + 1] * rsq;
            r[rPos + 1] = montgomery_reduce(temp);

            // r[2] = montgomery_reduce(c[2]*R + r[2]*R^2)
            temp = c2 * rValue + (int)r[rPos + 2] * rsq;
            r[rPos + 2] = montgomery_reduce(temp);

        }
        else
        {
            throw new IllegalArgumentException("Unsupported block size: " + blockSize);
        }
    }

    /**
     * Deterministic KEM encapsulation
     */
    public void crypto_kem_enc_derand(byte[] ct, int ctPos, byte[] ss, int ssPos,
                                      byte[] pk, int pkPos, byte[] coins, int coinsPos)
    {
        int n = params.getN();
        int symBytes = params.getSymBytes();
        int ssBytes = params.getSsBytes();
        int polyBytes = params.getPolyBytes();

        byte[] msg = new byte[n / 8 + symBytes];
        byte[] buf1 = new byte[symBytes + n / 4];
        byte[] buf2 = new byte[polyBytes];

        Poly c = new Poly(NTRUPLUS_N);
        Poly h = new Poly(NTRUPLUS_N);
        Poly r = new Poly(NTRUPLUS_N);
        Poly m = new Poly(NTRUPLUS_N);

        // Copy first n/8 bytes of coins to msg
        for (int i = 0; i < n / 8; i++)
        {
            msg[i] = coins[coinsPos + i];
        }

        // Compute hash_f of pk and store in remaining part of msg
        hash_f(msg, n / 8, pk, pkPos);

        // Compute hash_h of msg, result in buf1
        hash_h(buf1, 0, msg, 0);

        // Generate r from second part of buf1
        poly_cbd1(r, buf1, symBytes);
        poly_ntt(r, r);

        // Convert r to bytes and then hash_g
        poly_tobytes(buf2, 0, r);
        hash_g(buf2, 0, buf2, 0);

        // Generate m by encoding msg and buf2
        poly_sotp_encode(m, msg, 0, buf2, 0);
        poly_ntt(m, m);

        // Convert pk to polynomial h
        poly_frombytes(h, pk, pkPos);

        // Compute c = h*r + m in NTT domain
        poly_basemul_add(c, h, r, m);

        // Convert c to ciphertext
        poly_tobytes(ct, ctPos, c);

        // Copy first ssBytes of buf1 to ss
        for (int i = 0; i < ssBytes; i++)
        {
            ss[ssPos + i] = buf1[i];
        }

    }

// Helper methods that need to be added/updated:

    /**
     * Updated SHAKE256 with offsets
     */
    private void shake256(byte[] output, int outOffset, int outLen, byte[] input, int inOffset, int inLen)
    {
        org.bouncycastle.crypto.digests.SHAKEDigest shakeDigest = new org.bouncycastle.crypto.digests.SHAKEDigest(256);
        shakeDigest.update(input, inOffset, inLen);
        shakeDigest.doFinal(output, outOffset, outLen);
    }

    /**
     * Updated hash_f with offsets
     */
    private void hash_f(byte[] buf, int bufPos, byte[] msg, int msgPos)
    {
        byte[] data = new byte[1 + params.getPolyBytes()];
        data[0] = 0x00;
        System.arraycopy(msg, msgPos, data, 1, params.getPolyBytes());

        byte[] hashOutput = new byte[32];
        shake256(hashOutput, 0, 32, data, 0, params.getPolyBytes() + 1);
        System.arraycopy(hashOutput, 0, buf, bufPos, 32);
    }

    /**
     * Computes inverse of number-theoretic transform (NTT)
     */
    private void poly_invntt(Poly r, Poly a)
    {
        invntt(r.coeffs, a.coeffs);
    }

    /**
     * Inverse number-theoretic transform (NTT) in R_q.
     * Transforms the NTT representation back to the coefficient representation in R_q.
     * <p>
     * Supports:
     * - N=768: 4-coefficient blocks, step 4-64, 384-block processing
     * - N=864: 3-coefficient blocks, step 3-24, multiplication by 3 in second loop
     * - N=1152: 4-coefficient blocks, step 4-32, multiplication by 3 in second loop
     *
     * @param r Output vector (coefficient representation)
     * @param a Input vector (NTT representation)
     */
    private void invntt(short[] r, short[] a)
    {
        int n = params.getN();
        short omega = (short)params.getOmega();

        short t1, t2, t3;
        short zeta1, zeta2;
        int k;

        // Initialize based on N value
        if (n == 768)
        {
            k = 191;
        }
        else if (n == 864 || n == 1152)
        {
            k = 287;
        }
        else
        {
            throw new IllegalArgumentException("Unsupported N value: " + n);
        }

        // Copy input to output
        for (int i = 0; i < n; i++)
        {
            r[i] = a[i];
        }

        // First loop: butterfly operations with decreasing step sizes
        if (n == 768)
        {
            // N=768: step = 4, 8, 16, 32, 64
            for (int step = 4; step <= 64; step <<= 1)
            {
                for (int start = 0; start < n; start += (step << 1))
                {
                    zeta1 = zetas[k--];

                    for (int i = start; i < start + step; i++)
                    {
                        t1 = r[i + step];
                        r[i + step] = fqmul(zeta1, (short)(t1 - r[i]));
                        r[i] = barrett_reduce((short)(r[i] + t1));
                    }
                }
            }
        }
        else if (n == 864)
        {
            // N=864: step = 3, 6, 12, 24
            for (int step = 3; step <= 24; step <<= 1)
            {
                for (int start = 0; start < n; start += (step << 1))
                {
                    zeta1 = zetas[k--];

                    for (int i = start; i < start + step; i++)
                    {
                        t1 = r[i + step];
                        r[i + step] = barrett_reduce(fqmul(zeta1, (short)(t1 - r[i])));
                        r[i] = barrett_reduce((short)(r[i] + t1));
                    }
                }
            }
        }
        else
        { // n == 1152
            // N=1152: step = 4, 8, 16, 32
            for (int step = 4; step <= 32; step <<= 1)
            {
                for (int start = 0; start < n; start += (step << 1))
                {
                    zeta1 = zetas[k--];

                    for (int i = start; i < start + step; i++)
                    {
                        t1 = r[i + step];
                        r[i + step] = fqmul(zeta1, (short)(t1 - r[i]));
                        r[i] = barrett_reduce((short)(r[i] + t1));
                    }
                }
            }
        }

        // Second loop: larger block processing
        if (n == 768)
        {
            // N=768: process 384-coefficient blocks
            for (int start = 0; start < n; start += 384)
            {
                zeta2 = zetas[k--];
                zeta1 = zetas[k--];

                for (int i = start; i < start + 128; i++)
                {
                    t1 = fqmul(omega, (short)(r[i + 128] - r[i]));
                    t2 = fqmul(zeta1, (short)(r[i + 256] - r[i] + t1));
                    t3 = fqmul(zeta2, (short)(r[i + 256] - r[i + 128] - t1));

                    r[i] = (short)(r[i] + r[i + 128] + r[i + 256]);
                    r[i + 128] = t2;
                    r[i + 256] = t3;
                }
            }
        }
        else if (n == 864)
        {
            // N=864: step = 48, 144, 432 (multiply by 3)
            for (int step = 48; step <= n / 6; step *= 3)
            {
                for (int start = 0; start < n; start += 3 * step)
                {
                    zeta2 = zetas[k--];
                    zeta1 = zetas[k--];

                    for (int i = start; i < start + step; i++)
                    {
                        t1 = fqmul(omega, (short)(r[i + step] - r[i]));
                        t2 = fqmul(zeta1, (short)(r[i + 2 * step] - r[i] + t1));
                        t3 = fqmul(zeta2, (short)(r[i + 2 * step] - r[i + step] - t1));

                        r[i] = barrett_reduce((short)(r[i] + r[i + step] + r[i + 2 * step]));
                        r[i + step] = t2;
                        r[i + 2 * step] = t3;
                    }
                }
            }
        }
        else
        { // n == 1152
            // N=1152: step = 64, 192, 576 (multiply by 3)
            for (int step = 64; step <= n / 6; step *= 3)
            {
                for (int start = 0; start < n; start += 3 * step)
                {
                    zeta2 = zetas[k--];
                    zeta1 = zetas[k--];

                    for (int i = start; i < start + step; i++)
                    {
                        t1 = fqmul(omega, (short)(r[i + step] - r[i]));
                        t2 = fqmul(zeta1, (short)(r[i + 2 * step] - r[i] + t1));
                        t3 = fqmul(zeta2, (short)(r[i + 2 * step] - r[i + step] - t1));

                        r[i] = barrett_reduce((short)(r[i] + r[i + step] + r[i + 2 * step]));
                        r[i + step] = t2;
                        r[i + 2 * step] = t3;
                    }
                }
            }
        }

        // Final step: combine halves with specific constants
        for (int i = 0; i < n / 2; i++)
        {
            t1 = (short)(r[i] + r[i + n / 2]);
            t2 = fqmul((short)-1665, (short)(r[i] - r[i + n / 2]));

            if (n == 768)
            {
                r[i] = fqmul((short)-811, (short)(t1 - t2));
                r[i + n / 2] = fqmul((short)-1622, t2);
            }
            else
            { // n == 864 or n == 1152
                r[i] = fqmul((short)-1693, (short)(t1 - t2));
                r[i + n / 2] = fqmul((short)71, t2);
            }
        }
    }

    /**
     * Compute modulus 3 operation to polynomial
     */
    private void poly_crepmod3(Poly r, Poly a)
    {
        int n = params.getN();
        for (int i = 0; i < n; i++)
        {
            r.coeffs[i] = crepmod3(a.coeffs[i]);
        }
    }

    /**
     * Compute modulus 3 operation
     */
    private short crepmod3(short a)
    {
        int q = params.getQ();
        short t;
        final short v = (short)(((1 << 15) + 3 / 2) / 3);

        // Reduce a to range [0, q-1]
        a += (a >> 15) & q;
        // Center around 0: subtract (q+1)/2
        a -= (q + 1) / 2;
        // If negative, add q back
        a += (a >> 15) & q;
        // Subtract (q-1)/2 to get centered around 0
        a -= (q - 1) / 2;

        // Barrett reduction for mod 3
        t = (short)((v * a + (1 << 14)) >> 15);
        t *= 3;
        return (short)(a - t);
    }

    /**
     * Subtract two polynomials; no modular reduction is performed
     */
    private void poly_sub(Poly r, Poly a, Poly b)
    {
        int n = params.getN();
        for (int i = 0; i < n; ++i)
        {
            r.coeffs[i] = (short)(a.coeffs[i] - b.coeffs[i]);
        }
    }

    /**
     * Decode a message using SOTP_INV and a random
     */
    private int poly_sotp_decode(byte[] msg, int msgPos, Poly a, byte[] buf, int bufPos)
    {
        int n = params.getN();
        int eighthN = n / 8;
        int quarterN = n / 4;

        int r = 0;
        byte mask;

        for (int i = 0; i < eighthN; i++)
        {
            int t1 = buf[bufPos + i] & 0xFF; // Convert to unsigned
            int t2 = buf[bufPos + i + eighthN] & 0xFF;
            byte t3 = 0;

            for (int j = 0; j < 8; j++)
            {
                int t4 = t2 & 0x1;
                t4 += a.coeffs[8 * i + j];
                r |= t4;
                t4 = (t4 ^ t1) & 0x1;
                t3 ^= (byte)(t4 << j);

                t1 >>= 1;
                t2 >>= 1;
            }

            msg[msgPos + i] = t3;
        }

        r = r >> 1;
        r = (-r) >> 31; // This is the C trick: -(uint32_t)r) >> 31

        mask = (byte)(r - 1);

        for (int i = 0; i < eighthN; i++)
        {
            msg[msgPos + i] &= mask;
        }

        return r;
    }

    /**
     * Compares two byte arrays for equality in constant time
     */
    private int verify(byte[] a, int aPos, byte[] b, int bPos, int len)
    {
        int acc = 0;

        for (int i = 0; i < len; i++)
        {
            acc |= (a[aPos + i] ^ b[bPos + i]) & 0xFF;
        }

        // Return 0 if equal, 1 otherwise
        // Equivalent to: (-(uint64_t)acc) >> 63
        return (acc != 0) ? 1 : 0;
    }

    /**
     * Performs NTRU+ KEM decapsulation
     */
    public int crypto_kem_dec(byte[] ss, int ssPos, byte[] ct, int ctPos, byte[] sk, int skPos)
    {
        int n = params.getN();
        int symBytes = params.getSymBytes();
        int ssBytes = params.getSsBytes();
        int polyBytes = params.getPolyBytes();

        byte[] msg = new byte[n / 8 + symBytes];
        byte[] buf1 = new byte[polyBytes];
        byte[] buf2 = new byte[polyBytes];
        byte[] buf3 = new byte[polyBytes + symBytes];

        int fail;

        Poly c = new Poly(NTRUPLUS_N);
        Poly f = new Poly(NTRUPLUS_N);
        Poly hinv = new Poly(NTRUPLUS_N);
        Poly r1 = new Poly(NTRUPLUS_N);
        Poly r2 = new Poly(NTRUPLUS_N);
        Poly m1 = new Poly(NTRUPLUS_N);
        Poly m2 = new Poly(NTRUPLUS_N);

        // Load ciphertext and secret key components
        poly_frombytes(c, ct, ctPos);
        poly_frombytes(f, sk, skPos);
        poly_frombytes(hinv, sk, skPos + polyBytes);

        // m1 = c * f
        poly_basemul(m1, c, f);
        poly_invntt(m1, m1); // Convert from NTT domain
        poly_crepmod3(m1, m1); // Reduce mod 3

        // m2 = NTT(m1)
        poly_ntt(m2, m1);

        // c = c - m2
        poly_sub(c, c, m2);

        // r2 = c * hinv
        poly_basemul(r2, c, hinv);

        // Convert r2 to bytes and hash
        poly_tobytes(buf1, 0, r2);
        hash_g(buf2, 0, buf1, 0);

        // Decode message
        fail = poly_sotp_decode(msg, 0, m1, buf2, 0);

        // Append hash of pk from secret key
        for (int i = 0; i < symBytes; i++)
        {
            msg[n / 8 + i] = sk[skPos + 2 * polyBytes + i];
        }

        // Hash H
        hash_h(buf3, 0, msg, 0);

        // Generate r1 from second part of buf3
        poly_cbd1(r1, buf3, ssBytes);
        poly_ntt(r1, r1);
        poly_tobytes(buf2, 0, r1);

        // Verify that buf1 (from r2) equals buf2 (from r1)
        fail |= verify(buf1, 0, buf2, 0, polyBytes);

        // Copy shared secret, zeroing on failure
        if (fail != 0)
        {
            for (int i = 0; i < ssBytes; i++)
            {
                ss[ssPos + i] = 0;
            }
        }
        else
        {
            for (int i = 0; i < ssBytes; i++)
            {
                ss[ssPos + i] = buf3[i];
            }
        }

        return fail;
    }
}
