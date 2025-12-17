package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

public class NTRUPlusEngine
{
    private final int n;
    private final short Q;
    private final int blockSize;
    private static final short QINV = 12929;
    private static final short omega = -886;
    private static final short Rinv = -682;
    public short POLYBYTES;
    private static final short Rsq = 867;
    public short[] zetas;
    private final NTRUPlusParameters params;
    private final SHAKEDigest shakeDigest = new SHAKEDigest(256);

    public NTRUPlusEngine(NTRUPlusParameters params)
    {
        this.params = params;
        this.n = params.getN();
        this.Q = (short)params.getQ();
        this.blockSize = n == 864 ? 3 : 4;
        this.POLYBYTES = (short)params.getPolyBytes();
        this.zetas = params.getZetas();
    }

    /*************************************************
     * Name:        genf_derand
     * Description: Deterministically generates a secret polynomial f and its
     *              multiplicative inverse finv in the NTT domain.
     * Returns 0 on success; non-zero if f is not invertible in the NTT domain.
     **************************************************/
    public int genf_derand(short[] f, short[] finv, byte[] coins)
    {
        // coins should be 32 bytes
        byte[] buf = new byte[n / 4];

        shake256(buf, 0, buf.length, coins, 32);

        poly_cbd1(f, buf);
        poly_triple(f, f);
        f[0] += 1;

        poly_ntt(f, f);

        return poly_baseinv(finv, f);
    }

    /*************************************************
     * Name:        poly_cbd1
     * Description: Sample a polynomial deterministically from a random,
     *              with output polynomial close to centered binomial distribution
     **************************************************/
    public void poly_cbd1(short[] r, byte[] buf)
    {
        // buf should be of length NTRUPLUS_N/4 bytes
        int t1, t2;

        for (int i = 0; i < n / 8; i++)
        {
            t1 = buf[i] & 0xFF;  // Convert to unsigned
            t2 = buf[i + n / 8] & 0xFF;

            for (int j = 0; j < 8; j++)
            {
                r[8 * i + j] = (short)((t1 & 0x1) - (t2 & 0x1));
                t1 >>= 1;
                t2 >>= 1;
            }
        }
    }

    /*************************************************
     * Name:        poly_triple
     * Description: Multiply polynomial by 3; no modular reduction is performed
     **************************************************/
    public void poly_triple(short[] r, short[] a)
    {
        for (int i = 0; i < n; ++i)
        {
            r[i] = (short)(3 * a[i]);
        }
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
    private void poly_ntt(short[] r, short[] a)
    {
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
        int baseStep = params.getBaseStep();
        int minStep = params.getMinStep();
        for (int step = n / 6; step >= baseStep * 2; step /= 3)
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
        for (int step = baseStep; step >= minStep; step >>= 1)
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

    /*************************************************
     * Name:        fqmul
     * Description: Multiplication followed by Montgomery reduction.
     * Returns:     16-bit integer congruent to a*b*R^-1 mod q.
     **************************************************/
    public short fqmul(short a, short b)
    {
        return montgomery_reduce((int)a * b);
    }

    /*************************************************
     * Name:        montgomery_reduce
     * Description: Montgomery reduction; given a 32-bit integer a, computes
     *              a 16-bit integer congruent to a * R^-1 mod q,
     *              where R = 2^16.
     **************************************************/
    public short montgomery_reduce(int a)
    {
        short t = (short)(a * QINV);
        t = (short)((a - (int)t * Q) >> 16);
        return t;
    }

    /*************************************************
     * Name:        barrett_reduce
     * Description: Barrett reduction; given a 16-bit integer a, computes a
     *              centered representative congruent to a mod q.
     **************************************************/
    public short barrett_reduce(short a)
    {
        return (short)(a - (((((1 << 26) + Q / 2) / Q) * a + (1 << 25)) >> 26) * Q);
    }

    /*************************************************
     * Name:        poly_baseinv
     * Description: Inversion of polynomial in NTT domain
     **************************************************/
    private int poly_baseinv(short[] r, short[] a)
    {
        if (n == 864)
        {
            // Special handling for N=864 with 3-coefficient blocks
            for (int i = 0; i < n / 6; ++i)
            {
                // Use baseinv3 for 3-coefficient blocks
                if (baseinv3(r, 6 * i, a, 6 * i, zetas[144 + i]) == 1)
                {
                    Arrays.fill(r, (short)0);
                    return 1;
                }

                if (baseinv3(r, 6 * i + 3, a, 6 * i + 3,
                    (short)-zetas[144 + i]) == 1)
                {
                    Arrays.fill(r, (short)0);
                    return 1;
                }
            }
        }
        else
        {
            // Use existing logic for N=768 and N=1152
            int numBlocks = n / 8;
            int zetaOffset = (n == 768) ? 96 : 144;

            for (int i = 0; i < numBlocks; ++i)
            {
                if (baseinv(r, 8 * i, a, 8 * i,
                    zetas[zetaOffset + i]) == 1)
                {
                    Arrays.fill(r, (short)0);
                    return 1;
                }

                if (baseinv(r, 8 * i + 4, a, 8 * i + 4,
                    (short)-zetas[zetaOffset + i]) == 1)
                {
                    Arrays.fill(r, (short)0);
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
        // Extract coefficients from input array
        short a0 = a[aPos];
        short a1 = a[aPos + 1];
        short a2 = a[aPos + 2];

        // Step 1: Compute initial values with Montgomery reduction
        // r[0] = montgomery_reduce(a[1]*a[2]);
        short r0 = montgomery_reduce(a1 * a2);

        // r[1] = montgomery_reduce(a[2]*a[2]);
        short r1 = montgomery_reduce(a2 * a2);

        // r[2] = montgomery_reduce(a[1]*a[1] - a[0]*a[2]);
        short r2 = montgomery_reduce(a1 * a1 - a0 * a2);

        // Step 2: Apply zeta transformations
        // r[0] = montgomery_reduce(a[0]*a[0] - r[0]*zeta);
        r0 = montgomery_reduce(a0 * a0 - r0 * zeta);

        // r[1] = montgomery_reduce(r[1]*zeta - a[0]*a[1]);
        r1 = montgomery_reduce(r1 * zeta - a0 * a1);

        // Step 3: Compute determinant (t)
        // t = montgomery_reduce(r[2]*a[1] + r[1]*a[2]);
        short t = montgomery_reduce(r2 * a1 + r1 * a2);

        // t = montgomery_reduce(t*zeta + r[0]*a[0]);
        t = montgomery_reduce(t * zeta + r0 * a0);

        // Step 4: Check if invertible
        if (t == 0)
        {
            return 1; // Not invertible
        }

        // Step 5: Compute inverse scaling
        // t = fqinv(t);
        t = fqinv(t);

        // t = montgomery_reduce(t * NTRUPLUS_Rinv);
        t = montgomery_reduce(t * Rinv);

        // Step 6: Apply final scaling
        // r[0] = montgomery_reduce(r[0] * t);
        r[rPos] = montgomery_reduce(r0 * t);

        // r[1] = montgomery_reduce(r[1] * t);
        r[rPos + 1] = montgomery_reduce(r1 * t);

        // r[2] = montgomery_reduce(r[2] * t);
        r[rPos + 2] = montgomery_reduce(r2 * t);

        return 0; // Success
    }

    /*************************************************
     * Name:        baseinv
     * Description: Inversion of a polynomial in Zq[X]/(X^4 - zeta)
     * Returns:     0 if a is invertible, 1 otherwise.
     **************************************************/
    public int baseinv(short[] r, int rOff, short[] a, int aOff, short zeta)
    {
        short t0, t1, t2, t3;

        t0 = montgomery_reduce(a[aOff + 2] * a[aOff + 2] - 2 * a[aOff + 1] * a[aOff + 3]);
        t1 = montgomery_reduce(a[aOff + 3] * a[aOff + 3]);
        t0 = montgomery_reduce(a[aOff] * a[aOff] + t0 * zeta);
        t1 = montgomery_reduce(a[aOff + 1] * a[aOff + 1] + t1 * zeta - 2 * a[aOff] * a[aOff + 2]);
        t2 = montgomery_reduce(t1 * zeta);

        t3 = montgomery_reduce(t0 * t0 - t1 * t2);

        if (t3 == 0)
        {
            return 1;
        }

        r[rOff] = montgomery_reduce(a[aOff] * t0 + a[aOff + 2] * t2);
        r[rOff + 1] = montgomery_reduce(a[aOff + 3] * t2 + a[aOff + 1] * t0);
        r[rOff + 2] = montgomery_reduce(a[aOff + 2] * t0 + a[aOff] * t1);
        r[rOff + 3] = montgomery_reduce(a[aOff + 1] * t1 + a[aOff + 3] * t0);

        t3 = fqinv(t3);
        t3 = montgomery_reduce(t3 * Rinv);

        r[rOff] = montgomery_reduce(r[rOff] * t3);
        r[rOff + 1] = (short)-montgomery_reduce(r[rOff + 1] * t3);
        r[rOff + 2] = montgomery_reduce(r[rOff + 2] * t3);
        r[rOff + 3] = (short)-montgomery_reduce(r[rOff + 3] * t3);

        return 0;
    }

    public void shake256(byte[] output, int outOff, int outLen, byte[] input, int inLen)
    {
        shakeDigest.update(input, 0, inLen);
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
    private void poly_basemul(short[] r, short[] a, short[] b)
    {
        int doubleBlockSize = blockSize << 1;
        int zetaOffset = params.getZetasOffset();
        for (int i = 0; i < n / doubleBlockSize; ++i)
        {
            // First half of block with positive zeta
            basemul(r, doubleBlockSize * i, a, doubleBlockSize * i, b, doubleBlockSize * i, zetas[zetaOffset + i]);

            // Second half of block with negative zeta
            basemul(r, doubleBlockSize * i + blockSize, a, doubleBlockSize * i + blockSize, b, doubleBlockSize * i + blockSize, (short)-zetas[zetaOffset + i]);
        }
    }

    /**
     * Multiplication of polynomials in Zq[X]/(X^d - zeta)
     */
    private void basemul(short[] r, int rPos, short[] a, int aPos,
                         short[] b, int bPos, short zeta)
    {
        int blockSize = (n == 864) ? 3 : 4;
        short a0 = a[aPos], a1 = a[aPos + 1], a2 = a[aPos + 2];
        short b0 = b[bPos], b1 = b[bPos + 1], b2 = b[bPos + 2];
        int temp;
        if (blockSize == 4)
        {
            // 4-coefficient multiplication
            short a3 = a[aPos + 3];
            short b3 = b[bPos + 3];

            temp = (int)a1 * b3 + (int)a2 * b2 + (int)a3 * b1;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)a2 * b3 + (int)a3 * b2;
            r[rPos + 1] = montgomery_reduce(temp);

            temp = (int)a3 * b3;
            r[rPos + 2] = montgomery_reduce(temp);

            temp = (int)r[rPos + 2] * zeta + (int)a0 * b2 + (int)a1 * b1 + (int)a2 * b0;
            r[rPos + 2] = montgomery_reduce(temp);

            temp = (int)a0 * b3 + (int)a1 * b2 + (int)a2 * b1 + (int)a3 * b0;
            r[rPos + 3] = montgomery_reduce(temp);

            r[rPos + 3] = montgomery_reduce((int)r[rPos + 3] * Rsq);
        }
        else
        {
            // 3-coefficient multiplication for N=864
            temp = (int)a2 * b1 + (int)a1 * b2;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)a2 * b2;
            r[rPos + 1] = montgomery_reduce(temp);

            temp = (int)a2 * b0 + (int)a1 * b1 + (int)a0 * b2;
            r[rPos + 2] = montgomery_reduce(temp);
        }

        temp = (int)r[rPos] * zeta + (int)a0 * b0;
        r[rPos] = montgomery_reduce(temp);

        temp = (int)r[rPos + 1] * zeta + (int)a0 * b1 + (int)a1 * b0;
        r[rPos + 1] = montgomery_reduce(temp);

        r[rPos] = montgomery_reduce((int)r[rPos] * Rsq);
        r[rPos + 1] = montgomery_reduce((int)r[rPos + 1] * Rsq);
        r[rPos + 2] = montgomery_reduce((int)r[rPos + 2] * Rsq);
    }

    /**
     * Serialization of a polynomial
     *
     * @param r Output byte array (must have space for NTRUPLUS_POLYBYTES bytes)
     * @param a Input polynomial
     */
    public void poly_tobytes(byte[] r, int rOff, short[] a)
    {
        int t0, t1;

        for (int i = 0; i < n / 2; i++)
        {
            // Handle negative coefficients by adding q if coefficient is negative
            t0 = a[2 * i];
            t0 += (t0 >> 15) & Q;

            t1 = a[2 * i + 1];
            t1 += (t1 >> 15) & Q;

            // Pack two 13-bit coefficients into three bytes
            r[rOff + 3 * i] = (byte)(t0);  // Lower 8 bits of first coefficient
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
        shake256(buf, bufOff, 32, (byte)0x00, msg, 0, POLYBYTES);
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
    public int geng_derand(short[] g, short[] ginv, byte[] coins)
    {
        // Allocate buffer for SHAKE256 output
        byte[] buf = new byte[n / 4]; // NTRUPLUS_N / 4

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
    public void crypto_kem_keypair_derand(byte[] pk, byte[] sk, short[] f, short[] finv, short[] g, short[] ginv)
    {
        // Create temporary polynomials for computation
        short[] h = new short[n];
        short[] hinv = new short[n];

        // Compute h = g * finv (in NTT domain)
        poly_basemul(h, g, finv);

        // Compute hinv = f * ginv (in NTT domain)
        poly_basemul(hinv, f, ginv);

        // Serialize h to get the public key
        poly_tobytes(pk, 0, h);

        // Serialize f to the first part of the secret key
        poly_tobytes(sk, 0, f);

        // Serialize hinv to the second part of the secret key (offset by NTRUPLUS_POLYBYTES)
        poly_tobytes(sk, POLYBYTES, hinv);

        // Compute hash of public key and store in the third part of secret key
        // Offset: 2 * NTRUPLUS_POLYBYTES
        hash_f(sk, 2 * POLYBYTES, pk);
    }

    /**
     * Hash function H
     */
    private void hash_h(byte[] buf, byte[] msg)
    {
        int dataLen = n / 8 + params.getSymBytes();
        int outLen = params.getSsBytes() + n / 4;
        shake256(buf, 0, outLen, (byte)0x02, msg, 0, dataLen);
    }

    /**
     * Centered Binomial Distribution sampling
     */
    private void poly_cbd1(short[] r, byte[] buf, int bufPos)
    {
        int quarterN = n / 8;

        for (int i = 0; i < quarterN; i++)
        {
            int t1 = buf[bufPos + i] & 0xFF; // Convert to unsigned
            int t2 = buf[bufPos + i + quarterN] & 0xFF;

            for (int j = 0; j < 8; j++)
            {
                r[8 * i + j] = (short)((t1 & 0x1) - (t2 & 0x1));
                t1 >>= 1;
                t2 >>= 1;
            }
        }
    }

    /**
     * Hash function G
     */
    private void hash_g(byte[] buf, byte[] msg)
    {
        shake256(buf, 0, n / 4, (byte)0x01, msg, 0, params.getPolyBytes());
    }

    /**
     * SOTP encoding
     */
    private void poly_sotp_encode(short[] r, byte[] msg, byte[] buf)
    {
        int eighthN = n / 8;
        Bytes.xorTo(eighthN, msg, buf);
        poly_cbd1(r, buf, 0);
    }

    /**
     * Deserialization of a polynomial from bytes
     */
    private void poly_frombytes(short[] r, byte[] a, int aPos)
    {
        for (int i = 0; i < n / 2; i++)
        {
            r[2 * i] = (short)(((a[aPos + 3 * i] & 0xFF) | ((a[aPos + 3 * i + 1] & 0xFF) << 8)) & 0xFFF);
            r[2 * i + 1] = (short)(((a[aPos + 3 * i + 1] & 0xFF) >> 4 | ((a[aPos + 3 * i + 2] & 0xFF) << 4)) & 0xFFF);
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
    private void poly_basemul_add(short[] r, short[] a, short[] b, short[] c)
    {
        int doubleBlockSize = blockSize << 1;
        int zetasOffset = params.getZetasOffset();
        for (int i = 0; i < n / doubleBlockSize; ++i)
        {
            // First half of block with positive zeta
            basemul_add(r, doubleBlockSize * i,
                a, doubleBlockSize * i,
                b, doubleBlockSize * i,
                c, doubleBlockSize * i,
                zetas[zetasOffset + i], blockSize);

            // Second half of block with negative zeta
            basemul_add(r, doubleBlockSize * i + blockSize,
                a, doubleBlockSize * i + blockSize,
                b, doubleBlockSize * i + blockSize,
                c, doubleBlockSize * i + blockSize,
                (short)-zetas[zetasOffset + i], blockSize);
        }
    }

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

            // r[0] = montgomery_reduce(c[0]*R + r[0]*R^2)
            temp = c0 * rValue + (int)r[rPos] * Rsq;
            r[rPos] = montgomery_reduce(temp);

            // r[1] = montgomery_reduce(c[1]*R + r[1]*R^2)
            temp = c1 * rValue + (int)r[rPos + 1] * Rsq;
            r[rPos + 1] = montgomery_reduce(temp);

            // r[2] = montgomery_reduce(c[2]*R + r[2]*R^2)
            temp = c2 * rValue + (int)r[rPos + 2] * Rsq;
            r[rPos + 2] = montgomery_reduce(temp);

            // r[3] = montgomery_reduce(c[3]*R + r[3]*R^2)
            temp = c3 * rValue + (int)r[rPos + 3] * Rsq;
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

            // r[0] = montgomery_reduce(c[0]*R + r[0]*R^2)
            temp = c0 * rValue + (int)r[rPos] * Rsq;
            r[rPos] = montgomery_reduce(temp);

            // r[1] = montgomery_reduce(c[1]*R + r[1]*R^2)
            temp = c1 * rValue + (int)r[rPos + 1] * Rsq;
            r[rPos + 1] = montgomery_reduce(temp);

            // r[2] = montgomery_reduce(c[2]*R + r[2]*R^2)
            temp = c2 * rValue + (int)r[rPos + 2] * Rsq;
            r[rPos + 2] = montgomery_reduce(temp);

        }
    }

    /**
     * Deterministic KEM encapsulation
     */
    public void crypto_kem_enc_derand(byte[] ct, int ctPos, byte[] ss, int ssPos,
                                      byte[] pk, int pkPos, byte[] coins, int coinsPos)
    {
        int symBytes = params.getSymBytes();
        int ssBytes = params.getSsBytes();
        int polyBytes = params.getPolyBytes();

        byte[] msg = new byte[n / 8 + symBytes];
        byte[] buf1 = new byte[symBytes + n / 4];
        byte[] buf2 = new byte[polyBytes];

        short[] c = new short[n];
        short[] h = new short[n];
        short[] r = new short[n];
        short[] m = new short[n];

        // Copy first n/8 bytes of coins to msg
        System.arraycopy(coins, coinsPos, msg, 0, n / 8);

        // Compute hash_f of pk and store in remaining part of msg
        hash_f(msg, n / 8, pk, pkPos);

        // Compute hash_h of msg, result in buf1
        hash_h(buf1, msg);
        // Generate r from second part of buf1
        poly_cbd1(r, buf1, symBytes);
        poly_ntt(r, r);

        // Convert r to bytes and then hash_g
        poly_tobytes(buf2, 0, r);
        hash_g(buf2, buf2);

        // Generate m by encoding msg and buf2
        poly_sotp_encode(m, msg, buf2);
        poly_ntt(m, m);

        // Convert pk to polynomial h
        poly_frombytes(h, pk, pkPos);

        // Compute c = h*r + m in NTT domain
        poly_basemul_add(c, h, r, m);

        // Convert c to ciphertext
        poly_tobytes(ct, ctPos, c);

        // Copy first ssBytes of buf1 to ss
        System.arraycopy(buf1, 0, ss, ssPos, ssBytes);
    }

    /**
     * Updated SHAKE256 with offsets
     */
    private void shake256(byte[] output, int outOff, int outLen, byte domainSeperation, byte[] input, int inOff, int inLen)
    {
        shakeDigest.update(domainSeperation);
        shakeDigest.update(input, inOff, inLen);
        shakeDigest.doFinal(output, outOff, outLen);
    }

    /**
     * Updated hash_f with offsets
     */
    private void hash_f(byte[] buf, int bufPos, byte[] msg, int msgPos)
    {
        shake256(buf, bufPos, 32, (byte)0x00, msg, msgPos, params.getPolyBytes());
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
     */
    private void poly_invntt(short[] r)
    {
        short t1, t2, t3;
        short zeta1, zeta2;
        short a1, a2;
        int k;
        if (n == 768)
        {
            a1 = (short)-811;
            a2 = (short)-1622;
            k = 191;
        }
        else
        {
            a1 = (short)-1693;
            a2 = (short)71;
            k = 287;
        }

        int minStep = params.getMinStep();
        int baseStep = params.getBaseStep();
        // N=768: step = 4, 8, 16, 32, 64
        for (; minStep <= baseStep; minStep <<= 1)
        {
            for (int start = 0; start < n; start += (minStep << 1))
            {
                zeta1 = zetas[k--];
                for (int i = start; i < start + minStep; i++)
                {
                    t1 = r[i + minStep];
                    r[i + minStep] = fqmul(zeta1, (short)(t1 - r[i]));
                    r[i] = barrett_reduce((short)(r[i] + t1));
                }
            }
        }
        for (int step = baseStep << 1; step <= n / 6; step *= 3)
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

        for (int i = 0; i < n / 2; i++)
        {
            t1 = (short)(r[i] + r[i + n / 2]);
            t2 = fqmul((short)-1665, (short)(r[i] - r[i + n / 2]));
            r[i] = fqmul(a1, (short)(t1 - t2));
            r[i + n / 2] = fqmul(a2, t2);
        }
    }

    /**
     * Compute modulus 3 operation to polynomial
     */
    private void poly_crepmod3(short[] r, short[] a)
    {
        for (int i = 0; i < n; i++)
        {
            r[i] = crepmod3(a[i]);
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
        // Center around 0: subtract (q+1)/2
        a += (short)(((a >> 15) & q) - ((q + 1) / 2));
        // If negative, add q back
        // Subtract (q-1)/2 to get centered around 0
        a += (short)(((a >> 15) & q) - ((q - 1) / 2));

        // Barrett reduction for mod 3
        t = (short)((v * a + (1 << 14)) >> 15);
        t *= 3;
        return (short)(a - t);
    }

    /**
     * Subtract two polynomials; no modular reduction is performed
     */
    private void poly_sub(short[] r, short[] a, short[] b)
    {
        for (int i = 0; i < n; ++i)
        {
            r[i] = (short)(a[i] - b[i]);
        }
    }

    /**
     * Decode a message using SOTP_INV and a random
     */
    private int poly_sotp_decode(byte[] msg, short[] a, byte[] buf)
    {
        int eighthN = n / 8;

        int r = 0;
        byte mask;

        for (int i = 0; i < eighthN; i++)
        {
            int t1 = buf[i] & 0xFF; // Convert to unsigned
            int t2 = buf[i + eighthN] & 0xFF;
            byte t3 = 0;

            for (int j = 0; j < 8; j++)
            {
                int t4 = t2 & 0x1;
                t4 += a[8 * i + j];
                r |= t4;
                t4 = (t4 ^ t1) & 0x1;
                t3 ^= (byte)(t4 << j);

                t1 >>= 1;
                t2 >>= 1;
            }

            msg[i] = t3;
        }

        r = r >> 1;
        r = (-r) >> 31; // This is the C trick: -(uint32_t)r) >> 31

        mask = (byte)(r - 1);

        for (int i = 0; i < eighthN; i++)
        {
            msg[i] &= mask;
        }

        return r;
    }

    /**
     * Compares two byte arrays for equality in constant time
     */
    private int verify(byte[] a, byte[] b, int len)
    {
        int acc = 0;

        for (int i = 0; i < len; i++)
        {
            acc |= (a[i] ^ b[i]) & 0xFF;
        }

        // Return 0 if equal, 1 otherwise
        // Equivalent to: (-(uint64_t)acc) >> 63
        return (acc != 0) ? 1 : 0;
    }

    /**
     * Performs NTRU+ KEM decapsulation
     */
    public void crypto_kem_dec(byte[] ss, int ssPos, byte[] ct, int ctPos, byte[] sk, int skPos)
    {
        int symBytes = params.getSymBytes();
        int ssBytes = params.getSsBytes();
        int polyBytes = params.getPolyBytes();

        byte[] msg = new byte[n / 8 + symBytes];
        byte[] buf1 = new byte[polyBytes];
        byte[] buf2 = new byte[polyBytes];
        byte[] buf3 = new byte[polyBytes + symBytes];

        int fail;

        short[] c = new short[n];
        short[] f = new short[n];
        short[] hinv = new short[n];
        short[] r1 = new short[n];
        short[] r2 = new short[n];
        short[] m1 = new short[n];
        short[] m2 = new short[n];

        // Load ciphertext and secret key components
        poly_frombytes(c, ct, ctPos);
        poly_frombytes(f, sk, skPos);
        poly_frombytes(hinv, sk, skPos + polyBytes);

        // m1 = c * f
        poly_basemul(m1, c, f);
        poly_invntt(m1); // Convert from NTT domain
        poly_crepmod3(m1, m1); // Reduce mod 3

        // m2 = NTT(m1)
        poly_ntt(m2, m1);

        // c = c - m2
        poly_sub(c, c, m2);

        // r2 = c * hinv
        poly_basemul(r2, c, hinv);

        // Convert r2 to bytes and hash
        poly_tobytes(buf1, 0, r2);
        hash_g(buf2, buf1);

        // Decode message
        fail = poly_sotp_decode(msg, m1, buf2);

        // Append hash of pk from secret key
        for (int i = 0; i < symBytes; i++)
        {
            msg[n / 8 + i] = sk[skPos + 2 * polyBytes + i];
        }

        // Hash H
        hash_h(buf3, msg);

        // Generate r1 from second part of buf3
        poly_cbd1(r1, buf3, ssBytes);
        poly_ntt(r1, r1);
        poly_tobytes(buf2, 0, r1);

        // Verify that buf1 (from r2) equals buf2 (from r1)
        fail |= verify(buf1, buf2, polyBytes);

        // Copy shared secret, zeroing on failure
        if (fail != 0)
        {
            Arrays.fill(ss, (byte)0);
        }
        else
        {
            System.arraycopy(buf3, 0, ss, ssPos, ssBytes);
        }
    }
}
