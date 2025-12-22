package org.bouncycastle.pqc.crypto.ntruplus;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

class NTRUPlusEngine
{
    private static final short QINV = 12929;
    private static final short OMEGA = -886;
    private static final short RINV = -682;
    private static final short RSQ = 867;
    private static final short Q = 3457;
    private static final short Q_HALF = Q >> 1;
    private static final short QPlus1_Half = (Q + 1) >> 1;
    private static final short QMinus1_Half = (Q - 1) >> 1;
    private static final short V = ((1 << 26) + Q_HALF) / Q;
    private static final byte hash_f_domain = (byte) 0x00;
    private static final byte hash_g_domain = (byte) 0x01;
    private static final byte hash_h_domain = (byte) 0x02;
    static final int SSBytes = 32;

    private final int n;
    private final int halfN;
    private final int quarterN;
    private final int eighthN;
    private final int blockSize;
    private final int doubleBlockSize;
    private final int zetaOffset;
    public short polyBytes;
    public short[] zetas;
    private final NTRUPlusParameters params;
    private final SHAKEDigest shakeDigest = new SHAKEDigest(256);

    public NTRUPlusEngine(NTRUPlusParameters params)
    {
        this.params = params;
        this.n = params.getN();
        this.halfN = this.n >> 1;
        this.quarterN = this.n >> 2;
        this.eighthN = this.n >> 3;
        this.blockSize = n == 864 ? 3 : 4;
        this.doubleBlockSize = blockSize << 1;
        this.zetaOffset = params.getZetasOffset();
        this.polyBytes = (short)params.getPublicKeyBytes();
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
        byte[] buf = new byte[quarterN];

        shake256(buf, 0, buf.length, coins, 32);

        poly_cbd1(f, buf, 0);
        poly_triple(f, f);
        f[0] += 1;

        poly_ntt(f);

        return poly_baseinv(finv, f);
    }

    /*************************************************
     * Name:        poly_cbd1
     * Description: Sample a polynomial deterministically from a random,
     *              with output polynomial close to centered binomial distribution
     **************************************************/
    private void poly_cbd1(short[] r, byte[] buf, int bufPos)
    {
        for (int i = 0, pos = 0; i < eighthN; i++, pos += 8)
        {
            int t1 = buf[bufPos + i] & 0xFF; // Convert to unsigned
            int t2 = buf[bufPos + i + eighthN] & 0xFF;

            for (int j = 0; j < 8; j++)
            {
                r[pos + j] = (short)((t1 & 0x1) - (t2 & 0x1));
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
     */
    private void poly_ntt(short[] r)
    {
        short t1, t2, t3;
        short zeta1, zeta2;
        int k = 1;

        zeta1 = zetas[k++];

        for (int i = 0, pos = halfN; i < halfN; i++, pos++)
        {
            t1 = fqmul(zeta1, r[pos]);
            r[pos] = (short)(r[i] + r[pos] - t1);
            r[i] = (short)(r[i] + t1);
        }
        int baseStep = params.getBaseStep();
        int minStep = params.getMinStep();
        for (int step = n / 6; step >= (baseStep << 1); step /= 3)
        {
            int twoSteps = step << 1;
            int threeSteps = twoSteps + step;
            for (int start = 0; start < n; start += threeSteps)
            {
                zeta1 = zetas[k++];
                zeta2 = zetas[k++];

                for (int i = start, pos1 = start + step, pos2 = start + twoSteps; i < start + step; i++, pos1++, pos2++)
                {
                    t1 = fqmul(zeta1, r[pos1]);
                    t2 = fqmul(zeta2, r[pos2]);
                    t3 = fqmul(OMEGA, (short)(t1 - t2));

                    r[pos2] = (short)(r[i] - t1 - t3);
                    r[pos1] = (short)(r[i] - t2 + t3);
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

                for (int i = start, pos = start + step; i < start + step; i++, pos++)
                {
                    t1 = fqmul(zeta1, r[pos]);
                    r[pos] = barrett_reduce((short)(r[i] - t1));
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
        return (short)((a - (short)(a * QINV) * Q) >> 16);
    }

    /*************************************************
     * Name:        barrett_reduce
     * Description: Barrett reduction; given a 16-bit integer a, computes a
     *              centered representative congruent to a mod q.
     **************************************************/
    public short barrett_reduce(short a)
    {
        return (short)(a - ((V * a + (1 << 25)) >> 26) * Q);
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
            for (int i = 0, pos = 0, zetaOff = zetaOffset; i < n / 6; ++i, pos += 6, zetaOff++)
            {
                // Use baseinv3 for 3-coefficient blocks
                if (baseinv3(r, pos, a, pos, zetas[zetaOff]) == 1)
                {
                    Arrays.fill(r, (short)0);
                    return 1;
                }

                if (baseinv3(r, pos + 3, a, pos + 3, (short)-zetas[zetaOff]) == 1)
                {
                    Arrays.fill(r, (short)0);
                    return 1;
                }
            }
        }
        else
        {
            // Use existing logic for N=768 and N=1152
            for (int i = 0, pos = 0, zetaOff = zetaOffset; i < eighthN; ++i, pos += 8, zetaOff++)
            {
                if (baseinv(r, pos, a, pos, zetas[zetaOff]) == 1)
                {
                    Arrays.fill(r, (short)0);
                    return 1;
                }

                if (baseinv(r, pos + 4, a, pos + 4, (short)-zetas[zetaOff]) == 1)
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
        short a0 = a[aPos], a1 = a[aPos + 1], a2 = a[aPos + 2];

        short r0 = montgomery_reduce(a1 * a2);
        short r1 = montgomery_reduce(a2 * a2);
        short r2 = montgomery_reduce(a1 * a1 - a0 * a2);

        r0 = montgomery_reduce(a0 * a0 - r0 * zeta);
        r1 = montgomery_reduce(r1 * zeta - a0 * a1);

        short t = montgomery_reduce(r2 * a1 + r1 * a2);
        t = montgomery_reduce(t * zeta + r0 * a0);

        if (t == 0)
        {
            return 1; // Not invertible
        }

        t = fqinv(t);
        t = montgomery_reduce(t * RINV);

        r[rPos] = montgomery_reduce(r0 * t);
        r[rPos + 1] = montgomery_reduce(r1 * t);
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
        short a0 = a[aOff], a1 = a[aOff + 1], a2 = a[aOff + 2], a3 = a[aOff + 3];
        short t0, t1, t2, t3;

        t0 = montgomery_reduce(a2 * a2 - 2 * a1 * a3);
        t1 = montgomery_reduce(a3 * a3);
        t0 = montgomery_reduce(a0 * a0 + t0 * zeta);
        t1 = montgomery_reduce(a1 * a1 + t1 * zeta - 2 * a0 * a2);
        t2 = montgomery_reduce(t1 * zeta);

        t3 = montgomery_reduce(t0 * t0 - t1 * t2);

        if (t3 == 0)
        {
            return 1;
        }

        short r0 = montgomery_reduce(a0 * t0 + a2 * t2);
        short r1 = montgomery_reduce(a3 * t2 + a1 * t0);
        short r2 = montgomery_reduce(a2 * t0 + a0 * t1);
        short r3 = montgomery_reduce(a1 * t1 + a3 * t0);

        t3 = fqinv(t3);
        t3 = montgomery_reduce(t3 * RINV);

        r[rOff] = montgomery_reduce(r0 * t3);
        r[rOff + 1] = (short)-montgomery_reduce(r1 * t3);
        r[rOff + 2] = montgomery_reduce(r2 * t3);
        r[rOff + 3] = (short)-montgomery_reduce(r3 * t3);

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
        for (int i = 0; i < n / doubleBlockSize; ++i)
        {
            basemul(r, doubleBlockSize * i, a, doubleBlockSize * i, b, doubleBlockSize * i, zetas[zetaOffset + i]);
            basemul(r, doubleBlockSize * i + blockSize, a, doubleBlockSize * i + blockSize, b, doubleBlockSize * i + blockSize, (short)-zetas[zetaOffset + i]);
        }
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

        for (int i = 0, inOff = 0, outOff = rOff; i < halfN; i++)
        {
            t0 = a[inOff++];
            t0 += (t0 >> 15) & Q;

            t1 = a[inOff++];
            t1 += (t1 >> 15) & Q;

            // Pack two 13-bit coefficients into three bytes
            r[outOff++] = (byte)(t0);  // Lower 8 bits of first coefficient
            r[outOff++] = (byte)((t0 >> 8) | (t1 << 4));  // Upper 5 bits of t0, lower 4 bits of t1
            r[outOff++] = (byte)(t1 >> 4);  // Upper 8 bits of t1
        }
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
        byte[] buf = new byte[quarterN];
        shake256(buf, 0, buf.length, coins, 32);
        poly_cbd1(g, buf, 0);
        poly_triple(g, g);
        poly_ntt(g);
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
        poly_tobytes(sk, polyBytes, hinv);

        // Compute hash of public key and store in the third part of secret key
        shake256(sk, polyBytes << 1, 32, hash_f_domain, pk, 0, polyBytes);
    }

    /**
     * SOTP encoding
     */
    private void poly_sotp_encode(short[] r, byte[] msg, byte[] buf)
    {
        Bytes.xorTo(eighthN, msg, buf);
        poly_cbd1(r, buf, 0);
    }

    /**
     * Deserialization of a polynomial from bytes
     */
    private void poly_frombytes(short[] r, byte[] a, int aPos)
    {
        for (int i = 0, inOff = aPos, outOff = 0; i < halfN; i++, inOff += 3)
        {
            r[outOff++] = (short)(((a[inOff] & 0xFF) | ((a[inOff + 1] & 0xFF) << 8)) & 0xFFF);
            r[outOff++] = (short)(((a[inOff + 1] & 0xFF) >> 4 | ((a[inOff + 2] & 0xFF) << 4)) & 0xFFF);
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
        for (int i = 0, pos = 0, zetaOff = zetaOffset; i < n / doubleBlockSize; ++i, zetaOff++)
        {
            basemul_add(r, pos, a, pos, b, pos, c, pos, zetas[zetaOff], blockSize);
            pos += blockSize;
            basemul_add(r, pos, a, pos, b, pos, c, pos, (short)-zetas[zetaOff], blockSize);
            pos += blockSize;
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
        // Common multiplication core
        multiplyCore(r, rPos, a, aPos, b, bPos, zeta, blockSize);

        // Addition and final scaling
        finalizeWithAddition(r, rPos, c, cPos, blockSize);
    }

    /**
     * Multiplication of polynomials in Zq[X]/(X^d - zeta)
     */
    private void basemul(short[] r, int rPos, short[] a, int aPos,
                         short[] b, int bPos, short zeta)
    {
        // Common multiplication core
        multiplyCore(r, rPos, a, aPos, b, bPos, zeta, blockSize);

        // Final scaling (multiplication only)
        finalizeMultiplication(r, rPos, blockSize);
    }

    /**
     * Core multiplication logic shared by both basemul and basemul_add
     */
    private void multiplyCore(short[] r, int rPos, short[] a, int aPos,
                              short[] b, int bPos, short zeta, int blockSize)
    {
        // Extract common coefficients (a0, a1, a2, b0, b1, b2)
        short a0 = a[aPos], a1 = a[aPos + 1], a2 = a[aPos + 2];
        short b0 = b[bPos], b1 = b[bPos + 1], b2 = b[bPos + 2];
        int temp;

        if (blockSize == 4)
        {
            // 4-coefficient specific logic
            short a3 = a[aPos + 3];
            short b3 = b[bPos + 3];

            // High-degree terms
            temp = (int)a1 * b3 + (int)a2 * b2 + (int)a3 * b1;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)a2 * b3 + (int)a3 * b2;
            r[rPos + 1] = montgomery_reduce(temp);

            temp = (int)a3 * b3;
            temp = montgomery_reduce(temp);

            // Apply zeta to middle terms
            temp = temp * zeta + (int)a0 * b2 + (int)a1 * b1 + (int)a2 * b0;
            r[rPos + 2] = montgomery_reduce(temp);

            // Compute r3 term
            temp = (int)a0 * b3 + (int)a1 * b2 + (int)a2 * b1 + (int)a3 * b0;
            r[rPos + 3] = montgomery_reduce(temp);
        }
        else
        {
            // 3-coefficient specific logic
            // High-degree terms
            temp = (int)a2 * b1 + (int)a1 * b2;
            r[rPos] = montgomery_reduce(temp);

            temp = (int)a2 * b2;
            r[rPos + 1] = montgomery_reduce(temp);

            // Compute r2 term
            temp = (int)a2 * b0 + (int)a1 * b1 + (int)a0 * b2;
            r[rPos + 2] = montgomery_reduce(temp);
        }

        // Common low-degree terms (apply zeta to r0 and r1)
        temp = (int)r[rPos] * zeta + (int)a0 * b0;
        r[rPos] = montgomery_reduce(temp);

        temp = (int)r[rPos + 1] * zeta + (int)a0 * b1 + (int)a1 * b0;
        r[rPos + 1] = montgomery_reduce(temp);
    }

    /**
     * Final scaling for multiplication with addition (basemul_add)
     */
    private void finalizeWithAddition(short[] r, int rPos, short[] c, int cPos, int blockSize)
    {
        int rValue = 1 << 16; // NTRUPLUS_R = 2^16 = 65536

        // Handle all coefficients
        for (int i = 0; i < blockSize; i++)
        {
            int temp = c[cPos++] * rValue + (int)r[rPos] * RSQ;
            r[rPos++] = montgomery_reduce(temp);
        }
    }

    /**
     * Final scaling for multiplication only (basemul)
     */
    private void finalizeMultiplication(short[] r, int rPos, int blockSize)
    {
        for (int i = 0; i < blockSize; i++)
        {
            r[rPos] = montgomery_reduce((int)r[rPos++] * RSQ);
        }
    }

    /**
     * Deterministic KEM encapsulation
     */
    public void crypto_kem_enc_derand(byte[] ct, int ctPos, byte[] ss, int ssPos,
                                      byte[] pk, int pkPos, byte[] coins, int coinsPos)
    {
        byte[] msg = new byte[eighthN + SSBytes];
        byte[] buf1 = new byte[SSBytes + quarterN];
        byte[] buf2 = new byte[polyBytes];

        short[] c = new short[n];
        short[] h = new short[n];
        short[] r = new short[n];
        short[] m = new short[n];

        // Copy first n/8 bytes of coins to msg
        System.arraycopy(coins, coinsPos, msg, 0, eighthN);

        // Compute hash_f of pk and store in remaining part of msg
        shake256(msg, eighthN, 32, hash_f_domain, pk, pkPos, polyBytes);

        // Compute hash_h of msg, result in buf1
        shake256(buf1, 0, buf1.length, hash_h_domain, msg, 0, msg.length);
        // Generate r from second part of buf1
        poly_cbd1(r, buf1, SSBytes);
        poly_ntt(r);

        // Convert r to bytes and then hash_g
        poly_tobytes(buf2, 0, r);
        shake256(buf2, 0, quarterN, hash_g_domain, buf2, 0, polyBytes);

        // Generate m by encoding msg and buf2
        poly_sotp_encode(m, msg, buf2);
        poly_ntt(m);

        // Convert pk to polynomial h
        poly_frombytes(h, pk, pkPos);

        // Compute c = h*r + m in NTT domain
        poly_basemul_add(c, h, r, m);

        // Convert c to ciphertext
        poly_tobytes(ct, ctPos, c);

        // Copy first ssBytes of buf1 to ss
        System.arraycopy(buf1, 0, ss, ssPos, SSBytes);
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
        for (; minStep <= baseStep; minStep <<= 1)
        {
            for (int start = 0; start < n; start += (minStep << 1))
            {
                zeta1 = zetas[k--];
                for (int i = start, pos = start + minStep; i < start + minStep; i++, pos++)
                {
                    t1 = r[pos];
                    r[pos] = fqmul(zeta1, (short)(t1 - r[i]));
                    r[i] = barrett_reduce((short)(r[i] + t1));
                }
            }
        }
        for (int step = baseStep << 1; step <= n / 6; step *= 3)
        {
            int twoStep = step << 1;
            for (int start = 0; start < n; start += 3 * step)
            {
                zeta2 = zetas[k--];
                zeta1 = zetas[k--];

                for (int i = start, pos1 = start + step, pos2 = start + twoStep; i < start + step; i++, pos1++, pos2++)
                {
                    t1 = fqmul(OMEGA, (short)(r[pos1] - r[i]));
                    t2 = fqmul(zeta1, (short)(r[pos2] - r[i] + t1));
                    t3 = fqmul(zeta2, (short)(r[pos2] - r[pos1] - t1));

                    r[i] = barrett_reduce((short)(r[i] + r[pos1] + r[pos2]));
                    r[pos1] = t2;
                    r[pos2] = t3;
                }
            }
        }

        for (int i = 0; i < halfN; i++)
        {
            t1 = (short)(r[i] + r[i + halfN]);
            t2 = fqmul((short)-1665, (short)(r[i] - r[i + halfN]));
            r[i] = fqmul(a1, (short)(t1 - t2));
            r[i + halfN] = fqmul(a2, t2);
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
        short t;
        final short v = (short)(((1 << 15) + 1) / 3);

        // Reduce a to range [0, q-1]
        // Center around 0: subtract (q+1)/2
        a += (short)(((a >> 15) & Q) - QPlus1_Half);
        // If negative, add q back
        // Subtract (q-1)/2 to get centered around 0
        a += (short)(((a >> 15) & Q) - QMinus1_Half);

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
        byte[] msg = new byte[eighthN + SSBytes];
        byte[] buf1 = new byte[polyBytes];
        byte[] buf2 = new byte[polyBytes];
        byte[] buf3 = new byte[polyBytes + SSBytes];

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
        System.arraycopy(m1, 0, m2, 0, n);
        poly_ntt(m2);

        // c = c - m2
        poly_sub(c, c, m2);

        // r2 = c * hinv
        poly_basemul(r2, c, hinv);

        // Convert r2 to bytes and hash
        poly_tobytes(buf1, 0, r2);
        shake256(buf2, 0, quarterN, hash_g_domain, buf1, 0, polyBytes);

        // Decode message
        fail = poly_sotp_decode(msg, m1, buf2);

        // Append hash of pk from secret key
        System.arraycopy(sk, skPos + 2 * polyBytes, msg, eighthN, SSBytes);

        // Hash H
        shake256(buf3, 0, buf3.length, hash_h_domain, msg, 0, msg.length);

        // Generate r1 from second part of buf3
        poly_cbd1(r1, buf3, SSBytes);
        poly_ntt(r1);
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
            System.arraycopy(buf3, 0, ss, ssPos, SSBytes);
        }
    }
}
