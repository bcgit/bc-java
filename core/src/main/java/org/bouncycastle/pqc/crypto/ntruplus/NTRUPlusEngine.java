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
    public short[] zetas = new short[]{
        -147, -1033, -682, -248, -708, 682, 1, -722,
        -723, -257, -1124, -867, -256, 1484, 1262, -1590,
        1611, 222, 1164, -1346, 1716, -1521, -357, 395,
        -455, 639, 502, 655, -699, 541, 95, -1577,
        -1241, 550, -44, 39, -820, -216, -121, -757,
        -348, 937, 893, 387, -603, 1713, -1105, 1058,
        1449, 837, 901, 1637, -569, -1617, -1530, 1199,
        50, -830, -625, 4, 176, -156, 1257, -1507,
        -380, -606, 1293, 661, 1428, -1580, -565, -992,
        548, -800, 64, -371, 961, 641, 87, 630,
        675, -834, 205, 54, -1081, 1351, 1413, -1331,
        -1673, -1267, -1558, 281, -1464, -588, 1015, 436,
        223, 1138, -1059, -397, -183, 1655, 559, -1674,
        277, 933, 1723, 437, -1514, 242, 1640, 432,
        -1583, 696, 774, 1671, 927, 514, 512, 489,
        297, 601, 1473, 1130, 1322, 871, 760, 1212,
        -312, -352, 443, 943, 8, 1250, -100, 1660,
        -31, 1206, -1341, -1247, 444, 235, 1364, -1209,
        361, 230, 673, 582, 1409, 1501, 1401, 251,
        1022, -1063, 1053, 1188, 417, -1391, -27, -1626,
        1685, -315, 1408, -1248, 400, 274, -1543, 32,
        -1550, 1531, -1367, -124, 1458, 1379, -940, -1681,
        22, 1709, -275, 1108, 354, -1728, -968, 858,
        1221, -218, 294, -732, -1095, 892, 1588, -779
    };
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
    }

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

    /*************************************************
     * Name:        ntt
     *
     * Description: Number-theoretic transform (NTT) in R_q.
     **************************************************/
    public void ntt(short[] r, short[] a)
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
    public int poly_baseinv(Poly r, Poly a)
    {
        for (int i = 0; i < NTRUPLUS_N / 8; ++i)
        {

            if (baseinv(r.coeffs, 8 * i, a.coeffs, 8 * i, zetas[96 + i]) != 0)
            {
                Arrays.fill(r.coeffs, (short)0);
                return 1;
            }

            if (baseinv(r.coeffs, 8 * i + 4, a.coeffs, 8 * i + 4, (short)-zetas[96 + i]) != 0)
            {
                Arrays.fill(r.coeffs, (short)0);
                return 1;
            }
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
    public void poly_basemul(Poly r, Poly a, Poly b)
    {
        for (int i = 0; i < NTRUPLUS_N / 8; ++i)
        {
            // Process first block of 4 coefficients
            short[] rBlock1 = new short[4];
            short[] aBlock1 = Arrays.copyOfRange(a.coeffs, 8 * i, 8 * i + 4);
            short[] bBlock1 = Arrays.copyOfRange(b.coeffs, 8 * i, 8 * i + 4);
            basemul(rBlock1, aBlock1, bBlock1, zetas[96 + i]);
            System.arraycopy(rBlock1, 0, r.coeffs, 8 * i, 4);

            // Process second block of 4 coefficients with negative zeta
            short[] rBlock2 = new short[4];
            short[] aBlock2 = Arrays.copyOfRange(a.coeffs, 8 * i + 4, 8 * i + 8);
            short[] bBlock2 = Arrays.copyOfRange(b.coeffs, 8 * i + 4, 8 * i + 8);
            basemul(rBlock2, aBlock2, bBlock2, (short)-zetas[96 + i]);
            System.arraycopy(rBlock2, 0, r.coeffs, 8 * i + 4, 4);
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
    public void basemul(short[] r, short[] a, short[] b, short zeta)
    {
        // First compute initial terms with Montgomery reduction
        // r[0] = montgomery_reduce(a[1]*b[3] + a[2]*b[2] + a[3]*b[1])
        int temp = (int)a[1] * b[3] + (int)a[2] * b[2] + (int)a[3] * b[1];
        r[0] = montgomery_reduce(temp);

        // r[1] = montgomery_reduce(a[2]*b[3] + a[3]*b[2])
        temp = (int)a[2] * b[3] + (int)a[3] * b[2];
        r[1] = montgomery_reduce(temp);

        // r[2] = montgomery_reduce(a[3]*b[3])
        temp = (int)a[3] * b[3];
        r[2] = montgomery_reduce(temp);

        // Adjust with zeta and add lower-degree terms
        // r[0] = montgomery_reduce(r[0]*zeta + a[0]*b[0])
        temp = (int)r[0] * zeta + (int)a[0] * b[0];
        r[0] = montgomery_reduce(temp);

        // r[1] = montgomery_reduce(r[1]*zeta + a[0]*b[1] + a[1]*b[0])
        temp = (int)r[1] * zeta + (int)a[0] * b[1] + (int)a[1] * b[0];
        r[1] = montgomery_reduce(temp);

        // r[2] = montgomery_reduce(r[2]*zeta + a[0]*b[2] + a[1]*b[1] + a[2]*b[0])
        temp = (int)r[2] * zeta + (int)a[0] * b[2] + (int)a[1] * b[1] + (int)a[2] * b[0];
        r[2] = montgomery_reduce(temp);

        // r[3] = montgomery_reduce(a[0]*b[3] + a[1]*b[2] + a[2]*b[1] + a[3]*b[0])
        temp = (int)a[0] * b[3] + (int)a[1] * b[2] + (int)a[2] * b[1] + (int)a[3] * b[0];
        r[3] = montgomery_reduce(temp);

        // Adjust scaling by multiplying by NTRUPLUS_Rsq (R^2 mod q)
        r[0] = montgomery_reduce((int)r[0] * NTRUPLUS_Rsq);
        r[1] = montgomery_reduce((int)r[1] * NTRUPLUS_Rsq);
        r[2] = montgomery_reduce((int)r[2] * NTRUPLUS_Rsq);
        r[3] = montgomery_reduce((int)r[3] * NTRUPLUS_Rsq);
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
        Poly h = new Poly();
        Poly hinv = new Poly();

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
}
