package org.bouncycastle.pqc.crypto.sdith;

/**
 * GF(256) arithmetic helpers for SDitH, port of the reference gf256.c.
 * <p>
 * The generator polynomial is 0x11b = x^8 + x^4 + x^3 + x + 1 (AES polynomial),
 * the multiplicative generator is 0x41 — matching the reference and the f_poly
 * / Lagrangian-coefficient precomputed tables in the submission package.
 */
final class SDitHGF256
{
    static final int GEN = 0x41;

    private static final byte[] DEXP = new byte[256];
    private static final byte[] DLOG = new byte[256];

    static
    {
        // dexp[0] = 1, dexp[i] = gen * dexp[i-1] for i in [1, 254], dexp[255] = 0.
        int acc = 1;
        DEXP[0] = (byte)1;
        for (int i = 1; i < 255; ++i)
        {
            acc = mulNaive(acc, GEN);
            DEXP[i] = (byte)acc;
        }
        DEXP[255] = 0;
        for (int i = 0; i < 256; ++i)
        {
            DLOG[DEXP[i] & 0xff] = (byte)i;
        }
    }

    private SDitHGF256()
    {
    }

    /**
     * Naive constant-time GF(256) multiplication, matching mul_gf256_naive.
     */
    static int mulNaive(int x, int y)
    {
        x &= 0xff;
        y &= 0xff;
        int r = 0;
        for (int i = 0; i < 8; ++i)
        {
            r ^= ((-((y >>> i) & 1)) & (x << i));
        }
        for (int i = 15; i >= 8; --i)
        {
            r ^= ((-((r >>> i) & 1)) & (0x11b << (i - 8)));
        }
        return r & 0xff;
    }

    /**
     * Discrete log in GF(256). log(0) = 0xff by convention.
     */
    static int dlog(int x)
    {
        return DLOG[x & 0xff] & 0xff;
    }

    /**
     * Discrete exp in GF(256).
     */
    static int dexp(int x)
    {
        return DEXP[x & 0xff] & 0xff;
    }

    /**
     * Performs vz[16] += vx[m] * my[m][16] using naive constant-time GF(256)
     * multiplication; matches gf256_vec_mat16cols_muladd_ref_ct. The matrix is
     * a flat byte array laid out row-major.
     */
    static void vecMat16ColsMulAdd(byte[] vz, int vzOff, byte[] vx, int vxOff, byte[] my, int myOff, int m)
    {
        for (int i = 0; i < m; ++i)
        {
            int xi = vx[vxOff + i] & 0xff;
            int rowOff = myOff + i * 16;
            for (int j = 0; j < 16; ++j)
            {
                vz[vzOff + j] ^= (byte)mulNaive(xi, my[rowOff + j] & 0xff);
            }
        }
    }

    /**
     * Performs vz[N] += vx[m] * my[m][N] using naive constant-time GF(256)
     * multiplication; matches gf256_vec_mat128cols_muladd_ref_ct in the
     * reference (which hard-codes N = 128). For SDitH-cat1 the syndrome
     * length 116 is &lt; 128 and only one slice of width N is used; for
     * higher categories the matrix is sliced 128 columns at a time and this
     * helper is invoked per slice. The C reference always zero-pads the
     * slice to 128 columns regardless of how many y bytes are live.
     */
    static void vecMatNColsMulAdd(byte[] vz, int vzOff, byte[] vx, int vxOff, byte[] my, int myOff, int m, int n)
    {
        for (int i = 0; i < m; ++i)
        {
            int xi = vx[vxOff + i] & 0xff;
            int rowOff = myOff + i * n;
            for (int j = 0; j < n; ++j)
            {
                vz[vzOff + j] ^= (byte)mulNaive(xi, my[rowOff + j] & 0xff);
            }
        }
    }
}
