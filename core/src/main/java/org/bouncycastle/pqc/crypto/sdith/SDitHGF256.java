package org.bouncycastle.pqc.crypto.sdith;

import org.bouncycastle.math.raw.GF256AES;
import org.bouncycastle.util.Pack;

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
            acc = GF256AES.mul(acc, GEN);
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
     * Performs vz[16] += vx[m] * my[m][16] over GF(256); byte-identical to the
     * naive per-element form (gf256_vec_mat16cols_muladd_ref_ct) but accumulates
     * the two 8-byte halves in registers and multiplies via the word-parallel
     * {@link GF256AES#mulFx8(int, long)} rather than per-element {@link GF256AES#mul(int, int)}. The
     * matrix is a flat byte array laid out row-major.
     */
    static void vecMat16ColsMulAdd(byte[] vz, int vzOff, byte[] vx, int vxOff, byte[] my, int myOff, int m)
    {
        long z0 = Pack.littleEndianToLong(vz, vzOff);
        long z1 = Pack.littleEndianToLong(vz, vzOff + 8);
        for (int i = 0; i < m; ++i)
        {
            int xi = vx[vxOff + i] & 0xff;
            int rowOff = myOff + i * 16;
            z0 ^= GF256AES.mulFx8(xi, Pack.littleEndianToLong(my, rowOff));
            z1 ^= GF256AES.mulFx8(xi, Pack.littleEndianToLong(my, rowOff + 8));
        }
        Pack.longToLittleEndian(z0, vz, vzOff);
        Pack.longToLittleEndian(z1, vz, vzOff + 8);
    }

    /**
     * Performs vz[N] += vx[m] * my[m][N] over GF(256); byte-identical to the
     * naive per-element form (gf256_vec_mat128cols_muladd_ref_ct, which
     * hard-codes N = 128) but processes each 8-column block in a register via
     * the word-parallel {@link GF256AES#mulFx8(int, long)}, with a scalar tail for any
     * columns past the last full block. For SDitH-cat1 the syndrome length 116
     * is &lt; 128 and only one slice of width N is used; for higher categories
     * the matrix is sliced 128 columns at a time and this helper is invoked per
     * slice. The C reference always zero-pads the slice to 128 columns
     * regardless of how many y bytes are live.
     */
    static void vecMatNColsMulAdd(byte[] vz, int vzOff, byte[] vx, int vxOff, byte[] my, int myOff, int m, int n)
    {
        // Word-parallel over each 8-column block: hold the block accumulator in
        // a register across all m rows (no per-call scratch allocation), then a
        // scalar tail for any columns past the last full block.
        int b = 0;
        for (; b + 8 <= n; b += 8)
        {
            long z = Pack.littleEndianToLong(vz, vzOff + b);
            for (int i = 0; i < m; ++i)
            {
                z ^= GF256AES.mulFx8(vx[vxOff + i] & 0xff, Pack.littleEndianToLong(my, myOff + i * n + b));
            }
            Pack.longToLittleEndian(z, vz, vzOff + b);
        }
        for (; b < n; ++b)
        {
            int acc = vz[vzOff + b] & 0xff;
            for (int i = 0; i < m; ++i)
            {
                acc ^= GF256AES.mul(vx[vxOff + i] & 0xff, my[myOff + i * n + b] & 0xff);
            }
            vz[vzOff + b] = (byte)acc;
        }
    }
}
