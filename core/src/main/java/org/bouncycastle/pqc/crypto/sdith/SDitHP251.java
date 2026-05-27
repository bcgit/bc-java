package org.bouncycastle.pqc.crypto.sdith;

/**
 * GF(p251) modular arithmetic helpers for SDitH p251 variants, port of the
 * reference p251.c.
 * <p>
 * Operates on bytes interpreted as integers mod 251. Multiplication is the
 * naive form {@code (x * y) mod 251}; addition / subtraction are likewise mod 251.
 * Log/exp tables are built around the multiplicative generator 0x06.
 */
final class SDitHP251
{
    static final int GEN = 0x06;
    static final int ORDER = 250; // generator's multiplicative order

    private static final byte[] DEXP = new byte[251];
    private static final byte[] DLOG = new byte[251];

    static
    {
        // dexp[0] = 1, dexp[i] = gen * dexp[i-1] for i in [1, 249], dexp[250] = 0
        // (convention from p251_create_log_tables).
        int acc = 1;
        DEXP[0] = 1;
        for (int i = 1; i < ORDER; ++i)
        {
            acc = mulNaive(acc, GEN);
            DEXP[i] = (byte)acc;
        }
        DEXP[ORDER] = 0;
        for (int i = 0; i <= ORDER; ++i)
        {
            DLOG[DEXP[i] & 0xff] = (byte)i;
        }
    }

    private SDitHP251()
    {
    }

    /** Package-private accessor for the dlog table (used by SDitHP251P4 initialisation). */
    static byte[] DLOG()
    {
        return DLOG;
    }

    /** Package-private accessor for the dexp table. */
    static byte[] DEXP()
    {
        return DEXP;
    }

    /** Reduce a 16-bit value mod 251 via the magic-number method from the reference. */
    static int reduce16(int x)
    {
        return (x & 0xffff) - 251 * ((((x & 0xffff) * 33421) >>> 23) & 0xffffffff);
    }

    /** Reduce a 32-bit value mod 251. */
    static int reduce32(int x)
    {
        long xx = x & 0xffffffffL;
        long q = (xx * 2190262207L) >>> 39;
        return (int)(xx - 251L * q);
    }

    /** Mod-251 multiplication. */
    static int mulNaive(int x, int y)
    {
        x &= 0xff;
        y &= 0xff;
        return reduce16(x * y);
    }

    /** Mod-251 add. */
    static int add(int x, int y)
    {
        return reduce16((x & 0xff) + (y & 0xff));
    }

    /** Mod-251 sub. */
    static int sub(int x, int y)
    {
        return reduce16((x & 0xff) + 251 - (y & 0xff));
    }

    /** Mod-251 negate. */
    static int neg(int x)
    {
        return reduce16(251 - (x & 0xff));
    }

    /**
     * Performs vz[16] += vx[m] * my[m][16] over GF(p251); matches
     * p251_vec_mat16cols_muladd_ref_ct.
     */
    static void vecMat16ColsMulAdd(byte[] vz, int vzOff, byte[] vx, int vxOff, byte[] my, int myOff, int m)
    {
        long[] scratch = new long[16];
        for (int j = 0; j < m; ++j)
        {
            int xj = vx[vxOff + j] & 0xff;
            int rowOff = myOff + 16 * j;
            for (int i = 0; i < 16; ++i)
            {
                scratch[i] += (long)xj * (long)(my[rowOff + i] & 0xff);
            }
        }
        for (int i = 0; i < 16; ++i)
        {
            int acc = (int)((scratch[i] + (vz[vzOff + i] & 0xff)) & 0xffffffffL);
            vz[vzOff + i] = (byte)reduce32(acc);
        }
    }

    /**
     * Performs vz[N] += vx[m] * my[m][N] over GF(p251); matches
     * p251_vec_mat128cols_muladd_ref_ct, which hard-codes N = 128. For the
     * Java port the reference's lazy accumulation is preserved.
     */
    static void vecMatNColsMulAdd(byte[] vz, int vzOff, byte[] vx, int vxOff, byte[] my, int myOff, int m, int n)
    {
        long[] scratch = new long[n];
        for (int j = 0; j < n; ++j)
        {
            scratch[j] = vz[vzOff + j] & 0xff;
        }
        for (int j = 0; j < m; ++j)
        {
            int xj = vx[vxOff + j] & 0xff;
            int rowOff = myOff + n * j;
            for (int i = 0; i < n; ++i)
            {
                scratch[i] += (long)xj * (long)(my[rowOff + i] & 0xff);
            }
        }
        for (int j = 0; j < n; ++j)
        {
            vz[vzOff + j] = (byte)reduce32((int)(scratch[j] & 0xffffffffL));
        }
    }
}
