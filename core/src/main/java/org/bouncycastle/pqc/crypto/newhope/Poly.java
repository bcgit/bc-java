package org.bouncycastle.pqc.crypto.newhope;

import org.bouncycastle.crypto.digests.SHAKEDigest;

class Poly
{
    static void add(short[] x, short[] y, short[] z)
    {
        for (int i = 0; i < Params.N; ++i)
        {
            z[i] = Reduce.barrett((short)(x[i] + y[i]));
        }
    }

    static void bitReverse(short[] r)
    {
        NTT.bitReverse(r);
    }

    static void fromBytes(short[] r, byte[] a)
    {
        for (int i = 0; i < Params.N; ++i)
        {
            byte lo = a[2 * i];
            byte hi = a[2 * i + 1];
            int x = (lo & 0xFF) | ((hi & 0x3F) << 8);
            r[i] = (short)x;
        }
    }

    static void fromNTT(short[] r)
    {
        NTT.core(r, Precomp.OMEGAS_INV_MONTGOMERY);
        NTT.mulCoefficients(r, Precomp.PSIS_INV_MONTGOMERY);
    }

    static void getNoise(short[] r, byte[] seed, byte nonce)
    {
        byte[] iv = new byte[8];
        iv[0] = nonce;

        byte[] buf = new byte[3 * r.length];
        ChaCha20.process(seed, iv, buf, 0, buf.length);

        int j = 0;
        for (int i = 0; i < r.length; ++i)
        {
            int f = buf[j++] & 0xFF; 
            int g = buf[j++] & 0xFF; 
            int h = buf[j++] & 0xFF;

            int t = (f << 16) | (g << 8) | h;
            r[i] = (short)(bitCount(t) + Params.Q - 12);
        }
    }

    static void pointWise(short[] x, short[] y, short[] z)
    {
        for (int i = 0; i < Params.N; ++i)
        {
            int xi = x[i] & 0xFFFF, yi = y[i] & 0xFFFF;
            short t = Reduce.montgomery(3186 * yi);         // t is now in Montgomery domain
            z[i] = Reduce.montgomery(xi * (t & 0xFFFF));    // z[i] is back in normal domain
        }
    }

    static void toBytes(byte[] r, short[] p)
    {
        for (int i = 0; i < Params.N; ++i)
        {
            int t = Reduce.barrett(p[i]);   // Make sure that coefficients have only 14 bits
            int m = t - Params.Q;
            int c = m >> 31;
            t = m ^ ((t ^ m) & c);          // Make sure that coefficients are in [0,q]
            r[2 * i    ] = (byte)t;
            r[2 * i + 1] = (byte)(t >>> 8);
        }
    }

    static void toNTT(short[] r)
    {
        NTT.mulCoefficients(r, Precomp.PSIS_BITREV_MONTGOMERY); 
        NTT.core(r, Precomp.OMEGAS_MONTGOMERY);
    }

    static void uniform(short[] a, byte[] seed)
    {
        SHAKEDigest xof = new SHAKEDigest(128);
        xof.update(seed, 0, seed.length);

        int pos = 0;
        for (;;)
        {
            byte[] output = new byte[256];
            xof.doOutput(output, 0, output.length);

            for (int i = 0; i < output.length; i += 2)
            {
                int val = (output[i] & 0xFF) | ((output[i + 1] & 0xFF) << 8);
                val &= 0x3FFF;
                if (val < Params.Q)
                {
                    a[pos++] = (short)val;
                    if (pos == Params.N)
                    {
                        return;
                    }
                }
            }
        }
    }

    private static int bitCount(int n)
    {
//        return Integer.bitCount(n);
        n = n - ((n >>> 1) & 0x55555555);
        n = (n & 0x33333333) + ((n >>> 2) & 0x33333333);
        return ((n + (n >>> 4) & 0x0F0F0F0F) * 0x01010101) >>> 24;
    }
}
