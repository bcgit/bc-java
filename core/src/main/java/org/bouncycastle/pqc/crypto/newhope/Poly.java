package org.bouncycastle.pqc.crypto.newhope;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Pack;

class Poly
{
    static void add(short[] x, short[] y, short[] z)
    {
        for (int i = 0; i < Params.N; ++i)
        {
            z[i] = Reduce.barrett((short)(x[i] + y[i]));
        }
    }

    static void fromBytes(short[] r, byte[] a)
    {
        for (int i = 0; i < Params.N / 4; ++i)
        {
            int j = 7 * i;
            int a0 = a[j + 0] & 0xFF, a1 = a[j + 1] & 0xFF, a2 = a[j + 2] & 0xFF, a3 = a[j + 3] & 0xFF,
                a4 = a[j + 4] & 0xFF, a5 = a[j + 5] & 0xFF, a6 = a[j + 6] & 0xFF;

            int k = 4 * i;
            r[k + 0] = (short)( a0                    | ((a1 & 0x3F) <<  8));
            r[k + 1] = (short)((a1 >>> 6) | (a2 << 2) | ((a3 & 0x0F) << 10));
            r[k + 2] = (short)((a3 >>> 4) | (a4 << 4) | ((a5 & 0x03) << 12));
            r[k + 3] = (short)((a5 >>> 2) | (a6 << 6));
        }
    }

    static void fromNTT(short[] r)
    {
        NTT.bitReverse(r);
        NTT.core(r, Precomp.OMEGAS_INV_MONTGOMERY);
        NTT.mulCoefficients(r, Precomp.PSIS_INV_MONTGOMERY);
    }

    static void getNoise(short[] r, byte[] seed, byte nonce)
    {
        byte[] iv = new byte[8];
        iv[0] = nonce;

        byte[] buf = new byte[4 * Params.N];
        ChaCha20.process(seed, iv, buf, 0, buf.length);

        for (int i = 0; i < Params.N; ++i)
        {
            int t = Pack.bigEndianToInt(buf, i * 4);
            //r[i] = (short)(bitCount(t) + Params.Q - Params.K);

            int d = 0;
            for (int j = 0; j < 8; ++j)
            {
                d += (t >> j) & 0x01010101;
            }
            int a = ((d >>> 24) + (d >>> 0)) & 0xFF;
            int b = ((d >>> 16) + (d >>> 8)) & 0xFF;
            r[i] = (short)(a + Params.Q - b);
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
        for (int i = 0; i < Params.N / 4; ++i)
        {
            int j = 4 * i;

            // Make sure that coefficients are in [0,q]
            short t0 = normalize(p[j + 0]);
            short t1 = normalize(p[j + 1]);
            short t2 = normalize(p[j + 2]);
            short t3 = normalize(p[j + 3]);

            int k = 7 * i;
            r[k + 0] = (byte)t0;
            r[k + 1] = (byte)((t0 >> 8) | (t1 << 6));
            r[k + 2] = (byte)(t1 >> 2);
            r[k + 3] = (byte)((t1 >> 10) | (t2 << 4));
            r[k + 4] = (byte)(t2 >> 4);
            r[k + 5] = (byte)((t2 >> 12) | (t3 << 2));
            r[k + 6] = (byte)(t3 >> 6);
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
                if (val < 5 * Params.Q)
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

//    private static int bitCount(int n)
//    {
////        return Integer.bitCount(n);
//        n = n - ((n >>> 1) & 0x55555555);
//        n = (n & 0x33333333) + ((n >>> 2) & 0x33333333);
//        return ((n + (n >>> 4) & 0x0F0F0F0F) * 0x01010101) >>> 24;
//    }

    private static short normalize(short x)
    {
        int t = Reduce.barrett(x);
        int m = t - Params.Q;
        int c = m >> 31;
        t = m ^ ((t ^ m) & c);
        return (short)t;
    }
}
