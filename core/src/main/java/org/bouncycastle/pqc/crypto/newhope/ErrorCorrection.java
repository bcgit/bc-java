package org.bouncycastle.pqc.crypto.newhope;

import org.bouncycastle.util.Arrays;

class ErrorCorrection
{
    static int abs(int v)
    {
        int mask = v >> 31;
        return (v ^ mask) - mask;
    }

    static int f(int[] v, int off0, int off1, int x)
    {
        int xit, t, r, b;

        // Next 6 lines compute t = x/Params.Q;
        b = x * 2730;
        t = b >> 25;
        b = x - t * Params.Q;
        b = 12288 - b;
        b >>= 31;
        t -= b;

        r = t & 1;
        xit =  t >> 1;
        v[off0] = xit + r; // v0 = round(x/(2*Params.Q))

        t -= 1;
        r = t & 1;
        v[off1] = (t >> 1) + r;

        return abs(x-((v[off0]) * 2 * Params.Q));
    }

    static int g(int x)
    {
        int t, c, b;

        // Next 6 lines compute t = x/(4 * Params.Q);
        b = x * 2730;
        t = b >> 27;
        b = x - t * 49156;
        b = 49155 - b;
        b >>= 31;
        t -= b;

        c = t & 1;
        t = (t >> 1) + c; // t = round(x/(8 * Params.Q))

        t *= 8 * Params.Q;

        return abs(t - x);
    }

    static void helpRec(short[] c, short[] v, byte[] seed, byte nonce)
    {
        byte[] iv = new byte[8];
//        iv[7] = nonce;
        iv[0] = nonce;

        byte[] rand = new byte[32];
        ChaCha20.process(seed, iv, rand, 0, rand.length);

//      int32_t v0[4], v1[4], v_tmp[4], k;
        int[] vs = new int[8], vTmp = new int[4];
        int k;

        for (int i = 0; i < 256; ++i)
        {
            int rBit = (rand[i >>> 3] >>> (i & 7)) & 1;

            k  = f(vs, 0, 4, 8 * v[  0 + i] + 4 * rBit);
            k += f(vs, 1, 5, 8 * v[256 + i] + 4 * rBit);
            k += f(vs, 2, 6, 8 * v[512 + i] + 4 * rBit);
            k += f(vs, 3, 7, 8 * v[768 + i] + 4 * rBit);

            k = (2 * Params.Q - 1 - k) >> 31;

            vTmp[0] = ((~k) & vs[0]) ^ (k & vs[4]);
            vTmp[1] = ((~k) & vs[1]) ^ (k & vs[5]);
            vTmp[2] = ((~k) & vs[2]) ^ (k & vs[6]);
            vTmp[3] = ((~k) & vs[3]) ^ (k & vs[7]);

            c[  0 + i] = (short)((vTmp[0] -     vTmp[3]) & 3);  
            c[256 + i] = (short)((vTmp[1] -     vTmp[3]) & 3);
            c[512 + i] = (short)((vTmp[2] -     vTmp[3]) & 3);
            c[768 + i] = (short)((   -k   + 2 * vTmp[3]) & 3);
        }
    }

    static short LDDecode(int xi0, int xi1, int xi2, int xi3)
    {
        int t;

        t  = g(xi0);
        t += g(xi1);
        t += g(xi2);
        t += g(xi3);

        t -= 8 * Params.Q;

        return (short)(t >>> 31);
    }

    static void rec(byte[] key, short[] v, short[] c)
    {
        Arrays.fill(key, (byte)0);

        int[] tmp = new int[4];
        for(int i = 0; i < 256; ++i)
        {
            tmp[0] = 16 * Params.Q + 8 * (int)v[  0 + i] - Params.Q * (2 * c[  0 + i] + c[768 + i]);
            tmp[1] = 16 * Params.Q + 8 * (int)v[256 + i] - Params.Q * (2 * c[256 + i] + c[768 + i]);
            tmp[2] = 16 * Params.Q + 8 * (int)v[512 + i] - Params.Q * (2 * c[512 + i] + c[768 + i]);
            tmp[3] = 16 * Params.Q + 8 * (int)v[768 + i] - Params.Q * (                 c[768 + i]);

            key[i >>> 3] |= LDDecode(tmp[0], tmp[1], tmp[2], tmp[3]) << (i & 7);
        }
    }
}
