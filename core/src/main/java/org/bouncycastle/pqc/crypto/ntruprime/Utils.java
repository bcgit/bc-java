package org.bouncycastle.pqc.crypto.ntruprime;

import java.security.SecureRandom;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

class Utils
{
    protected static int getRandomUnsignedInteger(SecureRandom random)
    {
        byte[] c = new byte[4];
        random.nextBytes(c);
        return (bToUnsignedInt(c[0])
                + (bToUnsignedInt(c[1]) << 8)
                + (bToUnsignedInt(c[2]) << 16)
                + (bToUnsignedInt(c[3]) << 24));
    }

    protected static void getRandomSmallPolynomial(SecureRandom random, byte[] g)
    {
        for (int i = 0; i < g.length; i++)
            g[i] = (byte)((((getRandomUnsignedInteger(random) & 0x3fffffff) * 3) >>> 30) - 1);
    }

    protected static int getModFreeze(int x, int n)
    {
        return getSignedDivMod((x + ((n - 1) / 2)), n)[1] - ((n - 1) / 2);
    }

    protected static boolean isInvertiblePolynomialInR3(byte[] g, byte[] ginv, int p)
    {
        byte[] f = new byte[p + 1];
        byte[] h = new byte[p + 1];
        byte[] r = new byte[p + 1];
        byte[] v = new byte[p + 1];
        int loop, delta, sign, swap, t, i;

        r[0] = 1;
        f[0] = 1;
        f[p - 1] = -1;
        f[p] = -1;
        for (i = 0; i < p; i++)
            h[p - 1 - i] = g[i];

        h[p] = 0;
        delta = 1;

        for (loop = 0; loop < (2 * p) - 1; loop++)
        {
            System.arraycopy(v, 0, v, 1, p);
            v[0] = 0;

            sign = -h[0] * f[0];
            swap = checkLessThanZero(-delta) & checkNotEqualToZero(h[0]);
            delta ^= swap & (delta ^ -delta);
            delta += 1;

            for (i = 0; i < p + 1; i++)
            {
                t = swap & (f[i] ^ h[i]);
                f[i] ^= t;
                h[i] ^= t;
                t = swap & (v[i] ^ r[i]);
                v[i] ^= t;
                r[i] ^= t;
            }

            for (i = 0; i < p + 1; i++)
                h[i] = (byte)getModFreeze(h[i] + sign * f[i], 3);
            for (i = 0; i < p + 1; i++)
                r[i] = (byte)getModFreeze(r[i] + sign * v[i], 3);

            for (i = 0; i < p; i++)
                h[i] = h[i+1];
            h[p] = 0;
        }

        sign = f[0];
        for (i = 0; i < p; i++)
            ginv[i] = (byte)(sign * v[p - 1 - i]);

        return (delta == 0);
    }

    protected static void minmax(int[] L, int x, int y)
    {
        int xi = L[x];
        int yi = L[y];
        int xy = xi ^ yi;
        int c = yi - xi;
        c ^= xy & (c ^ yi ^ 0x80000000);
        c = c >>> 31;
        c = -c;
        c &= xy;
        L[x] = xi ^ c;
        L[y] = yi ^ c;
    }

    protected static void cryptoSort(int[] L, int p)
    {
        int top, a, b, i;

        if (p < 2)
          return;

        top = 1;
        while (top < p - top)
          top += top;

        for (a = top; a > 0; a = a >>> 1)
        {
            for (i = 0; i < p - a; i++)
                if ((i & a) == 0)
                    minmax(L, i, i + a);
            for (b = top; b > a; b = b >>> 1)
                for (i = 0; i < p - b; i++)
                    if ((i & a) == 0)
                        minmax(L, i + a, i + b);
        }
    }

    protected static void sortGenerateShortPolynomial(byte[] f, int[] L, int p, int w)
    {
        for (int i = 0; i < w; i++)
            L[i] = L[i] & -2;
        for (int i = w; i < p; i++)
            L[i] = (L[i] & -3) | 1;
        cryptoSort(L, p);
        for (int i = 0; i < p; i++)
            f[i] = (byte)((L[i] & 3) - 1);
    }

    protected static void getRandomShortPolynomial(SecureRandom random, byte[] f, int p, int w)
    {
        int[] L = new int[p];
        for (int i = 0; i < p; i++)
            L[i] = getRandomUnsignedInteger(random);
        sortGenerateShortPolynomial(f, L, p, w);
    }

    protected static int getInverseInRQ(int x, int q)
    {
        int ai = x;
        for (int i = 1; i < q - 2; i++)
            ai = getModFreeze(x * ai, q);
        return ai;
    }

    protected static void getOneThirdInverseInRQ(short[] finv3, byte[] f, int p, int q)
    {
        short[] h = new short[p + 1];
        short[] g = new short[p + 1];
        short[] r = new short[p + 1];
        short[] v = new short[p + 1];
        int loop, delta, scale, swap, h0, g0, t, i;

        r[0] = (short)getInverseInRQ(3, q);
        h[0] = 1;
        h[p - 1] = -1;
        h[p] = -1;
        for (i = 0; i < p; i++)
            g[p - 1 - i] = f[i];

        g[p] = 0;
        delta = 1;

        for (loop = 0; loop < (2 * p) - 1; loop++)
        {
            System.arraycopy(v, 0, v, 1, p);
            v[0] = 0;

            swap = checkLessThanZero(-delta) & checkNotEqualToZero(g[0]);
            delta ^= swap & (delta ^ -delta);
            delta += 1;

            for (i = 0; i < p + 1; i++)
            {
                t = swap & (h[i] ^ g[i]);
                h[i] ^= t;
                g[i] ^= t;
                t = swap & (v[i] ^ r[i]);
                v[i] ^= t;
                r[i] ^= t;
            }

            h0 = h[0];
            g0 = g[0];
            for (i = 0; i < p + 1; i++)
                g[i] = (short)getModFreeze((h0 * g[i]) - (g0 * h[i]), q);
            for (i = 0; i < p + 1; i++)
                r[i] = (short)getModFreeze((h0 * r[i]) - (g0 * v[i]), q);

            for (i = 0; i < p; i++)
                g[i] = g[i+1];
            g[p] = 0;
        }

        scale = getInverseInRQ(h[0], q);
        for (i = 0; i < p; i++)
            finv3[i] = (short)getModFreeze(scale * v[p - 1 - i], q);
    }

    protected static void multiplicationInRQ(short[] h, short[] finv3, byte[] g, int p, int q)
    {
        short[] fg = new short[p + p - 1];
        short result;
        int i, j;

        for (i = 0; i < p; i++)
        {
            result = 0;
            for (j = 0; j <= i; j++)
                result = (short)getModFreeze(result + (finv3[j] * g[i - j]), q);
            fg[i] = result;
        }

        for (i = p; i < p + p - 1; i++)
        {
            result = 0;
            for (j = i - p + 1; j < p; j++)
                result = (short)getModFreeze(result + (finv3[j] * g[i - j]), q);
            fg[i] = result;
        }

        for (i = p + p - 2; i >= p; i--)
        {
            fg[i - p] = (short)getModFreeze(fg[i - p] + fg[i], q);
            fg[i - p + 1] = (short)getModFreeze(fg[i - p + 1] + fg[i], q);
        }

        for (i = 0; i < p; i++)
            h[i] = fg[i];
    }

    private static void encode(byte[] out, short[] R, short[] M, int len, int start)
    {
        if (len == 1)
        {
            short r = R[0];
            short m = M[0];
            while (m > 1)
            {
                out[start++] = (byte)r;
                r = (short)(r >>> 8);
                m = (short)((m + 255) >>> 8);
            }
        }

        if (len > 1)
        {
            short[] R2 = new short[(len + 1) / 2];
            short[] M2 = new short[(len + 1) / 2];
            int i;

            for (i = 0; i < len - 1; i += 2)
            {
                int m0 = M[i];
                int r = R[i] + (R[i + 1] * m0);
                int m = M[i + 1] * m0;
                while (m >= 16384)
                {
                    out[start++] = (byte)r;
                    r = r >>> 8;
                    m = (m + 255) >>> 8;
                }
                R2[i / 2] = (short)r;
                M2[i / 2] = (short)m;
            }

            if (i < len)
            {
                R2[i / 2] = R[i];
                M2[i / 2] = M[i];
            }

            encode(out, R2, M2,(len + 1) / 2, start);
        }
    }

    protected static void getEncodedPolynomial(byte[] enc, short[] h, int p, int q)
    {
        short[] R = new short[p];
        short[] M = new short[p];

        for (int i = 0; i < p; i++)
            R[i] = (short)(h[i] + ((q - 1) / 2));
        for (int i = 0; i < p; i++)
            M[i] = (short)q;

        encode(enc, R, M, p, 0);
    }

    protected static void getEncodedSmallPolynomial(byte[] encSP, byte[] sp, int p)
    {
        byte x;
        int spIndex = 0;
        int encSPIndex = 0;
        for (int i = 0; i < p / 4; i++)
        {
            x = (byte)(sp[spIndex++] + 1);
            x += (byte)(sp[spIndex++] + 1) << 2;
            x += (byte)(sp[spIndex++] + 1) << 4;
            x += (byte)(sp[spIndex++] + 1) << 6;
            encSP[encSPIndex++] = x;
        }
        encSP[encSPIndex] = (byte)(sp[spIndex] + 1);
    }

    private static void generateAES256CTRStream(byte[] in, byte[] out, byte[] nonce, byte[] key)
    {
        StreamCipher cipher = SICBlockCipher.newInstance(AESEngine.newInstance());
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        cipher.processBytes(in, 0, out.length, out, 0);
    }

    protected static void expand(int[] L, byte[] k)
    {
        byte[] aesInput = new byte[L.length * 4];
        byte[] aesOutput = new byte[L.length * 4];
        byte[] nonce = new byte[16];
        generateAES256CTRStream(aesInput, aesOutput, nonce, k);
        for (int i = 0; i < L.length; i++)
            L[i] = (bToUnsignedInt(aesOutput[i * 4])
                    + (bToUnsignedInt(aesOutput[(i * 4) + 1]) << 8)
                    + (bToUnsignedInt(aesOutput[(i * 4) + 2]) << 16)
                    + (bToUnsignedInt(aesOutput[(i * 4) + 3]) << 24));
    }

    private static int getUnsignedMod(int x, int n)
    {
        return getUnsignedDivMod(x, n)[1];
    }

    protected static void generatePolynomialInRQFromSeed(short[] G, byte[] seed, int p, int q)
    {
        int[] L = new int[p];
        expand(L, seed);

        for (int i = 0; i < p; i++)
            G[i] = (short)(getUnsignedMod(L[i], q) - ((q - 1) / 2));
    }

    protected static void roundPolynomial(short[] out, short[] in)
    {
        for (int i = 0; i < out.length; i++)
            out[i] = (short)(in[i] - getModFreeze(in[i], 3));
    }

    protected static void getRoundedEncodedPolynomial(byte[] out, short[] in, int p, int q)
    {
        short[] R = new short[p];
        short[] M = new short[p];

        for (int i = 0; i < p; i++)
        {
            R[i] = (short)(((in[i] + ((q - 1) / 2)) * 10923) >>> 15);
            M[i] = (short)((q + 2) / 3);
        }

        encode(out, R, M, p, 0);
    }

    protected static byte[] getHashWithPrefix(byte[] prefix, byte[] hashInput)
    {
        byte[] hash = new byte[64];
        byte[] input = new byte[prefix.length + hashInput.length];
        System.arraycopy(prefix, 0, input, 0, prefix.length);
        System.arraycopy(hashInput, 0, input, prefix.length, hashInput.length);
        SHA512Digest hashDigest = new SHA512Digest();
        hashDigest.update(input, 0, input.length);
        hashDigest.doFinal(hash, 0);
        return hash;
    }

    private static void decode(short[] out, byte[] S, short[] M, int len, int start, int sIndex)
    {
        if (len == 1)
        {
            if (M[0] == 1)
                out[start] = 0;
            else if (M[0] <= 256)
                out[start] = (short)getUnsignedMod(bToUnsignedInt(S[sIndex]), M[0]);
            else
                out[start] = (short)getUnsignedMod(bToUnsignedInt(S[sIndex]) + (S[sIndex + 1] << 8), M[0]);
        }

        if (len > 1)
        {
            short[] R2 = new short[(len + 1) / 2];
            short[] M2 = new short[(len + 1) / 2];
            short[] bottomr = new short[len / 2];
            int[] bottomt = new int[len / 2];
            int i;

            for (i = 0; i < len - 1; i += 2)
            {
                int m = M[i] * (int)M[i+1];
                if (m > (256 * 16383))
                {
                    bottomt[i / 2] = 256 * 256;
                    bottomr[i / 2] = (short)(bToUnsignedInt(S[sIndex]) + (256 * bToUnsignedInt(S[sIndex + 1])));
                    sIndex += 2;
                    M2[i / 2] = (short)((((m + 255) >>> 8) + 255) >>> 8);
                }
                else if (m >= 16384)
                {
                    bottomt[i / 2] = 256;
                    bottomr[i / 2] = (short)bToUnsignedInt(S[sIndex]);
                    sIndex += 1;
                    M2[i / 2] = (short)((m + 255) >>> 8);
                }
                else
                {
                    bottomt[i / 2] = 1;
                    bottomr[i / 2] = 0;
                    M2[i / 2] = (short)m;
                }
            }
            if (i < len)
                M2[i / 2] = M[i];

            decode(R2, S, M2,(len + 1) / 2, start, sIndex);

            for (i = 0; i < len - 1; i += 2)
            {
                int r = sToUnsignedInt(bottomr[i / 2]);
                r += bottomt[i / 2] * sToUnsignedInt(R2[i / 2]);
                int[] r01 = getUnsignedDivMod(r, M[i]);
                out[start++] = (short)r01[1];
                out[start++] = (short)getUnsignedMod(r01[0], M[i + 1]);
            }
            if (i < len)
                out[start] = R2[i / 2];
        }
    }

    protected static void getDecodedPolynomial(short[] h, byte[] enc, int p, int q)
    {
        short[] R = new short[p];
        short[] M = new short[p];

        for (int i = 0; i < p; i++)
            M[i] = (short)q;

        decode(R, enc, M, p, 0, 0);

        for (int i = 0; i < p; i++)
            h[i] = (short)(R[i] - ((q - 1) / 2));
    }

    protected static void getRandomInputs(SecureRandom random, byte[] r)
    {
        byte[] seed = new byte[r.length / 8];
        random.nextBytes(seed);

        for (int i = 0; i < r.length; i++)
            r[i] = (byte)(1 & (seed[i >>> 3] >>> (i & 7)));
    }

    protected static void getEncodedInputs(byte[] out, byte[] in)
    {
        for (int i = 0; i < in.length; i++)
            out[i >>> 3] |= in[i] << (i & 7);
    }

    protected static void getRoundedDecodedPolynomial(short[] h, byte[] enc, int p, int q)
    {
        short[] R = new short[p];
        short[] M = new short[p];

        for (int i = 0; i < p; i++)
            M[i] = (short)((q + 2) / 3);

        decode(R, enc, M, p, 0, 0);

        for (int i = 0; i < p; i++)
            h[i] = (short)((R[i] * 3) - ((q - 1) / 2));
    }

    protected static void top(byte[] out, short[] bA, byte[] r, int q, int tau0, int tau1)
    {
        for (int i = 0; i < out.length; i++)
            out[i] = (byte)((tau1 * (getModFreeze(bA[i] + r[i] * ((q - 1) / 2), q) + tau0) + 16384) >>> 15);
    }

    protected static void getTopEncodedPolynomial(byte[] out, byte[] in)
    {
        for (int i = 0; i < out.length; i++)
            out[i] = (byte)(in[2 * i] + (in[(2 * i) + 1] << 4));
    }

    protected static void getDecodedSmallPolynomial(byte[] sp, byte[] encSP, int p)
    {
        byte x;
        int spIndex = 0;
        int encSPIndex = 0;

        for (int i = 0; i < p / 4; i++)
        {
            x = encSP[encSPIndex++];
            sp[spIndex++] = (byte)((bToUnsignedInt(x) & 3) - 1); x >>>= 2;
            sp[spIndex++] = (byte)((bToUnsignedInt(x) & 3) - 1); x >>>= 2;
            sp[spIndex++] = (byte)((bToUnsignedInt(x) & 3) - 1); x >>>= 2;
            sp[spIndex++] = (byte)((bToUnsignedInt(x) & 3) - 1);
        }

        x = encSP[encSPIndex];
        sp[spIndex] = (byte)((bToUnsignedInt(x) & 3) - 1);
    }

    protected static void scalarMultiplicationInRQ(short[] out, short[] in, int scalar, int q)
    {
        for (int i = 0; i < in.length; i++)
            out[i] = (short)getModFreeze(scalar * in[i], q);
    }

    protected static void transformRQToR3(byte[] out, short[] in)
    {
        for (int i = 0; i < in.length; i++)
            out[i] = (byte)getModFreeze(in[i], 3);
    }

    protected static void multiplicationInR3(byte[] h, byte[] finv3, byte[] g, int p)
    {
        byte[] fg = new byte[p + p - 1];
        byte result;
        int i, j;

        for (i = 0; i < p; i++)
        {
            result = 0;
            for (j = 0; j <= i; j++)
                result = (byte) getModFreeze(result + (finv3[j] * g[i - j]), 3);
            fg[i] = result;
        }

        for (i = p; i < p + p - 1; i++)
        {
            result = 0;
            for (j = i - p + 1; j < p; j++)
                result = (byte)getModFreeze(result + (finv3[j] * g[i - j]), 3);
            fg[i] = result;
        }

        for (i = p + p - 2; i >= p; i--)
        {
            fg[i - p] = (byte)getModFreeze(fg[i - p] + fg[i], 3);
            fg[i - p + 1] = (byte)getModFreeze(fg[i - p + 1] + fg[i], 3);
        }

        for (i = 0; i < p; i++)
            h[i] = fg[i];
    }

    protected static void checkForSmallPolynomial(byte[] r, byte[] ev, int p, int w)
    {
        int weight = 0;
        for (int i = 0; i != ev.length; i++)
        {
            weight += ev[i] & 1;
        }

        int mask = checkNotEqualToZero(weight - w);
        for (int i = 0; i < w; i++)
            r[i] = (byte)(((ev[i] ^ 1) & ~mask) ^ 1);
        for (int i = w; i < p; i++)
            r[i] = (byte)(ev[i] & ~mask);
    }

    protected static void updateDiffMask(byte[] encR, byte[] rho, int mask)
    {
        for (int i = 0; i < encR.length; i++)
            encR[i] ^= mask & (encR[i] ^ rho[i]);
    }

    protected static void getTopDecodedPolynomial(byte[] out, byte[] in)
    {
        for (int i = 0; i < in.length; i++)
        {
            out[2 * i] = (byte)(in[i] & 15);
            out[(2 * i) + 1] = (byte)(in[i] >>> 4);
        }
    }

    protected static void right(byte[] out, short[] aB, byte[] T, int q, int w, int tau2, int tau3)
    {
        for (int i = 0; i < out.length; i++)
            out[i] = (byte)(-checkLessThanZero(getModFreeze(getModFreeze((tau3 * T[i]) - tau2, q) - aB[i] + (4 * w) + 1, q)));
    }

    private static int[] getUnsignedDivMod(int dividend, int n)
    {
        long x = iToUnsignedLong(dividend);
        long v = iToUnsignedLong(0x80000000);
        long q, qpart, mask;

        v /= n;
        q = 0;

        qpart = (x * v) >>> 31;
        x -= qpart * n;
        q += qpart;

        qpart = (x * v) >>> 31;
        x -= qpart * n;
        q += qpart;

        x -= n;
        q += 1;
        mask = -(x >>> 63);
        x += mask & n;
        q += mask;

        return new int[]{toIntExact(q), toIntExact(x)};
    }

    private static int[] getSignedDivMod(int x, int n)
    {
        int q, r, mask;

        int[] div1 = getUnsignedDivMod(toIntExact(0x80000000 + iToUnsignedLong(x)), n);
        int[] div2 = getUnsignedDivMod(0x80000000, n);

        q = toIntExact(iToUnsignedLong(div1[0]) - iToUnsignedLong(div2[0]));
        r = toIntExact(iToUnsignedLong(div1[1]) - iToUnsignedLong(div2[1]));
        mask = -(r >>> 31);
        r += mask & n;
        q += mask;

        return new int[]{q, r};
    }

    private static int checkLessThanZero(int x)
    {
        return -(int)(x >>> 31);
    }

    private static int checkNotEqualToZero(int x)
    {
        long l = iToUnsignedLong(x);
        l = -l;
        return -(int)(l >>> 63);
    }

    static int bToUnsignedInt(byte b)
    {
        return b & 0xff;
    }

    static int sToUnsignedInt(short s)
    {
        return s & 0xffff;
    }
    
    static long iToUnsignedLong(int i)
    {
        return i & 0xffffffffL;
    }

    static int toIntExact(long l)
    {
        int i = (int)l;

        if (i != l)
        {
            throw new IllegalStateException("value out of integer range");
        }
        return i;
    }
}
