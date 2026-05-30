package org.bouncycastle.pqc.crypto.hqc;

class ReedMuller
{
    static void encodeSub(int[] out, int m)
    {
        int word1 = Bit0Mask(m >> 7);
        word1 ^= Bit0Mask(m) & 0xaaaaaaaa;
        word1 ^= Bit0Mask(m >> 1) & 0xcccccccc;
        word1 ^= Bit0Mask(m >> 2) & 0xf0f0f0f0;
        word1 ^= Bit0Mask(m >> 3) & 0xff00ff00;
        word1 ^= Bit0Mask(m >> 4) & 0xffff0000;
        out[0] = word1;

        word1 ^= Bit0Mask(m >> 5);
        out[1] = word1;

        word1 ^= Bit0Mask(m >> 6);
        out[3] = word1;

        word1 ^= Bit0Mask(m >> 5);
        out[2] = word1;
    }

    private static void hadamardTransform(int[] src, int[] dst)
    {
        for (int i = 0; i < 7; i++)
        {
            for (int j = 0; j < 64; j++)
            {
                int u = src[2 * j], v = src[2 * j + 1];
                dst[j     ] = u + v;
                dst[j + 64] = u - v;
            }

            // Swap
            int[] tmp = src; src = dst; dst = tmp;
        }
    }

    private static void expandThenSum(int[] desCode, int[] byteCodewords, int off, int mulParam)
    {
        int base = off * 4;
        for (int i = 0; i < 4; i++)
        {
            int t = byteCodewords[base + i];
            int destBase = i * 32;
            for (int j = 0; j < 32; j++)
            {
                desCode[destBase + j] = (t >> j) & 1;
            }
        }

        for (int i = 1; i < mulParam; i++)
        {
            int srcBase = base + i * 4;
            for (int j = 0; j < 4; j++)
            {
                int t = byteCodewords[srcBase + j];
                int destBase = j * 32;
                for (int k = 0; k < 32; k++)
                {
                    desCode[destBase + k] += (t >> k) & 1;
                }
            }
        }
    }

    private static int findPeaks(int[] input)
    {
        int peakAbsVal = 0;
        int peakVal = 0;
        int peakPos = 0;

        for (int i = 0; i < 128; i++)
        {
            int t = input[i];
            int posMask = t > 0 ? -1 : 0;
            int abs = (posMask & t) | (~posMask & -t);

            peakVal = abs > peakAbsVal ? t : peakVal;
            peakPos = abs > peakAbsVal ? i : peakPos;
            peakAbsVal = Math.max(abs, peakAbsVal);
        }
        int tmp = peakVal > 0 ? 1 : 0;
        peakPos |= 128 * tmp;
        return peakPos;
    }

    private static int Bit0Mask(int b)
    {
        return -(b & 1);
    }

    public static void encode(long[] codeword, byte[] m, int n1, int mulParam)
    {
        int[] word32 = new int[4];
        int outOff = 0;
        for (int i = 0; i < n1; i++)
        {
            encodeSub(word32, m[i]);
            long lo = (word32[0] & 0xFFFFFFFFL) | ((long)word32[1] << 32);
            long hi = (word32[2] & 0xFFFFFFFFL) | ((long)word32[3] << 32);
            for (int j = 0; j < mulParam; j++)
            {
                codeword[outOff    ] = lo;
                codeword[outOff + 1] = hi;
                outOff += 2;
            }
        }
    }

    public static void decode(byte[] m, long[] codeword, int n1, int mulParam)
    {
        int[] byteCodeWords = new int[codeword.length * 2];
        Utils.fromLongArrayToByte32Array(byteCodeWords, codeword);

        int[] expandedCodeword = new int[128];
        int[] tmp = new int[128];

        for (int i = 0; i < n1; i++)
        {
            expandThenSum(expandedCodeword, byteCodeWords, i * mulParam, mulParam);
            hadamardTransform(expandedCodeword, tmp);
            tmp[0] -= 64 * mulParam;
            m[i] = (byte)findPeaks(tmp);
        }
    }
}
