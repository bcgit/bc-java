package org.bouncycastle.pqc.crypto.hqc;

class GF2PolynomialCalculator
{
    static volatile int TABLE = 16;
    static volatile int WORD = 64;

    static void mod(long[] res, long[] a, int n, int nByte64)
    {
        long r;
        long carry;
        for (int i = 0; i < nByte64; i++)
        {
            r = a[i + nByte64 - 1] >>> (n & 0x3F);
            carry = a[i + nByte64] << (64 - (n & 0x3F));
            res[i] = a[i] ^ r ^ carry;
        }
        res[nByte64 - 1] &= Utils.bitMask(n, 64);
    }

    static void swap(int[] table, int fisrtIndex, int secIndex)
    {
        int tmp = table[fisrtIndex];
        table[fisrtIndex] = table[secIndex];
        table[secIndex] = tmp;
    }

    static void fastConvolutionMult(long[] res, int[] a, long[] b, int weight, int nByte64, int we, KeccakRandomGenerator random)
    {
        long carry;
        int dec, s;
        long[] table = new long[TABLE * (nByte64 + 1)];
        int[] permutedTable = new int[TABLE];
        int[] permutationTable = new int[TABLE];
        int[] permutedSparseVect = new int[we];
        int[] permutationSparseVect = new int[we];

        for (int i = 0; i < 16; i++)
        {
            permutedTable[i] = i;
        }

        byte[] permutationTableByte = new byte[TABLE * 2];
        random.expandSeed(permutationTableByte, TABLE << 1);

        Utils.fromByteArrayToByte16Array(permutationTable, permutationTableByte);

        for (int i = 0; i < TABLE - 1; i++)
        {
            swap(permutedTable, i, i + permutationTable[i] % (TABLE - i));
        }

        //int count = (permutedTable[0] * (nByte64 + 1));
        int idx = permutedTable[0] * (nByte64 + 1);
        long[] pt = new long[nByte64 + 1];

        for (int i = 0; i < nByte64; i++)
        {
            pt[i] = (long)b[i];
        }

        pt[nByte64] = 0x0L;

        System.arraycopy(pt, 0, table, idx, pt.length);

        for (int i = 1; i < TABLE; i++)
        {
            carry = 0x0L;
            idx = permutedTable[i] * (nByte64 + 1);
            long[] pt2 = new long[nByte64 + 1];

            for (int j = 0; j < nByte64; j++)
            {
                pt2[j] = (b[j] << i) ^ carry;
                carry = (b[j] >>> ((WORD - i)));
            }

            pt2[nByte64] = carry;
            System.arraycopy(pt2, 0, table, idx, pt2.length);
        }

        for (int i = 0; i < weight; i++)
        {
            permutedSparseVect[i] = i;
        }

        byte[] permutationSparseVectBytes = new byte[we * 2];
        random.expandSeed(permutationSparseVectBytes, weight << 1);

        Utils.fromByteArrayToByte16Array(permutationSparseVect, permutationSparseVectBytes);

        for (int i = 0; i < (weight - 1); i++)
        {
            swap(permutedSparseVect, i, i + permutationSparseVect[i] % (weight - i));
        }

        int[] resByte16 = new int[res.length * 4];

        for (int i = 0; i < weight; i++)
        {
            carry = 0x0L;
            dec = a[permutedSparseVect[i]] & 0xf;
            s = a[permutedSparseVect[i]] >> 4;

            idx = (permutedTable[dec] * (nByte64 + 1));
            long[] pt3 = new long[nByte64 + 1];
            for (int j = 0; j < pt3.length; j++)
            {
                pt3[j] = table[j + idx];
            }
            int count = s;
            for (int j = 0; j < nByte64 + 1; j++)
            {
                long tmp = (long)(((long)resByte16[count]) | (((long)resByte16[count + 1]) << 16) | ((long)(resByte16[count + 2]) << 32) | (((long)(resByte16[count + 3])) << 48));
                tmp ^= pt3[j];
                addlongToByte16Array(resByte16, tmp, count);
                count += 4;
            }
        }
        Utils.fromByte16ArrayToLongArray(res, resByte16);
    }

    static void modMult(long[] res, int[] a, long[] b, int weight, int n, int nByte64, int we, KeccakRandomGenerator random)
    {
        long[] tmp = new long[(nByte64 << 1) + 1];
        fastConvolutionMult(tmp, a, b, weight, nByte64, we, random);
        mod(res, tmp, n, nByte64);
    }

    private static void addlongToByte16Array(int[] array, long t, int startIndex)
    {
        long[] tmp = new long[]{t};
        int[] tmpArray = new int[4];
        Utils.fromLongArrayToByte16Array(tmpArray, tmp);
        System.arraycopy(tmpArray, 0, array, startIndex, tmpArray.length);
    }


    static void addLongs(long[] res, long[] a, long[] b)
    {
        for (int i = 0; i < a.length; i++)
        {
            res[i] = a[i] ^ (long)b[i];
        }
    }
}