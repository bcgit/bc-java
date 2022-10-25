package org.bouncycastle.pqc.crypto.bike;

import org.bouncycastle.pqc.math.linearalgebra.IntUtils;

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

    static void modMult(long[] res, byte[] a, byte[] b, int n, int nByte64, KeccakRandomGenerator random)
    {
        int[] pos1OfA = Utils.getPos1(a);

        long[] bLong = new long[nByte64];
        Utils.fromByteArrayToLongArray(bLong, b);

        long[] tmp = new long[(nByte64 << 1) + 1];
        fastConvolutionMult(tmp, pos1OfA, bLong, pos1OfA.length, nByte64, pos1OfA.length, random);
        mod(res, tmp, n, nByte64);
    }

    static void modMultBits(long[] res, int[] a, int[] b, int n, int nByte64, KeccakRandomGenerator random)
    {
        int[] pos1OfA = Utils.getPos1(Utils.convertIntArrayToBitArray(a));

        long[] bLong = new long[nByte64];
        Utils.fromBitArrayToLongArray(bLong, Utils.convertIntArrayToBitArray(b));

        long[] tmp = new long[(nByte64 << 1) + 1];
        fastConvolutionMult(tmp, pos1OfA, bLong, pos1OfA.length, nByte64, pos1OfA.length, random);
        mod(res, tmp, n, nByte64);
    }

    private static void addlongToByte16Array(int[] array, long t, int startIndex)
    {
        long[] tmp = new long[]{t};
        int[] tmpArray = new int[4];
        Utils.fromLongArrayToByte16Array(tmpArray, tmp);
        System.arraycopy(tmpArray, 0, array, startIndex, tmpArray.length);
    }

    static byte[] modInv(int[] poly, int n, int nByte64, KeccakRandomGenerator random)
    {
        long[] polyLong = new long[nByte64];
        Utils.fromBitArrayToLongArray(polyLong, Utils.convertIntArrayToBitArray(poly));

        int[] g = new int[n + 1];
        g[0] = 1;
        g[g.length - 1] = 1;

        long[] tmpA = new long[(nByte64 << 1) + 1];
        tmpA[0] = 1;

        int[] r0 = normalForm(g);
        int[] s0 = {0};
        int[] s2;
        int[][] q;

        int[] r1 = new int[n];
        long[] tmp1 = new long[(nByte64 << 1) + 1];
        System.arraycopy(polyLong, 0, tmp1, 0, polyLong.length);
        long[] r1Long = new long[nByte64];
        mod(r1Long, tmp1, n, nByte64);
        Utils.fromLongArrayToBitIntArray(r1, r1Long);

        long[] s1Long = new long[nByte64];
        mod(s1Long, tmpA, n, nByte64);
        int[] s1 = new int[n];
        Utils.fromLongArrayToBitIntArray(s1, s1Long);

        while (computeDegree(r1) != -1)
        {
            q = div(r0, r1);
            r0 = normalForm(r1);
            r1 = normalForm(q[1]);

            long[] tmp = new long[nByte64];
            modMultBits(tmp, q[0], s1, n, nByte64, random);
            int[] tmpBits = new int[n];
            Utils.fromLongArrayToBitIntArray(tmpBits, tmp);
            s2 = add(s0, tmpBits);

            s0 = normalForm(s1);
            s1 = normalForm(s2);
        }
        int hc = headCoefficient(r0);
        s0 = multWithElement(s0, GFCalculator.inverse(hc));
        return Utils.convertIntArrayToBitArray(s0);
    }

    private static int[] normalForm(int[] a)
    {
        int d = computeDegree(a);

        // if a is the zero polynomial
        if (d == -1)
        {
            // return new zero polynomial
            return new int[1];
        }

        // if a already is in normal form
        if (a.length == d + 1)
        {
            // return a clone of a
            return IntUtils.clone(a);
        }

        // else, reduce a
        int[] result = new int[d + 1];
        System.arraycopy(a, 0, result, 0, d + 1);
        return result;
    }

    private static int[][] div(int[] a, int[] f)
    {
        int df = computeDegree(f);
        int da = computeDegree(a) + 1;
        if (df == -1)
        {
            throw new ArithmeticException("Division by zero.");
        }
        int[][] result = new int[2][];
        result[0] = new int[1];
        result[1] = new int[da];
        int hc = headCoefficient(f);
        hc = GFCalculator.inverse(hc);
        result[0][0] = 0;
        System.arraycopy(a, 0, result[1], 0, result[1].length);
        while (df <= computeDegree(result[1]))
        {
            int[] q;
            int[] coeff = new int[1];
            coeff[0] = GFCalculator.mult(headCoefficient(result[1]), hc);
            q = multWithElement(f, coeff[0]);
            int n = computeDegree(result[1]) - df;
            q = multWithMonomial(q, n);
            coeff = multWithMonomial(coeff, n);
            result[0] = add(coeff, result[0]);
            result[1] = add(q, result[1]);
        }
        return result;
    }

    private static int[] multWithMonomial(int[] a, int k)
    {
        int d = computeDegree(a);
        if (d == -1)
        {
            return new int[1];
        }
        int[] result = new int[d + k + 1];
        System.arraycopy(a, 0, result, k, d + 1);
        return result;
    }

    private static int[] multWithElement(int[] a, int element)
    {
        int degree = computeDegree(a);
        if (degree == -1 || element == 0)
        {
            return new int[1];
        }

        if (element == 1)
        {
            return IntUtils.clone(a);
        }

        int[] result = new int[degree + 1];
        for (int i = degree; i >= 0; i--)
        {
            result[i] = a[i] ^ element;
        }

        return result;
    }


    private static int headCoefficient(int[] a)
    {
        int degree = computeDegree(a);
        if (degree == -1)
        {
            return 0;
        }
        return a[degree];
    }

    private static int computeDegree(int[] a)
    {
        int degree;
        for (degree = a.length - 1; degree >= 0 && a[degree] == 0; degree--)
        {
            ;
        }
        return degree;
    }

    private static int[] add(int[] a, int[] b)
    {
        int[] result, addend;
        if (a.length < b.length)
        {
            result = new int[b.length];
            System.arraycopy(b, 0, result, 0, b.length);
            addend = a;
        }
        else
        {
            result = new int[a.length];
            System.arraycopy(a, 0, result, 0, a.length);
            addend = b;
        }

        for (int i = addend.length - 1; i >= 0; i--)
        {
            result[i] = result[i] ^ addend[i];
        }

        return result;
    }

    static void addBytes(byte[] res, byte[] a, byte[] b)
    {
        for (int i = 0; i < a.length; i++)
        {
            res[i] = (byte)(a[i] ^ b[i]);
        }
    }
}