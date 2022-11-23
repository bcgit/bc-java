package org.bouncycastle.pqc.crypto.gemss;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.util.Pack;

class Pointer
{
    protected long[] array;
    protected int cp;

    public Pointer()
    {
        cp = 0;
    }

    public Pointer(int len)
    {
        array = new long[len];
        cp = 0;
    }

    public Pointer(Pointer pointer)
    {
        array = pointer.array;
        cp = pointer.cp;
    }

    public Pointer(Pointer pointer, int shift)
    {
        array = pointer.array;
        cp = pointer.cp + shift;
    }

    public long get(int p)
    {
        return array[cp + p];
    }

    public long get()
    {
        return array[cp];
    }

    public void set(int p, long v)
    {
        array[cp + p] = v;
    }

    public void set(long v)
    {
        array[cp] = v;
    }

    public void setXor(int p, long v)
    {
        array[cp + p] ^= v;
    }

    public void setXor(long v)
    {
        array[cp] ^= v;
    }

    public void setXorRange(Pointer p, int len)
    {
        int outOff = cp;
        int inOff = p.cp;
        for (int i = 0; i < len; ++i)
        {
            array[outOff++] ^= p.array[inOff++];
        }
    }

    public void setXorRange(Pointer p, int inOff, int len)
    {
        int outOff = cp;
        inOff += p.cp;
        for (int i = 0; i < len; ++i)
        {
            array[outOff++] ^= p.array[inOff++];
        }
    }

    public void setXorRange(int outOff, Pointer p, int inOff, int len)
    {
        outOff += cp;
        inOff += p.cp;
        for (int i = 0; i < len; ++i)
        {
            array[outOff++] ^= p.array[inOff++];
        }
    }

    public void setXorRange_SelfMove(Pointer p, int len)
    {
        int inOff = p.cp;
        for (int i = 0; i < len; ++i)
        {
            array[cp++] ^= p.array[inOff++];
        }
    }

    public void setXorMatrix_NoMove(Pointer p, int len1, int len2)
    {
        int outOff = cp;
        int pos, i, j;
        for (i = 0; i < len2; ++i)
        {
            for (j = 0, pos = outOff; j < len1; ++j)
            {
                array[pos++] ^= p.array[p.cp++];
            }
        }
    }

    public void setXorMatrix(Pointer p, int len1, int len2)
    {
        int outOff = cp;
        int pos, i, j;
        for (i = 0; i < len2; ++i)
        {
            for (j = 0, pos = outOff; j < len1; ++j)
            {
                array[pos++] ^= p.array[p.cp++];
            }
        }
        cp += len1;
    }

    public void setXorRangeXor(int outOff, Pointer a, int a_cp, Pointer b, int b_cp, int len)
    {
        outOff += cp;
        a_cp += a.cp;
        b_cp += b.cp;
        for (int i = 0; i < len; ++i)
        {
            array[outOff++] ^= a.array[a_cp++] ^ b.array[b_cp++];
        }
    }

    public void setXorRange(int outOff, PointerUnion p, int inOff, int len)
    {
        outOff += cp;
        inOff += p.cp;
        if (p.remainder == 0)
        {
            for (int i = 0; i < len; ++i)
            {
                array[outOff++] ^= p.array[inOff++];
            }
        }
        else
        {
            int right = p.remainder << 3;
            int left = ((8 - p.remainder) << 3);
            for (int i = 0; i < len; ++i, ++inOff)
            {
                array[outOff++] ^= (p.array[inOff] >>> right) | (p.array[1 + inOff] << left);
            }
        }

    }

    //Assume the input is a Pointer not a PointerUnion
//    public void setXorRangeShift(int outOff, Pointer p, int inOff, int len, int right)
//    {
//
//        outOff += cp;
//        inOff += p.cp;
//        int left = 64 - right;
//        for (int i = 0; i < len; ++i, ++inOff)
//        {
//            array[outOff++] ^= (p.array[inOff] >>> right) ^ (p.array[inOff + 1] << left);
//        }
//    }

    public void setRangeAndMask(int outOff, Pointer p, int inOff, int len, long mask)
    {
        outOff += cp;
        inOff += p.cp;
        for (int i = 0; i < len; ++i)
        {
            array[outOff++] = p.array[inOff++] & mask;
        }
    }

    public void setXorRangeAndMask(int outOff, Pointer p, int inOff, int len, long mask)
    {
        outOff += cp;
        inOff += p.cp;
        for (int i = 0; i < len; ++i)
        {
            array[outOff++] ^= p.array[inOff++] & mask;
        }
    }

    public void setXorRangeAndMaskMove(Pointer p, int len, long mask)
    {
        int outOff = cp;
        for (int i = 0; i < len; ++i)
        {
            array[outOff++] ^= p.array[p.cp++] & mask;
        }
    }

    public void setRangeRotate(int outOff, Pointer p, int inOff, int len, int right)
    {
        int left = 64 - right;
        outOff += cp;
        inOff += p.cp;
        for (int i = 0; i < len; ++i, ++inOff)
        {
            array[outOff++] = (p.array[inOff] >>> left) | (p.array[inOff + 1] << right);
        }
    }

    public void move(int p)
    {
        cp += p;
    }

    public void moveIncremental()
    {
        cp++;
    }

    public long[] getArray()
    {
        return array;
    }

    public int getIndex()
    {
        return cp;
    }

    public void setAnd(int p, long v)
    {
        array[cp + p] &= v;
    }

    public void setAnd(long v)
    {
        array[cp] &= v;
    }

    public void setClear(int p)
    {
        array[cp + p] = 0;
    }

    public void changeIndex(Pointer p)
    {
        array = p.array;
        cp = p.cp;
    }

    public void changeIndex(int p)
    {
        cp = p;
    }

    public void changeIndex(Pointer p, int idx)
    {
        array = p.array;
        cp = p.cp + idx;
    }

    public void setRangeClear(int pos, int size)
    {
        pos += cp;
        Arrays.fill(array, pos, pos + size, 0L);
    }

    public int getLength()
    {
        return array.length - cp;
    }

    public void copyFrom(Pointer src, int len)
    {
        System.arraycopy(src.array, src.cp, array, cp, len);
    }

    public void copyFrom(int shift, Pointer src, int inOff, int len)
    {
        System.arraycopy(src.array, src.cp + inOff, array, cp + shift, len);
    }

    public void set1_gf2n(int startPos, int size)
    {
        array[cp + startPos] = 1;
        for (int i = 1; i < size; ++i)
        {
            array[cp + startPos + i] = 0;
        }
    }

    public byte[] toBytes(int length)
    {
        byte[] res = new byte[length];
        for (int i = 0; i < res.length; ++i)
        {
            res[i] = (byte)(array[cp + (i >>> 3)] >>> ((i & 7) << 3));
        }
        return res;
    }

    public void indexReset()
    {
        cp = 0;
    }

    public void fillRandom(int shift, SecureRandom random, int length)
    {
        byte[] rv = new byte[length];
        random.nextBytes(rv);
        fill(shift, rv, 0, rv.length);
    }

    public void fill(int shift, byte[] arr, int input_cp, int len)
    {
        int i, q;
        for (i = 0, q = cp + shift; q < array.length && i + 8 <= len; ++q)
        {
            array[q] = Pack.littleEndianToLong(arr, input_cp);
            input_cp += 8;
            i += 8;
        }
        if (i < len && q < array.length)
        {
            int r = 0;
            array[q] = 0;
            for (; r < 8 && i < len; ++r, ++input_cp, ++i)
            {
                array[q] |= (arr[input_cp] & 0xFFL) << (r << 3);
            }
        }
    }

    public void setRangeFromXor(int outOff, Pointer a, int aOff, Pointer b, int bOff, int len)
    {
        outOff += cp;
        aOff += a.cp;
        bOff += b.cp;
        for (int i = 0; i < len; ++i)
        {
            array[outOff + i] = a.array[aOff + i] ^ b.array[bOff + i];
        }
    }

    public int is0_gf2n(int p, int size)
    {
        long r = get(p);
        for (int i = 1; i < size; ++i)
        {
            r |= get(p + i);
        }
        return (int)GeMSSUtils.NORBITS_UINT(r);
    }

    public void setOneShiftWithMove(int j, int loop, int move)
    {
        for (; j < loop; ++j)
        {
            /* It is a^(i*NB_BITS_UINT + j) */
            array[cp] = 1L << j;
            cp += move;
        }
    }

    public long getDotProduct(int off, Pointer b, int bOff, int len)
    {
        off += cp;
        bOff += b.cp;
        long res = array[off++] & b.array[bOff++];
        for (int i = 1; i < len; ++i)
        {
            res ^= array[off++] & b.array[bOff++];
        }
        return res;
    }

    public long isNot0_gf2n(int off, int size)
    {
        off += cp;
        long r = array[off];
        for (int i = 1; i < size; ++i)
        {
            r |= array[off++];
        }
        return GeMSSUtils.ORBITS_UINT(r);
    }

    public int setRange_xi(long xi, int k, int len)
    {
        for (int j = 0; j < len; ++j, ++k)
        {
            array[cp + k] = -((xi >>> j) & 1L);
        }
        return k;
    }

    public int searchDegree(int da, int db, int NB_WORD_GFqn)
    {
        while (is0_gf2n(da * NB_WORD_GFqn, NB_WORD_GFqn) != 0 && da >= db)
        {
            --da;
        }
        return da;
    }

    public void mul_gf2x(Pointer A, Pointer B)
    {
        switch (array.length)
        {
        case 6:
            mul192_no_simd_gf2x(array, 0, A.array, A.cp, B.array, B.cp);
            break;
        case 9:
            mul288_no_simd_gf2x(array, 0, A.array, A.cp, B.array, B.cp, new long[4]);
            break;
        case 12:
            mul384_no_simd_gf2x(array, A.array, A.cp, B.array, B.cp, new long[6]);
            break;
        case 13:
            mul416_no_simd_gf2x(array, A.array, A.cp, B.array, B.cp, new long[7]);
            break;
        case 17:
            mul544_no_simd_gf2x(array, A.array, A.cp, B.array, B.cp, new long[5], new long[5], new long[9], new long[4]);
            break;
        }
    }

    private long MUL32_NO_SIMD_GF2X(long a, long b)
    {
        long tmp = (-(b & 1L)) & a;
        tmp ^= ((-((b >>> 1) & 1L)) & a) << 1;
        tmp ^= ((-((b >>> 2) & 1L)) & a) << 2;
        tmp ^= ((-((b >>> 3) & 1L)) & a) << 3;
        tmp ^= ((-((b >>> 4) & 1L)) & a) << 4;
        tmp ^= ((-((b >>> 5) & 1L)) & a) << 5;
        tmp ^= ((-((b >>> 6) & 1L)) & a) << 6;
        tmp ^= ((-((b >>> 7) & 1L)) & a) << 7;
        tmp ^= ((-((b >>> 8) & 1L)) & a) << 8;
        tmp ^= ((-((b >>> 9) & 1L)) & a) << 9;
        tmp ^= ((-((b >>> 10) & 1L)) & a) << 10;
        tmp ^= ((-((b >>> 11) & 1L)) & a) << 11;
        tmp ^= ((-((b >>> 12) & 1L)) & a) << 12;
        tmp ^= ((-((b >>> 13) & 1L)) & a) << 13;
        tmp ^= ((-((b >>> 14) & 1L)) & a) << 14;
        tmp ^= ((-((b >>> 15) & 1L)) & a) << 15;
        tmp ^= ((-((b >>> 16) & 1L)) & a) << 16;
        tmp ^= ((-((b >>> 17) & 1L)) & a) << 17;
        tmp ^= ((-((b >>> 18) & 1L)) & a) << 18;
        tmp ^= ((-((b >>> 19) & 1L)) & a) << 19;
        tmp ^= ((-((b >>> 20) & 1L)) & a) << 20;
        tmp ^= ((-((b >>> 21) & 1L)) & a) << 21;
        tmp ^= ((-((b >>> 22) & 1L)) & a) << 22;
        tmp ^= ((-((b >>> 23) & 1L)) & a) << 23;
        tmp ^= ((-((b >>> 24) & 1L)) & a) << 24;
        tmp ^= ((-((b >>> 25) & 1L)) & a) << 25;
        tmp ^= ((-((b >>> 26) & 1L)) & a) << 26;
        tmp ^= ((-((b >>> 27) & 1L)) & a) << 27;
        tmp ^= ((-((b >>> 28) & 1L)) & a) << 28;
        tmp ^= ((-((b >>> 29) & 1L)) & a) << 29;
        tmp ^= ((-((b >>> 30) & 1L)) & a) << 30;
        tmp ^= ((-((b >>> 31) & 1L)) & a) << 31;
        return tmp;
    }

    private void MUL64_NO_SIMD_GF2X(long[] C, int c_cp, long A, long B)
    {
        long c0, c1, tmp;
        c0 = (-(B & 1L)) & A;
        /* Optimization: the '&1' is removed */
        tmp = ((-(B >>> 63)) & A);
        c0 ^= tmp << 63;
        c1 = tmp >>> 1;
        tmp = ((-((B >>> 1) & 1L)) & A);
        c0 ^= tmp << 1;
        c1 ^= tmp >>> 63;
        tmp = ((-((B >>> 2) & 1L)) & A);
        c0 ^= tmp << 2;
        c1 ^= tmp >>> 62;
        tmp = ((-((B >>> 3) & 1L)) & A);
        c0 ^= tmp << 3;
        c1 ^= tmp >>> 61;
        tmp = ((-((B >>> 4) & 1L)) & A);
        c0 ^= tmp << 4;
        c1 ^= tmp >>> 60;
        tmp = ((-((B >>> 5) & 1L)) & A);
        c0 ^= tmp << 5;
        c1 ^= tmp >>> 59;
        tmp = ((-((B >>> 6) & 1L)) & A);
        c0 ^= tmp << 6;
        c1 ^= tmp >>> 58;
        tmp = ((-((B >>> 7) & 1L)) & A);
        c0 ^= tmp << 7;
        c1 ^= tmp >>> 57;
        tmp = ((-((B >>> 8) & 1L)) & A);
        c0 ^= tmp << 8;
        c1 ^= tmp >>> 56;
        tmp = ((-((B >>> 9) & 1L)) & A);
        c0 ^= tmp << 9;
        c1 ^= tmp >>> 55;
        tmp = ((-((B >>> 10) & 1L)) & A);
        c0 ^= tmp << 10;
        c1 ^= tmp >>> 54;
        tmp = ((-((B >>> 11) & 1L)) & A);
        c0 ^= tmp << 11;
        c1 ^= tmp >>> 53;
        tmp = ((-((B >>> 12) & 1L)) & A);
        c0 ^= tmp << 12;
        c1 ^= tmp >>> 52;
        tmp = ((-((B >>> 13) & 1L)) & A);
        c0 ^= tmp << 13;
        c1 ^= tmp >>> 51;
        tmp = ((-((B >>> 14) & 1L)) & A);
        c0 ^= tmp << 14;
        c1 ^= tmp >>> 50;
        tmp = ((-((B >>> 15) & 1L)) & A);
        c0 ^= tmp << 15;
        c1 ^= tmp >>> 49;
        tmp = ((-((B >>> 16) & 1L)) & A);
        c0 ^= tmp << 16;
        c1 ^= tmp >>> 48;
        tmp = ((-((B >>> 17) & 1L)) & A);
        c0 ^= tmp << 17;
        c1 ^= tmp >>> 47;
        tmp = ((-((B >>> 18) & 1L)) & A);
        c0 ^= tmp << 18;
        c1 ^= tmp >>> 46;
        tmp = ((-((B >>> 19) & 1L)) & A);
        c0 ^= tmp << 19;
        c1 ^= tmp >>> 45;
        tmp = ((-((B >>> 20) & 1L)) & A);
        c0 ^= tmp << 20;
        c1 ^= tmp >>> 44;
        tmp = ((-((B >>> 21) & 1L)) & A);
        c0 ^= tmp << 21;
        c1 ^= tmp >>> 43;
        tmp = ((-((B >>> 22) & 1L)) & A);
        c0 ^= tmp << 22;
        c1 ^= tmp >>> 42;
        tmp = ((-((B >>> 23) & 1L)) & A);
        c0 ^= tmp << 23;
        c1 ^= tmp >>> 41;
        tmp = ((-((B >>> 24) & 1L)) & A);
        c0 ^= tmp << 24;
        c1 ^= tmp >>> 40;
        tmp = ((-((B >>> 25) & 1L)) & A);
        c0 ^= tmp << 25;
        c1 ^= tmp >>> 39;
        tmp = ((-((B >>> 26) & 1L)) & A);
        c0 ^= tmp << 26;
        c1 ^= tmp >>> 38;
        tmp = ((-((B >>> 27) & 1L)) & A);
        c0 ^= tmp << 27;
        c1 ^= tmp >>> 37;
        tmp = ((-((B >>> 28) & 1L)) & A);
        c0 ^= tmp << 28;
        c1 ^= tmp >>> 36;
        tmp = ((-((B >>> 29) & 1L)) & A);
        c0 ^= tmp << 29;
        c1 ^= tmp >>> 35;
        tmp = ((-((B >>> 30) & 1L)) & A);
        c0 ^= tmp << 30;
        c1 ^= tmp >>> 34;
        tmp = ((-((B >>> 31) & 1L)) & A);
        c0 ^= tmp << 31;
        c1 ^= tmp >>> 33;
        tmp = ((-((B >>> 32) & 1L)) & A);
        c0 ^= tmp << 32;
        c1 ^= tmp >>> 32;
        tmp = ((-((B >>> 33) & 1L)) & A);
        c0 ^= tmp << 33;
        c1 ^= tmp >>> 31;
        tmp = ((-((B >>> 34) & 1L)) & A);
        c0 ^= tmp << 34;
        c1 ^= tmp >>> 30;
        tmp = ((-((B >>> 35) & 1L)) & A);
        c0 ^= tmp << 35;
        c1 ^= tmp >>> 29;
        tmp = ((-((B >>> 36) & 1L)) & A);
        c0 ^= tmp << 36;
        c1 ^= tmp >>> 28;
        tmp = ((-((B >>> 37) & 1L)) & A);
        c0 ^= tmp << 37;
        c1 ^= tmp >>> 27;
        tmp = ((-((B >>> 38) & 1L)) & A);
        c0 ^= tmp << 38;
        c1 ^= tmp >>> 26;
        tmp = ((-((B >>> 39) & 1L)) & A);
        c0 ^= tmp << 39;
        c1 ^= tmp >>> 25;
        tmp = ((-((B >>> 40) & 1L)) & A);
        c0 ^= tmp << 40;
        c1 ^= tmp >>> 24;
        tmp = ((-((B >>> 41) & 1L)) & A);
        c0 ^= tmp << 41;
        c1 ^= tmp >>> 23;
        tmp = ((-((B >>> 42) & 1L)) & A);
        c0 ^= tmp << 42;
        c1 ^= tmp >>> 22;
        tmp = ((-((B >>> 43) & 1L)) & A);
        c0 ^= tmp << 43;
        c1 ^= tmp >>> 21;
        tmp = ((-((B >>> 44) & 1L)) & A);
        c0 ^= tmp << 44;
        c1 ^= tmp >>> 20;
        tmp = ((-((B >>> 45) & 1L)) & A);
        c0 ^= tmp << 45;
        c1 ^= tmp >>> 19;
        tmp = ((-((B >>> 46) & 1L)) & A);
        c0 ^= tmp << 46;
        c1 ^= tmp >>> 18;
        tmp = ((-((B >>> 47) & 1L)) & A);
        c0 ^= tmp << 47;
        c1 ^= tmp >>> 17;
        tmp = ((-((B >>> 48) & 1L)) & A);
        c0 ^= tmp << 48;
        c1 ^= tmp >>> 16;
        tmp = ((-((B >>> 49) & 1L)) & A);
        c0 ^= tmp << 49;
        c1 ^= tmp >>> 15;
        tmp = ((-((B >>> 50) & 1L)) & A);
        c0 ^= tmp << 50;
        c1 ^= tmp >>> 14;
        tmp = ((-((B >>> 51) & 1L)) & A);
        c0 ^= tmp << 51;
        c1 ^= tmp >>> 13;
        tmp = ((-((B >>> 52) & 1L)) & A);
        c0 ^= tmp << 52;
        c1 ^= tmp >>> 12;
        tmp = ((-((B >>> 53) & 1L)) & A);
        c0 ^= tmp << 53;
        c1 ^= tmp >>> 11;
        tmp = ((-((B >>> 54) & 1L)) & A);
        c0 ^= tmp << 54;
        c1 ^= tmp >>> 10;
        tmp = ((-((B >>> 55) & 1L)) & A);
        c0 ^= tmp << 55;
        c1 ^= tmp >>> 9;
        tmp = ((-((B >>> 56) & 1L)) & A);
        c0 ^= tmp << 56;
        c1 ^= tmp >>> 8;
        tmp = ((-((B >>> 57) & 1L)) & A);
        c0 ^= tmp << 57;
        c1 ^= tmp >>> 7;
        tmp = ((-((B >>> 58) & 1L)) & A);
        c0 ^= tmp << 58;
        c1 ^= tmp >>> 6;
        tmp = ((-((B >>> 59) & 1L)) & A);
        c0 ^= tmp << 59;
        c1 ^= tmp >>> 5;
        tmp = ((-((B >>> 60) & 1L)) & A);
        c0 ^= tmp << 60;
        c1 ^= tmp >>> 4;
        tmp = ((-((B >>> 61) & 1L)) & A);
        c0 ^= tmp << 61;
        c1 ^= tmp >>> 3;
        tmp = ((-((B >>> 62) & 1L)) & A);
        C[c_cp] = c0 ^ (tmp << 62);
        C[c_cp + 1] = c1 ^ (tmp >>> 2);
    }

    private void MUL64_NO_SIMD_GF2X_XOR(long[] C, int c_cp, long A, long B)
    {
        long c0, c1, tmp;
        c0 = (-(B & 1L)) & A;
        /* Optimization: the '&1' is removed */
        tmp = ((-(B >>> 63)) & A);
        c0 ^= tmp << 63;
        c1 = tmp >>> 1;
        tmp = ((-((B >>> 1) & 1L)) & A);
        c0 ^= tmp << 1;
        c1 ^= tmp >>> 63;
        tmp = ((-((B >>> 2) & 1L)) & A);
        c0 ^= tmp << 2;
        c1 ^= tmp >>> 62;
        tmp = ((-((B >>> 3) & 1L)) & A);
        c0 ^= tmp << 3;
        c1 ^= tmp >>> 61;
        tmp = ((-((B >>> 4) & 1L)) & A);
        c0 ^= tmp << 4;
        c1 ^= tmp >>> 60;
        tmp = ((-((B >>> 5) & 1L)) & A);
        c0 ^= tmp << 5;
        c1 ^= tmp >>> 59;
        tmp = ((-((B >>> 6) & 1L)) & A);
        c0 ^= tmp << 6;
        c1 ^= tmp >>> 58;
        tmp = ((-((B >>> 7) & 1L)) & A);
        c0 ^= tmp << 7;
        c1 ^= tmp >>> 57;
        tmp = ((-((B >>> 8) & 1L)) & A);
        c0 ^= tmp << 8;
        c1 ^= tmp >>> 56;
        tmp = ((-((B >>> 9) & 1L)) & A);
        c0 ^= tmp << 9;
        c1 ^= tmp >>> 55;
        tmp = ((-((B >>> 10) & 1L)) & A);
        c0 ^= tmp << 10;
        c1 ^= tmp >>> 54;
        tmp = ((-((B >>> 11) & 1L)) & A);
        c0 ^= tmp << 11;
        c1 ^= tmp >>> 53;
        tmp = ((-((B >>> 12) & 1L)) & A);
        c0 ^= tmp << 12;
        c1 ^= tmp >>> 52;
        tmp = ((-((B >>> 13) & 1L)) & A);
        c0 ^= tmp << 13;
        c1 ^= tmp >>> 51;
        tmp = ((-((B >>> 14) & 1L)) & A);
        c0 ^= tmp << 14;
        c1 ^= tmp >>> 50;
        tmp = ((-((B >>> 15) & 1L)) & A);
        c0 ^= tmp << 15;
        c1 ^= tmp >>> 49;
        tmp = ((-((B >>> 16) & 1L)) & A);
        c0 ^= tmp << 16;
        c1 ^= tmp >>> 48;
        tmp = ((-((B >>> 17) & 1L)) & A);
        c0 ^= tmp << 17;
        c1 ^= tmp >>> 47;
        tmp = ((-((B >>> 18) & 1L)) & A);
        c0 ^= tmp << 18;
        c1 ^= tmp >>> 46;
        tmp = ((-((B >>> 19) & 1L)) & A);
        c0 ^= tmp << 19;
        c1 ^= tmp >>> 45;
        tmp = ((-((B >>> 20) & 1L)) & A);
        c0 ^= tmp << 20;
        c1 ^= tmp >>> 44;
        tmp = ((-((B >>> 21) & 1L)) & A);
        c0 ^= tmp << 21;
        c1 ^= tmp >>> 43;
        tmp = ((-((B >>> 22) & 1L)) & A);
        c0 ^= tmp << 22;
        c1 ^= tmp >>> 42;
        tmp = ((-((B >>> 23) & 1L)) & A);
        c0 ^= tmp << 23;
        c1 ^= tmp >>> 41;
        tmp = ((-((B >>> 24) & 1L)) & A);
        c0 ^= tmp << 24;
        c1 ^= tmp >>> 40;
        tmp = ((-((B >>> 25) & 1L)) & A);
        c0 ^= tmp << 25;
        c1 ^= tmp >>> 39;
        tmp = ((-((B >>> 26) & 1L)) & A);
        c0 ^= tmp << 26;
        c1 ^= tmp >>> 38;
        tmp = ((-((B >>> 27) & 1L)) & A);
        c0 ^= tmp << 27;
        c1 ^= tmp >>> 37;
        tmp = ((-((B >>> 28) & 1L)) & A);
        c0 ^= tmp << 28;
        c1 ^= tmp >>> 36;
        tmp = ((-((B >>> 29) & 1L)) & A);
        c0 ^= tmp << 29;
        c1 ^= tmp >>> 35;
        tmp = ((-((B >>> 30) & 1L)) & A);
        c0 ^= tmp << 30;
        c1 ^= tmp >>> 34;
        tmp = ((-((B >>> 31) & 1L)) & A);
        c0 ^= tmp << 31;
        c1 ^= tmp >>> 33;
        tmp = ((-((B >>> 32) & 1L)) & A);
        c0 ^= tmp << 32;
        c1 ^= tmp >>> 32;
        tmp = ((-((B >>> 33) & 1L)) & A);
        c0 ^= tmp << 33;
        c1 ^= tmp >>> 31;
        tmp = ((-((B >>> 34) & 1L)) & A);
        c0 ^= tmp << 34;
        c1 ^= tmp >>> 30;
        tmp = ((-((B >>> 35) & 1L)) & A);
        c0 ^= tmp << 35;
        c1 ^= tmp >>> 29;
        tmp = ((-((B >>> 36) & 1L)) & A);
        c0 ^= tmp << 36;
        c1 ^= tmp >>> 28;
        tmp = ((-((B >>> 37) & 1L)) & A);
        c0 ^= tmp << 37;
        c1 ^= tmp >>> 27;
        tmp = ((-((B >>> 38) & 1L)) & A);
        c0 ^= tmp << 38;
        c1 ^= tmp >>> 26;
        tmp = ((-((B >>> 39) & 1L)) & A);
        c0 ^= tmp << 39;
        c1 ^= tmp >>> 25;
        tmp = ((-((B >>> 40) & 1L)) & A);
        c0 ^= tmp << 40;
        c1 ^= tmp >>> 24;
        tmp = ((-((B >>> 41) & 1L)) & A);
        c0 ^= tmp << 41;
        c1 ^= tmp >>> 23;
        tmp = ((-((B >>> 42) & 1L)) & A);
        c0 ^= tmp << 42;
        c1 ^= tmp >>> 22;
        tmp = ((-((B >>> 43) & 1L)) & A);
        c0 ^= tmp << 43;
        c1 ^= tmp >>> 21;
        tmp = ((-((B >>> 44) & 1L)) & A);
        c0 ^= tmp << 44;
        c1 ^= tmp >>> 20;
        tmp = ((-((B >>> 45) & 1L)) & A);
        c0 ^= tmp << 45;
        c1 ^= tmp >>> 19;
        tmp = ((-((B >>> 46) & 1L)) & A);
        c0 ^= tmp << 46;
        c1 ^= tmp >>> 18;
        tmp = ((-((B >>> 47) & 1L)) & A);
        c0 ^= tmp << 47;
        c1 ^= tmp >>> 17;
        tmp = ((-((B >>> 48) & 1L)) & A);
        c0 ^= tmp << 48;
        c1 ^= tmp >>> 16;
        tmp = ((-((B >>> 49) & 1L)) & A);
        c0 ^= tmp << 49;
        c1 ^= tmp >>> 15;
        tmp = ((-((B >>> 50) & 1L)) & A);
        c0 ^= tmp << 50;
        c1 ^= tmp >>> 14;
        tmp = ((-((B >>> 51) & 1L)) & A);
        c0 ^= tmp << 51;
        c1 ^= tmp >>> 13;
        tmp = ((-((B >>> 52) & 1L)) & A);
        c0 ^= tmp << 52;
        c1 ^= tmp >>> 12;
        tmp = ((-((B >>> 53) & 1L)) & A);
        c0 ^= tmp << 53;
        c1 ^= tmp >>> 11;
        tmp = ((-((B >>> 54) & 1L)) & A);
        c0 ^= tmp << 54;
        c1 ^= tmp >>> 10;
        tmp = ((-((B >>> 55) & 1L)) & A);
        c0 ^= tmp << 55;
        c1 ^= tmp >>> 9;
        tmp = ((-((B >>> 56) & 1L)) & A);
        c0 ^= tmp << 56;
        c1 ^= tmp >>> 8;
        tmp = ((-((B >>> 57) & 1L)) & A);
        c0 ^= tmp << 57;
        c1 ^= tmp >>> 7;
        tmp = ((-((B >>> 58) & 1L)) & A);
        c0 ^= tmp << 58;
        c1 ^= tmp >>> 6;
        tmp = ((-((B >>> 59) & 1L)) & A);
        c0 ^= tmp << 59;
        c1 ^= tmp >>> 5;
        tmp = ((-((B >>> 60) & 1L)) & A);
        c0 ^= tmp << 60;
        c1 ^= tmp >>> 4;
        tmp = ((-((B >>> 61) & 1L)) & A);
        c0 ^= tmp << 61;
        c1 ^= tmp >>> 3;
        tmp = ((-((B >>> 62) & 1L)) & A);
        C[c_cp] ^= c0 ^ (tmp << 62);
        C[c_cp + 1] ^= c1 ^ (tmp >>> 2);
    }

    private void mul128_no_simd_gf2x(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp)
    {
        MUL64_NO_SIMD_GF2X(C, c_cp, A[a_cp], B[b_cp]);//x0, x1
        MUL64_NO_SIMD_GF2X(C, c_cp + 2, A[a_cp + 1], B[b_cp + 1]);//x2, x3
        C[c_cp + 2] ^= C[c_cp + 1];//c2=x1+x2
        C[c_cp + 1] = C[c_cp] ^ C[c_cp + 2];//c1=x0+x1+x2
        C[c_cp + 2] ^= C[c_cp + 3];//c2=x1+x2+x3
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 1, A[a_cp] ^ A[a_cp + 1], B[b_cp] ^ B[b_cp + 1]);//x4, x5
    }

    private void mul128_no_simd_gf2x(long[] C, int c_cp, long a0, long a1, long b0, long b1)
    {
        MUL64_NO_SIMD_GF2X(C, c_cp, a0, b0);//x0, x1
        MUL64_NO_SIMD_GF2X(C, c_cp + 2, a1, b1);//x2, x3
        C[c_cp + 2] ^= C[c_cp + 1];//c2=x1+x2
        C[c_cp + 1] = C[c_cp] ^ C[c_cp + 2];//c1=x0+x1+x2
        C[c_cp + 2] ^= C[c_cp + 3];//c2=x1+x2+x3
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 1, a0 ^ a1, b0 ^ b1);//x4, x5
    }

    private void mul128_no_simd_gf2x_xor(long[] C, int c_cp, long a0, long a1, long b0, long b1, long[] RESERVED_BUF, int buf_cp)
    {
        MUL64_NO_SIMD_GF2X(RESERVED_BUF, buf_cp, a0, b0);//x0, x1
        //c0=x0, c1=x1
        MUL64_NO_SIMD_GF2X(RESERVED_BUF, buf_cp + 2, a1, b1);//x2, x3
        //c2=x2, c3=x3
        C[c_cp] ^= RESERVED_BUF[buf_cp];
        RESERVED_BUF[buf_cp + 2] ^= RESERVED_BUF[buf_cp + 1];
        C[c_cp + 1] ^= RESERVED_BUF[buf_cp] ^ RESERVED_BUF[buf_cp + 2];
        C[c_cp + 2] ^= RESERVED_BUF[buf_cp + 2] ^ RESERVED_BUF[buf_cp + 3];
        C[c_cp + 3] ^= RESERVED_BUF[buf_cp + 3];
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 1, a0 ^ a1, b0 ^ b1);//x4, x5
    }

    public void mul192_no_simd_gf2x(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp)// long[] RESERVED_BUF2, int buf_cp)
    {
        /* A0*B0 */
        MUL64_NO_SIMD_GF2X(C, c_cp, A[a_cp], B[b_cp]);//x0, x1
        /* A2*B2 */
        MUL64_NO_SIMD_GF2X(C, c_cp + 4, A[a_cp + 2], B[b_cp + 2]);//x4,x5
        /* A1*B1 */
        MUL64_NO_SIMD_GF2X(C, c_cp + 2, A[a_cp + 1], B[b_cp + 1]);//x2, x3
        C[c_cp + 1] ^= C[c_cp + 2];//C1=x1^x2
        C[c_cp + 3] ^= C[c_cp + 4];//c3=x3^x4
        C[c_cp + 4] = C[c_cp + 3] ^ C[c_cp + 5];//c4=x3+x4+x5
        C[c_cp + 2] = C[c_cp + 3] ^ C[c_cp + 1] ^ C[c_cp];//c2=x1+x2+x3+x4
        C[c_cp + 3] = C[c_cp + 1] ^ C[c_cp + 4];//c3=x1+x2+x4+x5
        C[c_cp + 1] ^= C[c_cp];
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 1, A[a_cp] ^ A[a_cp + 1], B[b_cp] ^ B[b_cp + 1]);//x6, x7
        /* (A1+A2)*(B1+B2)  */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 3, A[a_cp + 1] ^ A[a_cp + 2], B[b_cp + 1] ^ B[b_cp + 2]);//x10, x11
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 2, A[a_cp] ^ A[a_cp + 2], B[b_cp] ^ B[b_cp + 2]);//x8, x9
    }

    private void mul288_no_simd_gf2x(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp, long[] RESERVED_BUF)//long[] AA, long[] BB,
    {
        mul128_no_simd_gf2x(C, c_cp, A, a_cp, B, b_cp);
        MUL64_NO_SIMD_GF2X(C, c_cp + 4, A[a_cp + 2], B[b_cp + 2]); //x0,x1
        MUL64_NO_SIMD_GF2X(C, c_cp + 7, A[a_cp + 3], B[b_cp + 3]);//x2,x3
        C[c_cp + 7] ^= C[c_cp + 5];//x1+x2
        C[c_cp + 8] ^= MUL32_NO_SIMD_GF2X(A[a_cp + 4], B[b_cp + 4]);//x3+x4
        C[c_cp + 5] = C[c_cp + 7] ^ C[c_cp + 4];//x0+x1+x2
        C[c_cp + 7] ^= C[c_cp + 8];//x1+x2+x3+x4
        C[c_cp + 6] = C[c_cp + 7] ^ C[c_cp + 4];//x0+x1+x2+x3+x4
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 5, A[a_cp + 2] ^ A[a_cp + 3], B[b_cp + 2] ^ B[b_cp + 3]);//x4, x5
        /* (A1+A2)*(B1+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 7, A[a_cp + 3] ^ A[a_cp + 4], B[b_cp + 3] ^ B[b_cp + 4]);//x6, x7
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 6, A[a_cp + 2] ^ A[a_cp + 4], B[b_cp + 2] ^ B[b_cp + 4]);//x2,x3
        //end of 160
        C[c_cp + 4] ^= C[c_cp + 2];
        C[c_cp + 5] ^= C[c_cp + 3];
        long AA0 = A[a_cp] ^ A[a_cp + 2];
        long AA1 = A[a_cp + 1] ^ A[a_cp + 3];
        long BB0 = B[b_cp] ^ B[b_cp + 2];
        long BB1 = B[b_cp + 1] ^ B[b_cp + 3];
        MUL64_NO_SIMD_GF2X(RESERVED_BUF, 0, AA0, BB0); //x0,x1
        MUL64_NO_SIMD_GF2X(RESERVED_BUF, 2, AA1, BB1);//x2,x3
        RESERVED_BUF[2] ^= RESERVED_BUF[1];//x1+x2
        RESERVED_BUF[3] ^= MUL32_NO_SIMD_GF2X(A[a_cp + 4], B[b_cp + 4]);//x3+x4
        C[c_cp + 2] = C[c_cp + 4] ^ C[c_cp] ^ RESERVED_BUF[0];
        C[c_cp + 3] = C[c_cp + 5] ^ C[c_cp + 1] ^ RESERVED_BUF[2] ^ RESERVED_BUF[0];//x0+x1+x2
        RESERVED_BUF[2] ^= RESERVED_BUF[3];//x1+x2+x3+x4
        C[c_cp + 4] ^= C[c_cp + 6] ^ RESERVED_BUF[2] ^ RESERVED_BUF[0];//x0+x1+x2+x3+x4
        C[c_cp + 5] ^= C[c_cp + 7] ^ RESERVED_BUF[2];
        C[c_cp + 6] ^= C[c_cp + 8] ^ RESERVED_BUF[3];
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 3, AA0 ^ AA1, BB0 ^ BB1);//x4, x5
        /* (A1+A2)*(B1+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 5, AA1 ^ A[a_cp + 4], BB1 ^ B[b_cp + 4]);//x6, x7
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 4, AA0 ^ A[a_cp + 4], BB0 ^ B[b_cp + 4]);//x2,x3
    }

    private void mul384_no_simd_gf2x(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] RESERVED_BUF6)
    {
        mul192_no_simd_gf2x(C, 0, A, a_cp, B, b_cp);
        mul192_no_simd_gf2x(C, 6, A, a_cp + 3, B, b_cp + 3);
        long AA0 = A[a_cp] ^ A[a_cp + 3];
        long AA1 = A[a_cp + 1] ^ A[a_cp + 4];
        long AA2 = A[a_cp + 2] ^ A[a_cp + 5];
        long BB0 = B[b_cp] ^ B[b_cp + 3];
        long BB1 = B[b_cp + 1] ^ B[b_cp + 4];
        long BB2 = B[b_cp + 2] ^ B[b_cp + 5];
        C[6] ^= C[3];
        C[7] ^= C[4];
        C[8] ^= C[5];
        MUL64_NO_SIMD_GF2X(RESERVED_BUF6, 0, AA0, BB0);//x0, x1
        /* A2*B2 */
        MUL64_NO_SIMD_GF2X(RESERVED_BUF6, 4, AA2, BB2);//x4,x5
        /* A1*B1 */
        MUL64_NO_SIMD_GF2X(RESERVED_BUF6, 2, AA1, BB1);//x2, x3
        C[3] = C[6] ^ C[0] ^ RESERVED_BUF6[0];
        RESERVED_BUF6[1] ^= RESERVED_BUF6[2];//C1=x1^x2
        RESERVED_BUF6[3] ^= RESERVED_BUF6[4];//c3=x3^x4
        RESERVED_BUF6[4] = RESERVED_BUF6[3] ^ RESERVED_BUF6[5];//c4=x3+x4+x5
        C[5] = C[8] ^ C[2] ^ RESERVED_BUF6[3] ^ RESERVED_BUF6[1] ^ RESERVED_BUF6[0];//c2=x1+x2+x3+x4
        C[6] ^= C[9] ^ RESERVED_BUF6[1] ^ RESERVED_BUF6[4];//c3=x1+x2+x4+x5
        C[4] = C[7] ^ C[1] ^ RESERVED_BUF6[1] ^ RESERVED_BUF6[0];
        C[7] ^= C[10] ^ RESERVED_BUF6[4];
        C[8] ^= C[11] ^ RESERVED_BUF6[5];
        MUL64_NO_SIMD_GF2X_XOR(C, 4, AA0 ^ AA1, BB0 ^ BB1);//x6, x7
        /* (A1+A2)*(B1+B2)  */
        MUL64_NO_SIMD_GF2X_XOR(C, 6, AA1 ^ AA2, BB1 ^ BB2);//x10, x11
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, 5, AA0 ^ AA2, BB0 ^ BB2);//x8, x9
    }

    private void mul416_no_simd_gf2x(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] RESERVED_BUF)
    {
        mul192_no_simd_gf2x(C, 0, A, a_cp, B, b_cp);
        mul128_no_simd_gf2x(C, 6, A, a_cp + 3, B, b_cp + 3);
        MUL64_NO_SIMD_GF2X(C, 10, A[a_cp + 5], B[b_cp + 5]);
        C[12] = MUL32_NO_SIMD_GF2X(A[a_cp + 6], B[b_cp + 6]) ^ C[11];
        C[11] = C[10] ^ C[12];
        MUL64_NO_SIMD_GF2X_XOR(C, 11, A[a_cp + 5] ^ A[a_cp + 6], B[b_cp + 5] ^ B[b_cp + 6]);
        C[8] ^= C[10];
        C[9] ^= C[11];
        C[10] = C[8];
        C[11] = C[9];
        C[8] ^= C[6];
        C[9] ^= C[7];
        C[10] ^= C[12];
        mul128_no_simd_gf2x_xor(C, 8, A[a_cp + 3] ^ A[a_cp + 5], A[a_cp + 4] ^ A[a_cp + 6],
            B[b_cp + 3] ^ B[b_cp + 5], B[b_cp + 4] ^ B[b_cp + 6], RESERVED_BUF, 0);
        long AA0 = A[a_cp] ^ A[a_cp + 3];
        long AA1 = A[a_cp + 1] ^ A[a_cp + 4];
        long AA2 = A[a_cp + 2] ^ A[a_cp + 5];
        long AA3 = A[a_cp + 6];
        long BB0 = B[b_cp] ^ B[b_cp + 3];
        long BB1 = B[b_cp + 1] ^ B[b_cp + 4];
        long BB2 = B[b_cp + 2] ^ B[b_cp + 5];
        long BB3 = B[b_cp + 6];
        C[6] ^= C[3];
        C[7] ^= C[4];
        C[8] ^= C[5];
        mul128_no_simd_gf2x(RESERVED_BUF, 0, AA0, AA1, BB0, BB1);
        MUL64_NO_SIMD_GF2X(RESERVED_BUF, 4, AA2, BB2);
        RESERVED_BUF[6] = MUL32_NO_SIMD_GF2X(AA3, BB3) ^ RESERVED_BUF[5];
        RESERVED_BUF[5] = RESERVED_BUF[4] ^ RESERVED_BUF[6];
        MUL64_NO_SIMD_GF2X_XOR(RESERVED_BUF, 5, AA2 ^ AA3, BB2 ^ BB3);
        C[3] = C[6] ^ C[0] ^ RESERVED_BUF[0];
        C[4] = C[7] ^ C[1] ^ RESERVED_BUF[1];
        RESERVED_BUF[2] ^= RESERVED_BUF[4];
        RESERVED_BUF[3] ^= RESERVED_BUF[5];
        C[5] = C[8] ^ C[2] ^ RESERVED_BUF[2] ^ RESERVED_BUF[0];
        C[6] ^= C[9] ^ RESERVED_BUF[3] ^ RESERVED_BUF[1];
        C[7] ^= C[10] ^ RESERVED_BUF[2] ^ RESERVED_BUF[6];
        C[8] ^= C[11] ^ RESERVED_BUF[3];
        C[9] ^= C[12] ^ RESERVED_BUF[6];
        mul128_no_simd_gf2x_xor(C, 5, AA0 ^ AA2, AA1 ^ AA3,
            BB0 ^ BB2, BB1 ^ BB3, RESERVED_BUF, 0);
    }

    private void mul544_no_simd_gf2x(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] AA, long[] BB,
                                     long[] RESERVED_BUF9, long[] RESERVED_BUF6)
    {
        mul128_no_simd_gf2x(C, 0, A, a_cp, B, b_cp);
        mul128_no_simd_gf2x(C, 4, A, a_cp + 2, B, b_cp + 2);
        AA[0] = A[a_cp] ^ A[a_cp + 2];
        AA[1] = A[a_cp + 1] ^ A[a_cp + 3];
        BB[0] = B[b_cp] ^ B[b_cp + 2];
        BB[1] = B[b_cp + 1] ^ B[b_cp + 3];
        mul128_no_simd_gf2x(RESERVED_BUF9, 0, AA, 0, BB, 0);
        AA[0] = A[a_cp] ^ A[a_cp + 4];
        AA[1] = A[a_cp + 1] ^ A[a_cp + 5];
        AA[2] = A[a_cp + 2] ^ A[a_cp + 6];
        AA[3] = A[a_cp + 3] ^ A[a_cp + 7];
        AA[4] = A[a_cp + 8];
        BB[0] = B[b_cp] ^ B[b_cp + 4];
        BB[1] = B[b_cp + 1] ^ B[b_cp + 5];
        BB[2] = B[b_cp + 2] ^ B[b_cp + 6];
        BB[3] = B[b_cp + 3] ^ B[b_cp + 7];
        BB[4] = B[b_cp + 8];
        C[4] ^= C[2];
        C[5] ^= C[3];
        C[2] = C[4] ^ C[0] ^ RESERVED_BUF9[0];
        C[3] = C[5] ^ C[1] ^ RESERVED_BUF9[1];
        C[4] ^= C[6] ^ RESERVED_BUF9[2];
        C[5] ^= C[7] ^ RESERVED_BUF9[3];
        mul288_no_simd_gf2x(C, 8, A, a_cp + 4, B, b_cp + 4, RESERVED_BUF6);//AA3, BB3,
        mul288_no_simd_gf2x(RESERVED_BUF9, 0, AA, 0, BB, 0, RESERVED_BUF6);//AA3, BB3,
        C[8] ^= C[4];
        C[9] ^= C[5];
        C[10] ^= C[6];
        C[11] ^= C[7];
        C[4] = C[8] ^ C[0] ^ RESERVED_BUF9[0];
        C[5] = C[9] ^ C[1] ^ RESERVED_BUF9[1];
        C[6] = C[10] ^ C[2] ^ RESERVED_BUF9[2];
        C[7] = C[11] ^ C[3] ^ RESERVED_BUF9[3];
        C[8] ^= C[12] ^ RESERVED_BUF9[4];
        C[9] ^= C[13] ^ RESERVED_BUF9[5];
        C[10] ^= C[14] ^ RESERVED_BUF9[6];
        C[11] ^= C[15] ^ RESERVED_BUF9[7];
        C[12] ^= C[16] ^ RESERVED_BUF9[8];
    }
}
