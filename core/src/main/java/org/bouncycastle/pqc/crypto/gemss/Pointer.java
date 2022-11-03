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

    public void setXorRange(int outOff, Pointer p, int inOff, int len)
    {
        outOff += cp;
        inOff += p.cp;
        for (int i = 0; i < len; ++i)
        {
            array[outOff++] ^= p.array[inOff++];
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
    public void setXorRangeShift(int outOff, Pointer p, int inOff, int len, int right)
    {

        outOff += cp;
        inOff += p.cp;
        int left = 64 - right;
        for (int i = 0; i < len; ++i, ++inOff)
        {
            array[outOff++] ^= (p.array[inOff] >>> right) ^ (p.array[inOff + 1] << left);
        }
    }

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

    public void setXorRangeAndMaskRotate(int outOff, Pointer p, int inOff, int len, long mask, int j)
    {
        int jc = 64 - j;
        outOff += cp;
        inOff += p.cp;
        long A_mask1 = p.array[inOff++] & mask, A_mask2;
        array[outOff++] ^= A_mask1 << j;
        for (int i = 1; i < len; ++i)
        {
            A_mask2 = p.array[inOff++] & mask;
            array[outOff++] ^= (A_mask1 >>> jc) | (A_mask2 << j);
            A_mask1 = A_mask2;
        }
    }

    public void setXorRangeAndMaskRotateOverflow(int outOff, Pointer p, int inOff, int len, long mask, int j)
    {
        int jc = 64 - j;
        inOff += p.cp;
        long A_mask1 = p.array[inOff++] & mask, A_mask2;
        outOff += cp;
        array[outOff++] ^= A_mask1 << j;
        for (int i = 1; i < len; ++i)
        {
            A_mask2 = p.array[inOff++] & mask;
            array[outOff++] ^= (A_mask1 >>> jc) | (A_mask2 << j);
            A_mask1 = A_mask2;
        }
        array[outOff] ^= A_mask1 >>> jc;
    }

    public void move(int p)
    {
        cp += p;
    }

    public void moveIncremental()
    {
        cp++;
    }

//    public void moveDecremental()
//    {
//        cp--;
//    }

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

    public void reset()
    {
        cp = 0;
        Arrays.fill(array, 0L);
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
        if (i < len)
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
        long r;
        int i;
        r = get(p);
        for (i = 1; i < size; ++i)
        {
            r |= get(p + i);
        }

        for (i = 64; i > 0; i >>>= 1)
        {
            r |= r >>> i;
        }
        r = ~r;
        r &= 1;
        return (int)r;
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

    /**
     * @brief Squaring in GF(2)[x].
     * @details For each 32-bit block on the input, we use the following strategy:
     * Assume we want to insert a null bit between each bit of 0x00000000FFFFFFFF.
     * We do as following:
     * 0x00000000FFFFFFFF (it is already an insertion of a zero 32-bit packed)
     * 0x0000FFFF0000FFFF (insertion by pack of 16 bits)
     * 0x00FF00FF00FF00FF (insertion by pack of 8 bits)
     * 0x0F0F0F0F0F0F0F0F (insertion by pack of 4 bits)
     * 0x3333333333333333 (insertion by pack of 2 bits)
     * 0x5555555555555555 (insertion by pack of 1 bit).
     * @param[in] A   An element of GF(2^n).
     * @param[out] C   C=A*A in GF(2)[x] (the result is not reduced).
     * @remark Constant-time implementation.
     */
    public void sqr_nocst_gf2x(Pointer A, int NB_WORD_GFqn, int NB_WORD_MUL)
    {
        long Ci;
        int i = NB_WORD_GFqn - 1;
        int pos = cp + NB_WORD_MUL - 1;
        //int Aoff = A.cp + i;
        if ((NB_WORD_MUL & 1) != 0)
        {
            /* Lower 32 bits of A[i] */
            Ci = A.get(i);//A.array[Aoff];//
            Ci = (Ci ^ (Ci << 16)) & 0x0000FFFF0000FFFFL;
            Ci = square_gf2(Ci);
            array[pos--] = Ci;
            i = NB_WORD_GFqn - 2;
        }
        for (; i != -1; --i)
        {
            /* Higher 32 bits of A[i] */
            Ci = A.get(i) >>> 32;//A.array[Aoff] >>> 32;
            Ci = (Ci ^ (Ci << 16)) & (0x0000FFFF0000FFFFL);
            Ci = square_gf2(Ci);
            array[pos--] = Ci;
            /* Lower 32 bits of A[i] */
            Ci = A.get(i);//A.array[Aoff--];
            Ci = ((Ci & 0xFFFFFFFFL) ^ (Ci << 16)) & (0x0000FFFF0000FFFFL);
            Ci = square_gf2(Ci);
            array[pos--] = Ci;
        }
    }

    private long square_gf2(long Ci)
    {
        Ci = (Ci ^ (Ci << 8)) & (0x00FF00FF00FF00FFL);
        Ci = (Ci ^ (Ci << 4)) & (0x0F0F0F0F0F0F0F0FL);
        Ci = (Ci ^ (Ci << 2)) & (0x3333333333333333L);
        Ci = (Ci ^ (Ci << 1)) & (0x5555555555555555L);
        return Ci;
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

    public void mul_gf2x(Pointer A, Pointer B, int HFEnq, int NB_WORD_GFqn, int HFEnr)
    {
        switch (array.length)
        {
        case 6:
            mul192_no_simd_gf2x(array, 0, A.array, A.cp, B.array, B.cp, new long[2], 0);
            return;
        case 9:
            mul288_no_simd_gf2x(array, 0, A.array, A.cp, B.array, B.cp, new long[3], new long[3], new long[7]);
            return;
        case 12:
            mul384_no_simd_gf2x(array, A.array, A.cp, B.array, B.cp, new long[3], new long[3], new long[8]);
            return;
        case 13:
            mul416_no_simd_gf2x(array, A.array, A.cp, B.array, B.cp, new long[4], new long[4], new long[13],
                new long[2], new long[2]);
            return;
        case 17:
            mul544_no_simd_gf2x(array, A.array, A.cp, B.array, B.cp, new long[5], new long[5], new long[9],
                new long[3], new long[3], new long[7]);
            return;
        }
        int i, j, k, b_cp = B.cp, a_cp, c_cp, jc;
        long b, mask, mask1, mask2;
        for (i = 0; i < HFEnq; ++i)
        {
            b = B.array[b_cp];
            mask = -(b & 1L);
            a_cp = A.cp;
            c_cp = cp;
            /* j=0 */
            for (j = 0; j < NB_WORD_GFqn; ++j)
            {
                array[c_cp++] ^= A.array[a_cp++] & mask;
            }

            /* The last 64-bit block BL of A contains HFEnr bits.
               So, there is no overflow for BL<<j while j<=(64-HFEnr). */
            for (j = 1, jc = 63; j <= 64 - HFEnr; ++j, --jc)
            {
                a_cp = A.cp;
                c_cp = cp;
                mask = -((b >>> j) & 1L);
                mask1 = A.array[a_cp++] & mask;
                array[c_cp++] ^= mask1 << j;
                for (k = 1; k < NB_WORD_GFqn; ++k)
                {
                    mask2 = A.array[a_cp++] & mask;
                    array[c_cp++] ^= (mask1 >>> jc) | (mask2 << j);
                    mask1 = mask2;
                }
            }
            for (; j < 64; ++j, --jc)
            {
                a_cp = A.cp;
                c_cp = cp;
                mask = -((b >>> j) & 1L);
                mask1 = A.array[a_cp++] & mask;
                array[c_cp++] ^= mask1 << j;
                for (k = 1; k < NB_WORD_GFqn; ++k)
                {
                    mask2 = A.array[a_cp++] & mask;
                    array[c_cp++] ^= (mask1 >>> jc) | (mask2 << j);
                    mask1 = mask2;
                }
                array[c_cp] ^= mask1 >>> jc;
            }
            b_cp++;
            cp++;
        }
        b = B.array[b_cp];
        /* j=0 */
        mask = -(b & 1L);
        a_cp = A.cp;
        c_cp = cp;
        /* j=0 */
        for (j = 0; j < NB_WORD_GFqn; ++j)
        {
            array[c_cp++] ^= A.array[a_cp++] & mask;
        }
        /* The last 64-bit block BL of A contains HFEnr bits. So, there is no overflow for BL<<j while j<=(64-HFEnr). */
        int loop_end = HFEnr > 32 ? 65 - HFEnr : HFEnr;
        for (j = 1, jc = 63; j < loop_end; ++j, --jc)
        {
            a_cp = A.cp;
            c_cp = cp;
            mask = -((b >>> j) & 1L);
            mask1 = A.array[a_cp++] & mask;
            array[c_cp++] ^= mask1 << j;
            for (k = 1; k < NB_WORD_GFqn; ++k)
            {
                mask2 = A.array[a_cp++] & mask;
                array[c_cp++] ^= (mask1 >>> jc) | (mask2 << j);
                mask1 = mask2;
            }
        }
        if (HFEnr > 32)
        {
            for (; j < HFEnr; ++j, --jc)
            {
                a_cp = A.cp;
                c_cp = cp;
                mask = -((b >>> j) & 1L);
                mask1 = A.array[a_cp++] & mask;
                array[c_cp++] ^= mask1 << j;
                for (k = 1; k < NB_WORD_GFqn; ++k)
                {
                    mask2 = A.array[a_cp++] & mask;
                    array[c_cp++] ^= (mask1 >>> jc) | (mask2 << j);
                    mask1 = mask2;
                }
                array[c_cp] ^= mask1 >>> jc;
            }
        }
        cp = 0;
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

    private void mul128_no_simd_gf2x(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp, long[] RESERVED_BUF, int buf_cp)
    {
        // buffer size: 2
        long AA, BB;
        //long[] RESERVED_BUF2 = new long[2];
        MUL64_NO_SIMD_GF2X(C, c_cp, A[a_cp], B[b_cp]);
        MUL64_NO_SIMD_GF2X(C, c_cp + 2, A[a_cp + 1], B[b_cp + 1]);
        C[c_cp + 2] ^= C[c_cp + 1];
        C[c_cp + 1] = C[c_cp] ^ C[c_cp + 2];
        C[c_cp + 2] ^= C[c_cp + 3];
    /*  C[0] = C0
        C[1] = C0^C1^C2
        C[2] = C1^C2^C3
        C[3] = C3 */
        AA = A[a_cp] ^ A[a_cp + 1];
        BB = B[b_cp] ^ B[b_cp + 1];
        MUL64_NO_SIMD_GF2X(RESERVED_BUF, buf_cp, AA, BB);
        C[c_cp + 1] ^= RESERVED_BUF[buf_cp];
        C[c_cp + 2] ^= RESERVED_BUF[buf_cp + 1];
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

    private void mul160_no_simd_gf2x(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp,
                                     long[] RESERVED_BUF2, int buf_cp)
    {
        //Buffer size: 2
        long AA, BB;
        /* A0*B0 */
        MUL64_NO_SIMD_GF2X(C, c_cp, A[a_cp], B[b_cp]);
        /* A2*B2 */
        C[c_cp + 4] = MUL32_NO_SIMD_GF2X(A[a_cp + 2], B[b_cp + 2]);
        /* A1*B1 */
        MUL64_NO_SIMD_GF2X(RESERVED_BUF2, buf_cp, A[a_cp + 1], B[b_cp + 1]);
        C[c_cp + 1] ^= RESERVED_BUF2[buf_cp];
        C[c_cp + 4] ^= RESERVED_BUF2[buf_cp + 1];
        C[c_cp + 2] = C[c_cp + 4];
        C[c_cp + 3] = C[c_cp + 1];
    /*  C[0] = C0
        C[1] = C1^C2
        C[2] = C4^C3
        C[3] = C1^C2
        C[4] = C4^C3 */
        C[c_cp + 1] ^= C[c_cp];
        C[c_cp + 2] ^= C[c_cp + 1];
        C[c_cp + 3] ^= C[c_cp + 4];
    /*  C[0] = C0
        C[1] = C0^(C1^C2)
        C[2] = (C0^C1^C2)^(C3^C4)
        C[3] = (C1^C2)^(C3^C4)
        C[4] = C3^C4 */
        AA = A[a_cp] ^ A[a_cp + 1];
        BB = B[b_cp] ^ B[b_cp + 1];
        /* (A0+A1)*(B0+B1) */
        MUL64_NO_SIMD_GF2X(RESERVED_BUF2, buf_cp, AA, BB);
        C[c_cp + 1] ^= RESERVED_BUF2[buf_cp];
        C[c_cp + 2] ^= RESERVED_BUF2[buf_cp + 1];
        AA = A[a_cp + 1] ^ A[a_cp + 2];
        BB = B[b_cp + 1] ^ B[b_cp + 2];
        /* (A1+A2)*(B1+B2) */
        MUL64_NO_SIMD_GF2X(RESERVED_BUF2, buf_cp, AA, BB);
        C[c_cp + 3] ^= RESERVED_BUF2[buf_cp];
        C[c_cp + 4] ^= RESERVED_BUF2[buf_cp + 1];
        AA = A[a_cp] ^ A[a_cp + 2];
        BB = B[b_cp] ^ B[b_cp + 2];
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X(RESERVED_BUF2, buf_cp, AA, BB);
        C[c_cp + 2] ^= RESERVED_BUF2[buf_cp];
        C[c_cp + 3] ^= RESERVED_BUF2[buf_cp + 1];
    }

    public void mul192_no_simd_gf2x(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp, long[] RESERVED_BUF2, int buf_cp)
    {
        //Buffer size: 2
        long AA, BB;
        //long[] RESERVED_BUF2 = new long[2];
        /* A0*B0 */
        MUL64_NO_SIMD_GF2X(C, c_cp, A[a_cp], B[b_cp]);
        /* A2*B2 */
        MUL64_NO_SIMD_GF2X(C, c_cp + 4, A[a_cp + 2], B[b_cp + 2]);
        /* A1*B1 */
        MUL64_NO_SIMD_GF2X(RESERVED_BUF2, buf_cp, A[a_cp + 1], B[b_cp + 1]);
        C[c_cp + 1] ^= RESERVED_BUF2[buf_cp];
        C[c_cp + 4] ^= RESERVED_BUF2[buf_cp + 1];
        C[c_cp + 2] = C[c_cp + 4];
        C[c_cp + 3] = C[c_cp + 1];
    /*  C[0] = C0
        C[1] = C1^C2
        C[2] = C4^C3
        C[3] = C1^C2
        C[4] = C4^C3
        C[5] = C5 */
        C[c_cp + 1] ^= C[c_cp];
        C[c_cp + 4] ^= C[c_cp + 5];
        C[c_cp + 2] ^= C[c_cp + 1];
        C[c_cp + 3] ^= C[c_cp + 4];
    /*  C[0] = C0
        C[1] = C0^(C1^C2)
        C[2] = (C0^C1^C2)^(C3^C4)
        C[3] = (C1^C2)^(C3^C4^C5)
        C[4] = (C3^C4)^C5
        C[5] = C5 */
        AA = A[a_cp] ^ A[a_cp + 1];
        BB = B[b_cp] ^ B[b_cp + 1];
        /* (A0+A1)*(B0+B1) */
        MUL64_NO_SIMD_GF2X(RESERVED_BUF2, buf_cp, AA, BB);
        C[c_cp + 1] ^= RESERVED_BUF2[buf_cp];
        C[c_cp + 2] ^= RESERVED_BUF2[buf_cp + 1];
        AA = A[a_cp + 1] ^ A[a_cp + 2];
        BB = B[b_cp + 1] ^ B[b_cp + 2];
        /* (A1+A2)*(B1+B2)  */
        MUL64_NO_SIMD_GF2X(RESERVED_BUF2, buf_cp, AA, BB);
        C[c_cp + 3] ^= RESERVED_BUF2[buf_cp];
        C[c_cp + 4] ^= RESERVED_BUF2[buf_cp + 1];
        AA = A[a_cp] ^ A[a_cp + 2];
        BB = B[b_cp] ^ B[b_cp + 2];
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X(RESERVED_BUF2, buf_cp, AA, BB);
        C[c_cp + 2] ^= RESERVED_BUF2[buf_cp];
        C[c_cp + 3] ^= RESERVED_BUF2[buf_cp + 1];
    }

    private void mul224_no_simd_gf2x(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp, long[] AA, long[] BB,
                                     long[] RESERVED_BUF6, int buf_cp)
    {
        //buffer size: 6=4+2
        mul128_no_simd_gf2x(C, c_cp, A, a_cp, B, b_cp, RESERVED_BUF6, buf_cp);
        //MUL96_NO_SIMD_GF2X(C + 4, A + 2, B + 2, tmp, tmp1, tmp2);
        MUL64_NO_SIMD_GF2X(C, c_cp + 4, A[a_cp + 2], B[b_cp + 2]);
        C[c_cp + 6] = MUL32_NO_SIMD_GF2X(A[a_cp + 3], B[b_cp + 3]);
        C[c_cp + 6] ^= C[c_cp + 1];
        C[c_cp + 5] = C[c_cp + 4] ^ C[c_cp + 6];
    /*  C[0] = C0
        C[1] = C0^C1^C2
        C[2] = C1^C2 */
        MUL64_NO_SIMD_GF2X(RESERVED_BUF6, buf_cp, A[a_cp + 2] ^ A[a_cp + 3], B[b_cp + 2] ^ B[b_cp + 3]);
        C[c_cp + 1] ^= RESERVED_BUF6[buf_cp];
        C[c_cp + 2] ^= RESERVED_BUF6[buf_cp + 1];
        //end of mul96
        C[c_cp + 2] ^= C[c_cp + 4];
        C[c_cp + 3] ^= C[c_cp + 5];
        C[c_cp + 4] = C[c_cp + 2];
        C[c_cp + 5] = C[c_cp + 3];
        C[c_cp + 2] ^= C[c_cp];
        C[c_cp + 3] ^= C[c_cp + 1];
        C[c_cp + 4] ^= C[c_cp + 6];
        AA[0] = A[a_cp] ^ A[a_cp + 2];
        AA[1] = A[a_cp + 1] ^ A[a_cp + 3];
        BB[0] = B[b_cp] ^ B[b_cp + 2];
        BB[1] = B[b_cp + 1] ^ B[b_cp + 3];
        mul128_no_simd_gf2x(RESERVED_BUF6, 0, AA, 0, BB, 0, RESERVED_BUF6, buf_cp + 4);
        C[c_cp + 2] ^= RESERVED_BUF6[buf_cp];
        C[c_cp + 3] ^= RESERVED_BUF6[buf_cp + 1];
        C[c_cp + 4] ^= RESERVED_BUF6[buf_cp + 2];
        C[c_cp + 5] ^= RESERVED_BUF6[buf_cp + 3];
    }

    private void mul288_no_simd_gf2x(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp, long[] AA, long[] BB, long[] RESERVED_BUF)
    {
        //buffer size: 5+2=7
//        long[] AA = new long[3];
//        long[] BB = new long[3];
//        long[] RESERVED_BUF6 = new long[5];
        mul128_no_simd_gf2x(C, c_cp, A, a_cp, B, b_cp, RESERVED_BUF, 0);
        mul160_no_simd_gf2x(C, 4, A, a_cp + 2, B, b_cp + 2, RESERVED_BUF, 0);
        C[c_cp + 4] ^= C[c_cp + 2];
        C[c_cp + 5] ^= C[c_cp + 3];
        C[c_cp + 2] = C[c_cp + 4] ^ C[c_cp];
        C[c_cp + 3] = C[c_cp + 5] ^ C[c_cp + 1];
        C[c_cp + 4] ^= C[c_cp + 6];
        C[c_cp + 5] ^= C[c_cp + 7];
        C[c_cp + 6] ^= C[c_cp + 8];
        AA[0] = A[a_cp] ^ A[a_cp + 2];
        AA[1] = A[a_cp + 1] ^ A[a_cp + 3];
        AA[2] = A[a_cp + 4];
        BB[0] = B[b_cp] ^ B[b_cp + 2];
        BB[1] = B[b_cp + 1] ^ B[b_cp + 3];
        BB[2] = B[b_cp + 4];
        mul160_no_simd_gf2x(RESERVED_BUF, 0, AA, 0, BB, 0, RESERVED_BUF, 5);
        C[c_cp + 2] ^= RESERVED_BUF[0];
        C[c_cp + 3] ^= RESERVED_BUF[1];
        C[c_cp + 4] ^= RESERVED_BUF[2];
        C[c_cp + 5] ^= RESERVED_BUF[3];
        C[c_cp + 6] ^= RESERVED_BUF[4];
    }

    private void mul384_no_simd_gf2x(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] AA, long[] BB,
                                     long[] RESERVED_BUF6)
    {
        //buffer size 6+2=8
        mul192_no_simd_gf2x(C, 0, A, a_cp, B, b_cp, RESERVED_BUF6, 0);
        mul192_no_simd_gf2x(C, 6, A, a_cp + 3, B, b_cp + 3, RESERVED_BUF6, 0);
        C[6] ^= C[3];
        C[7] ^= C[4];
        C[8] ^= C[5];
        C[3] = C[6] ^ C[0];
        C[4] = C[7] ^ C[1];
        C[5] = C[8] ^ C[2];
        C[6] ^= C[9];
        C[7] ^= C[10];
        C[8] ^= C[11];
        AA[0] = A[a_cp] ^ A[a_cp + 3];
        AA[1] = A[a_cp + 1] ^ A[a_cp + 4];
        AA[2] = A[a_cp + 2] ^ A[a_cp + 5];
        BB[0] = B[b_cp] ^ B[b_cp + 3];
        BB[1] = B[b_cp + 1] ^ B[b_cp + 4];
        BB[2] = B[b_cp + 2] ^ B[b_cp + 5];
        mul192_no_simd_gf2x(RESERVED_BUF6, 0, AA, 0, BB, 0, RESERVED_BUF6, 6);
        C[3] ^= RESERVED_BUF6[0];
        C[4] ^= RESERVED_BUF6[1];
        C[5] ^= RESERVED_BUF6[2];
        C[6] ^= RESERVED_BUF6[3];
        C[7] ^= RESERVED_BUF6[4];
        C[8] ^= RESERVED_BUF6[5];
    }

    private void mul416_no_simd_gf2x(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] AA, long[] BB,
                                     long[] RESERVED_BUF, long[] AA2, long[] BB2)
    {
        // buffer size: 7+6=13
        mul192_no_simd_gf2x(C, 0, A, a_cp, B, b_cp, RESERVED_BUF, 0);
        mul224_no_simd_gf2x(C, 6, A, a_cp + 3, B, b_cp + 3, AA, BB, RESERVED_BUF, 0);
        mul128_no_simd_gf2x(C, 6, A, a_cp + 3, B, b_cp + 3, RESERVED_BUF, 0);
        C[6] ^= C[3];
        C[7] ^= C[4];
        C[8] ^= C[5];
        C[3] = C[6] ^ C[0];
        C[4] = C[7] ^ C[1];
        C[5] = C[8] ^ C[2];
        C[6] ^= C[9];
        C[7] ^= C[10];
        C[8] ^= C[11];
        C[9] ^= C[12];
        AA[0] = A[a_cp] ^ A[a_cp + 3];
        AA[1] = A[a_cp + 1] ^ A[a_cp + 4];
        AA[2] = A[a_cp + 2] ^ A[a_cp + 5];
        AA[3] = A[a_cp + 6];
        BB[0] = B[b_cp] ^ B[b_cp + 3];
        BB[1] = B[b_cp + 1] ^ B[b_cp + 4];
        BB[2] = B[b_cp + 2] ^ B[b_cp + 5];
        BB[3] = B[b_cp + 6];
        mul224_no_simd_gf2x(RESERVED_BUF, 0, AA, 0, BB, 0, AA2, BB2, RESERVED_BUF, 7);
        C[3] ^= RESERVED_BUF[0];
        C[4] ^= RESERVED_BUF[1];
        C[5] ^= RESERVED_BUF[2];
        C[6] ^= RESERVED_BUF[3];
        C[7] ^= RESERVED_BUF[4];
        C[8] ^= RESERVED_BUF[5];
        C[9] ^= RESERVED_BUF[6];
    }

    private void mul544_no_simd_gf2x(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] AA, long[] BB,
                                     long[] RESERVED_BUF9, long[] AA3, long[] BB3, long[] RESERVED_BUF6)
    {
        mul128_no_simd_gf2x(C, 0, A, a_cp, B, b_cp, RESERVED_BUF9, 0);
        mul128_no_simd_gf2x(C, 4, A, a_cp + 2, B, b_cp + 2, RESERVED_BUF9, 0);
        C[2] ^= C[4];
        C[3] ^= C[5];
        C[4] = C[2];
        C[5] = C[3];
        C[2] ^= C[0];
        C[3] ^= C[1];
        C[4] ^= C[6];
        C[5] ^= C[7];
        AA[0] = A[a_cp] ^ A[a_cp + 2];
        AA[1] = A[a_cp + 1] ^ A[a_cp + 3];
        BB[0] = B[b_cp] ^ B[b_cp + 2];
        BB[1] = B[b_cp + 1] ^ B[b_cp + 3];
        mul128_no_simd_gf2x(RESERVED_BUF9, 0, AA, 0, BB, 0, RESERVED_BUF9, 4);
        C[2] ^= RESERVED_BUF9[0];
        C[3] ^= RESERVED_BUF9[1];
        C[4] ^= RESERVED_BUF9[2];
        C[5] ^= RESERVED_BUF9[3];
        mul288_no_simd_gf2x(C, 8, A, a_cp + 4, B, b_cp + 4, AA3, BB3, RESERVED_BUF9);
        C[8] ^= C[4];
        C[9] ^= C[5];
        C[10] ^= C[6];
        C[11] ^= C[7];
        C[4] = C[8] ^ C[0];
        C[5] = C[9] ^ C[1];
        C[6] = C[10] ^ C[2];
        C[7] = C[11] ^ C[3];
        C[8] ^= C[12];
        C[9] ^= C[13];
        C[10] ^= C[14];
        C[11] ^= C[15];
        C[12] ^= C[16];
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
        mul288_no_simd_gf2x(RESERVED_BUF9, 0, AA, 0, BB, 0, AA3, BB3, RESERVED_BUF6);
        C[4] ^= RESERVED_BUF9[0];
        C[5] ^= RESERVED_BUF9[1];
        C[6] ^= RESERVED_BUF9[2];
        C[7] ^= RESERVED_BUF9[3];
        C[8] ^= RESERVED_BUF9[4];
        C[9] ^= RESERVED_BUF9[5];
        C[10] ^= RESERVED_BUF9[6];
        C[11] ^= RESERVED_BUF9[7];
        C[12] ^= RESERVED_BUF9[8];
    }

    void REM192_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        Q[0] = (Pol[2] >>> ki) ^ (Pol[3] << ki64);
        Q[1] = (Pol[3] >>> ki) ^ (Pol[4] << ki64);
        Q[2] = (Pol[4] >>> ki) ^ (Pol[5] << ki64);
        P[p_cp] = Pol[0] ^ Q[0] ^ (Q[0] << k3);
        P[p_cp + 1] = Pol[1] ^ Q[1] ^ (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 2] = Pol[2] ^ Q[2] ^ (Q[1] >>> k364) ^ (Q[2] << k3);
        /* 64-(k364+ki) == (k3-ki) */
        long R = (ki >= k3) ? Q[2] >>> (ki - k3) : (Q[1] >>> (k364 + ki)) ^ (Q[2] << (k3 - ki));
        P[p_cp] ^= R ^ (R << k3);
        P[p_cp + 2] &= mask;
    }

    void REM288_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        Q[0] = (Pol[4] >>> ki) ^ (Pol[5] << ki64);
        Q[1] = (Pol[5] >>> ki) ^ (Pol[6] << ki64);
        Q[2] = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
        Q[3] = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        Q[4] = Pol[8] >>> ki;
        P[p_cp] = Pol[0] ^ Q[0];
        P[p_cp + 1] = Pol[1] ^ Q[1];
        P[p_cp + 2] = Pol[2] ^ Q[2];
        P[p_cp + 3] = Pol[3] ^ Q[3];
        P[p_cp + 4] = Pol[4] ^ Q[4];
        P[p_cp] ^= Q[0] << k3;
        P[p_cp + 1] ^= (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 2] ^= (Q[1] >>> k364) ^ (Q[2] << k3);
        P[p_cp + 3] ^= (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 4] ^= (Q[3] >>> k364) ^ (Q[4] << k3);
        /* 64-(k364+ki) == (k3-ki) */
        long R = (ki >= k3) ? Q[4] >>> (ki - k3) : (Q[3] >>> (k364 + ki)) ^ (Q[4] << (k3 - ki));
        P[p_cp] ^= R;
        P[p_cp] ^= R << k3;
        P[p_cp + 4] &= mask;
    }

    void REM288_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        Q[0] = (Pol[4] >>> ki) ^ (Pol[5] << ki64);
        Q[1] = (Pol[5] >>> ki) ^ (Pol[6] << ki64);
        Q[2] = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
        Q[3] = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        Q[4] = (Pol[8] >>> ki);
        P[p_cp] = Pol[0] ^ Q[0];
        P[p_cp + 1] = Pol[1] ^ Q[1];
        P[p_cp + 2] = Pol[2] ^ Q[2];
        P[p_cp + 3] = Pol[3] ^ Q[3];
        P[p_cp + 4] = Pol[4] ^ Q[4];
        P[p_cp] ^= Q[0] << k3;
        P[p_cp + 1] ^= (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 2] ^= (Q[1] >>> k364) ^ (Q[2] << k3);
        P[p_cp + 3] ^= (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 4] ^= (Q[3] >>> k364) ^ (Q[4] << k3);
        /* 64-(k364+ki) == (k3-ki) */
        long R = (ki >= k3) ? Q[4] >>> (ki - k3) : (Q[3] >>> (k364 + ki)) ^ (Q[4] << (k3 - ki));
        P[p_cp] ^= R;
        P[p_cp] ^= R << k3;
        /* This row is the unique difference with REM288_TRINOMIAL_GF2X */
        P[p_cp + 1] ^= R >>> k364;
        P[p_cp + 4] &= mask;
    }

    void REM544_PENTANOMIAL_K3_IS_128_GF2X(long[] P, int p_cp, long[] Pol, int k1, int k2, int ki, int ki64,
                                           int k164, int k264, long[] Q, long mask)
    {
        Q[0] = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        Q[1] = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        Q[2] = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        Q[3] = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
        Q[4] = (Pol[12] >>> ki) ^ (Pol[13] << ki64);
        Q[5] = (Pol[13] >>> ki) ^ (Pol[14] << ki64);
        Q[6] = (Pol[14] >>> ki) ^ (Pol[15] << ki64);
        Q[7] = (Pol[15] >>> ki) ^ (Pol[16] << ki64);
        Q[8] = (Pol[16] >>> ki);
        /* R for K2=3 */
        Q[0] ^= Pol[16] >>> (k264);
        /* R for K3=128 */
        Q[0] ^= (Q[6] >>> ki) ^ (Q[7] << ki64);
        Q[1] ^= (Q[7] >>> ki) ^ (Q[8] << ki64);
        P[p_cp] = Pol[0] ^ Q[0];
        P[p_cp + 1] = Pol[1] ^ Q[1];
        P[p_cp + 2] = Pol[2] ^ Q[2];
        P[p_cp + 3] = Pol[3] ^ Q[3];
        P[p_cp + 4] = Pol[4] ^ Q[4];
        P[p_cp + 5] = Pol[5] ^ Q[5];
        P[p_cp + 6] = Pol[6] ^ Q[6];
        P[p_cp + 7] = Pol[7] ^ Q[7];
        P[p_cp + 8] = Pol[8] ^ Q[8];
        /* K3=128 */
        P[p_cp + 2] ^= Q[0];
        P[p_cp + 3] ^= Q[1];
        P[p_cp + 4] ^= Q[2];
        P[p_cp + 5] ^= Q[3];
        P[p_cp + 6] ^= Q[4];
        P[p_cp + 7] ^= Q[5];
        P[p_cp + 8] ^= Q[6];
        P[p_cp] ^= Q[0] << k1;
        P[p_cp + 1] ^= (Q[0] >>> k164) ^ (Q[1] << k1);
        P[p_cp + 2] ^= (Q[1] >>> k164) ^ (Q[2] << k1);
        P[p_cp + 3] ^= (Q[2] >>> k164) ^ (Q[3] << k1);
        P[p_cp + 4] ^= (Q[3] >>> k164) ^ (Q[4] << k1);
        P[p_cp + 5] ^= (Q[4] >>> k164) ^ (Q[5] << k1);
        P[p_cp + 6] ^= (Q[5] >>> k164) ^ (Q[6] << k1);
        P[p_cp + 7] ^= (Q[6] >>> k164) ^ (Q[7] << k1);
        P[p_cp + 8] ^= (Q[7] >>> k164) ^ (Q[8] << k1);
        P[p_cp] ^= Q[0] << k2;
        P[p_cp + 1] ^= (Q[0] >>> k264) ^ (Q[1] << k2);
        P[p_cp + 2] ^= (Q[1] >>> k264) ^ (Q[2] << k2);
        P[p_cp + 3] ^= (Q[2] >>> k264) ^ (Q[3] << k2);
        P[p_cp + 4] ^= (Q[3] >>> k264) ^ (Q[4] << k2);
        P[p_cp + 5] ^= (Q[4] >>> k264) ^ (Q[5] << k2);
        P[p_cp + 6] ^= (Q[5] >>> k264) ^ (Q[6] << k2);
        P[p_cp + 7] ^= (Q[6] >>> k264) ^ (Q[7] << k2);
        P[p_cp + 8] ^= (Q[7] >>> k264) ^ (Q[8] << k2);
        P[p_cp + 8] &= mask;
    }

    void REM544_PENTANOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k1, int k2, int k3, int ki, int ki64, int k164,
                                 int k264, int k364, long[] Q, long mask)
    {
        Q[0] = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        Q[1] = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        Q[2] = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        Q[3] = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
        Q[4] = (Pol[12] >>> ki) ^ (Pol[13] << ki64);
        Q[5] = (Pol[13] >>> ki) ^ (Pol[14] << ki64);
        Q[6] = (Pol[14] >>> ki) ^ (Pol[15] << ki64);
        Q[7] = (Pol[15] >>> ki) ^ (Pol[16] << ki64);
        Q[8] = Pol[16] >>> ki;
        P[p_cp] = Pol[0] ^ Q[0];
        P[p_cp + 1] = Pol[1] ^ Q[1];
        P[p_cp + 2] = Pol[2] ^ Q[2];
        P[p_cp + 3] = Pol[3] ^ Q[3];
        P[p_cp + 4] = Pol[4] ^ Q[4];
        P[p_cp + 5] = Pol[5] ^ Q[5];
        P[p_cp + 6] = Pol[6] ^ Q[6];
        P[p_cp + 7] = Pol[7] ^ Q[7];
        P[p_cp + 8] = Pol[8] ^ Q[8];
        P[p_cp] ^= Q[0] << k1;
        P[p_cp + 1] ^= (Q[0] >>> k164) ^ (Q[1] << k1);
        P[p_cp + 2] ^= (Q[1] >>> k164) ^ (Q[2] << k1);
        P[p_cp + 3] ^= (Q[2] >>> k164) ^ (Q[3] << k1);
        P[p_cp + 4] ^= (Q[3] >>> k164) ^ (Q[4] << k1);
        P[p_cp + 5] ^= (Q[4] >>> k164) ^ (Q[5] << k1);
        P[p_cp + 6] ^= (Q[5] >>> k164) ^ (Q[6] << k1);
        P[p_cp + 7] ^= (Q[6] >>> k164) ^ (Q[7] << k1);
        P[p_cp + 8] ^= (Q[7] >>> k164) ^ (Q[8] << k1);
        P[p_cp] ^= Q[0] << k2;
        P[p_cp + 1] ^= (Q[0] >>> k264) ^ (Q[1] << k2);
        P[p_cp + 2] ^= (Q[1] >>> k264) ^ (Q[2] << k2);
        P[p_cp + 3] ^= (Q[2] >>> k264) ^ (Q[3] << k2);
        P[p_cp + 4] ^= (Q[3] >>> k264) ^ (Q[4] << k2);
        P[p_cp + 5] ^= (Q[4] >>> k264) ^ (Q[5] << k2);
        P[p_cp + 6] ^= (Q[5] >>> k264) ^ (Q[6] << k2);
        P[p_cp + 7] ^= (Q[6] >>> k264) ^ (Q[7] << k2);
        P[p_cp + 8] ^= (Q[7] >>> k264) ^ (Q[8] << k2);
        P[p_cp] ^= Q[0] << k3;
        P[p_cp + 1] ^= (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 2] ^= (Q[1] >>> k364) ^ (Q[2] << k3);
        P[p_cp + 3] ^= (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 4] ^= (Q[3] >>> k364) ^ (Q[4] << k3);
        P[p_cp + 5] ^= (Q[4] >>> k364) ^ (Q[5] << k3);
        P[p_cp + 6] ^= (Q[5] >>> k364) ^ (Q[6] << k3);
        P[p_cp + 7] ^= (Q[6] >>> k364) ^ (Q[7] << k3);
        P[p_cp + 8] ^= (Q[7] >>> k364) ^ (Q[8] << k3);
        /* 64-(k364+ki) == (k3-ki) */
        long R = (ki >= k3) ? Q[8] >>> (ki - k3) : (Q[7] >>> (k364 + ki)) ^ (Q[8] << (k3 - ki));
        R ^= (ki >= k2) ? Q[8] >>> (ki - k2) : (Q[7] >>> (k264 + ki)) ^ (Q[8] << (k2 - ki));
        R ^= (ki >= k1) ? Q[8] >>> (ki - k1) : (Q[7] >>> (k164 + ki)) ^ (Q[8] << (k1 - ki));
        P[p_cp] ^= R;
        P[p_cp] ^= R << k1;
        P[p_cp] ^= R << k2;
        P[p_cp] ^= R << k3;
        P[p_cp + 8] &= mask;
    }

    void REM384_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        long R2;
        Q[0] = (Pol[5] >>> ki) ^ (Pol[6] << ki64);
        Q[1] = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
        Q[2] = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        Q[3] = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        Q[4] = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        Q[5] = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        P[p_cp] = Pol[0] ^ Q[0];
        P[p_cp + 1] = Pol[1] ^ Q[1];
        P[p_cp + 2] = Pol[2] ^ Q[2];
        P[p_cp + 3] = Pol[3] ^ Q[3];
        P[p_cp + 4] = Pol[4] ^ Q[4];
        P[p_cp + 5] = Pol[5] ^ Q[5];
        /* 64-(k364+ki) == (k3-ki) */
        long R = (Q[3] >>> (k364 + ki)) ^ (Q[4] << (k3 - ki));
        P[p_cp] ^= R;
        R2 = (Q[4] >>> (k364 + ki)) ^ (Q[5] << (k3 - ki));
        P[p_cp + 1] ^= R2;
        P[p_cp + 1] ^= (R ^ Q[0]) << k3;
        P[p_cp + 2] ^= ((R ^ Q[0]) >>> k364) ^ ((R2 ^ Q[1]) << k3);
        P[p_cp + 3] ^= ((R2 ^ Q[1]) >>> k364) ^ (Q[2] << k3);
        P[p_cp + 4] ^= (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 5] ^= Q[3] >>> k364;
        P[p_cp + 5] &= mask;
    }

    void REM384_SPECIALIZED358_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        Q[0] = (Pol[5] >>> ki) ^ (Pol[6] << ki64);
        Q[1] = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
        Q[2] = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        Q[3] = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        Q[4] = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        Q[5] = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        /* 64-(k364+ki) == (k3-ki) */
        long R = (Q[4] >>> (k364 + ki)) ^ (Q[5] << (k3 - ki));
        Q[0] ^= R;
        P[p_cp] = Pol[0] ^ Q[0];
        P[p_cp + 1] = Pol[1] ^ Q[1];
        P[p_cp + 2] = Pol[2] ^ Q[2];
        P[p_cp + 3] = Pol[3] ^ Q[3];
        P[p_cp + 4] = Pol[4] ^ Q[4];
        P[p_cp + 5] = Pol[5] ^ Q[5];
        P[p_cp] ^= Q[0] << k3;
        P[p_cp + 1] ^= (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 2] ^= (Q[1] >>> k364) ^ (Q[2] << k3);
        P[p_cp + 3] ^= (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 4] ^= (Q[3] >>> k364) ^ (Q[4] << k3);
        P[p_cp + 5] ^= (Q[4] >>> k364);
        P[p_cp + 5] &= mask;
    }

    void REM402_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        Q[0] = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
        Q[1] = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        Q[2] = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        Q[3] = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        Q[4] = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        Q[5] = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
        Q[6] = (Pol[12] >>> ki);

        Q[0] ^= (Q[3] >>> 39) ^ (Q[4] << 25);
        Q[1] ^= (Q[4] >>> 39) ^ (Q[5] << 25);
        Q[2] ^= (Q[5] >>> 39) ^ (Q[6] << 25);
        P[p_cp] = Pol[0] ^ Q[0];
        P[p_cp + 1] = Pol[1] ^ Q[1];
        P[p_cp + 2] = Pol[2] ^ Q[2];
        P[p_cp + 3] = Pol[3] ^ Q[3];
        P[p_cp + 4] = Pol[4] ^ Q[4];
        P[p_cp + 5] = Pol[5] ^ Q[5];
        P[p_cp + 6] = Pol[6] ^ Q[6];

        P[p_cp + 2] ^= (Q[0] << k3);
        P[p_cp + 3] ^= (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 4] ^= (Q[1] >>> k364) ^ (Q[2] << k3);
        P[p_cp + 5] ^= (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 6] ^= Q[3] >>> k364;
        P[p_cp + 6] &= mask;
    }



}
