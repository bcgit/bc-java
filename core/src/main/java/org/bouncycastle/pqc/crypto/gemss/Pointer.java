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
}
