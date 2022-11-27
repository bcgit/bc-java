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
        int pos = cp + startPos;
        array[pos++] = 1L;
        //Arrays.fill(array, pos, size - 1, 0L);
        for (int i = 1; i < size; ++i)
        {
            array[pos++] = 0L;
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
            array[outOff++] = a.array[aOff++] ^ b.array[bOff++];
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
}
