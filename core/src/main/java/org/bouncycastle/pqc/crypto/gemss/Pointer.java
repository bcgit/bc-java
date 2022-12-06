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
            for (int i = 0; i < len; ++i)
            {
                array[outOff++] ^= (p.array[inOff] >>> right) | (p.array[++inOff] << left);
            }
        }
    }

    public void setXorRangeAndMask(Pointer p, int len, long mask)
    {
        int outOff = cp;
        int inOff = p.cp;
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
        for (int i = 0; i < len; ++i)
        {
            array[outOff++] = (p.array[inOff] >>> left) ^ (p.array[++inOff] << right);
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

    public void setRangeFromXor(Pointer a, Pointer b, int len)
    {
        for (int i = 0, outOff = cp, aOff = a.cp, bOff = b.cp; i < len; ++i)
        {
            array[outOff++] = a.array[aOff++] ^ b.array[bOff++];
        }
    }

    public void setRangeFromXorAndMask_xor(Pointer a, Pointer b, long mask, int len)
    {
        int outOff = cp;
        int a_cp = a.cp;
        int b_cp = b.cp;
        for (int i = 0; i < len; ++i)
        {
            array[outOff] = (a.array[a_cp] ^ b.array[b_cp]) & mask;
            a.array[a_cp++] ^= array[outOff];
            b.array[b_cp++] ^= array[outOff++];
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

    public int getD_for_not0_or_plus(int NB_WORD_GFqn, int start)
    {
        int i, j, d, pos;
        long mask, b;
        /* Search the degree of X^(2^n) - X mod (F-U) */
        for (i = start, d = 0, mask = 0L, pos = cp; i > 0; --i)
        {
            b = array[pos++];
            for (j = 1; j < NB_WORD_GFqn; ++j)
            {
                b |= array[pos++];
            }
            mask |= GeMSSUtils.ORBITS_UINT(b);
            /* We add 1 to d as soon as we exceed all left zero coefficients */
            d += mask;
        }
        return d;
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

    public void setRangePointerUnion(PointerUnion p, int len)
    {
        if (p.remainder == 0)
        {
            System.arraycopy(p.array, p.cp, array, cp, len);
        }
        else
        {
            int left = (8 - p.remainder) << 3;
            int right = p.remainder << 3;
            int outOff = cp;
            int inOff = p.cp;
            for (int i = 0; i < len; ++i)
            {
                array[outOff++] = (p.array[inOff] >>> right) ^ (p.array[++inOff] << left);
            }
        }
    }

    public void setRangePointerUnion(PointerUnion p, int len, int shift)
    {
        int right2 = shift & 63;
        int left2 = 64 - right2;
        int outOff = cp;
        int inOff = p.cp;
        if (p.remainder == 0)
        {
            for (int i = 0; i < len; ++i)
            {
                array[outOff++] = (p.array[inOff] >>> right2) ^ (p.array[++inOff] << left2);
            }
        }
        else
        {
            int right1 = p.remainder << 3;
            int left1 = ((8 - p.remainder) << 3);
            for (int i = 0; i < len; ++i)
            {
                array[outOff++] = (((p.array[inOff] >>> right1) | (p.array[++inOff] << left1)) >>> right2) ^
                    (((p.array[inOff] >>> right1) | (p.array[inOff + 1] << left1)) << left2);
            }
        }
    }

    public void setRangePointerUnion_Check(PointerUnion p, int len, int shift)
    {
        int right2 = shift & 63;
        int left2 = 64 - right2;
        int outOff = cp;
        int inOff = p.cp;
        int i;
        if (p.remainder == 0)
        {
            for (i = 0; i < len && inOff < p.array.length - 1; ++i)
            {
                array[outOff++] = (p.array[inOff] >>> right2) ^ (p.array[++inOff] << left2);
            }
            if (i < len)
            {
                array[outOff] = (p.array[inOff] >>> right2);
            }
        }
        else
        {
            int right1 = p.remainder << 3;
            int left1 = ((8 - p.remainder) << 3);
            for (i = 0; i < len && inOff < p.array.length - 2; ++i)
            {
                array[outOff++] = (((p.array[inOff] >>> right1) | (p.array[++inOff] << left1)) >>> right2) ^
                    (((p.array[inOff] >>> right1) | (p.array[inOff + 1] << left1)) << left2);
            }
            if (i < len)
            {
                array[outOff] = (((p.array[inOff] >>> right1) | (p.array[++inOff] << left1)) >>> right2) ^
                    ((p.array[inOff] >>> right1) << left2);
            }
        }
    }

    public int isEqual_nocst_gf2(Pointer b, int len)
    {
        int inOff = b.cp;
        int outOff = cp;
        for (int i = 0; i < len; ++i)
        {
            if (array[outOff++] != b.array[inOff++])
            {
                return 0;
            }
        }
        return 1;
    }

    public void swap(Pointer b)
    {
        long[] tmp_array = b.array;
        int tmp_cp = b.cp;
        b.array = array;
        b.cp = cp;
        array = tmp_array;
        cp = tmp_cp;
    }
}
