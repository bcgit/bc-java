package org.bouncycastle.pqc.crypto.gemss;

import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
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
        for (int i = 0; i < len; ++i)
        {
            array[outOff + i] ^= p.get(i + inOff);
        }
    }

//    public void setXorRangeRotate(int outOff, Pointer p, int inOff, int len, int rotate)
//    {
//        outOff += cp;
//        for (int i = 0; i < len; ++i)
//        {
//            array[outOff + i] ^= p.get(i + inOff);
//        }
//    }

    public void setXorRangeAndMask(int outOff, Pointer p, int inOff, int len, long mask)
    {
        outOff += cp;
        for (int i = 0; i < len; ++i)
        {
            array[outOff + i] ^= p.get(i + inOff) & mask;
        }
    }

    public void setXorRangeAndMaskRotate(int outOff, Pointer p, int inOff, int len, long mask, int j)
    {
        int jc = 64 - j;
        long A_mask1 = p.get(inOff) & mask, A_mask2;
        outOff += cp;
        array[outOff] ^= A_mask1 << j;
        for (int i = 1; i < len; ++i)
        {
            A_mask2 = p.get(inOff + i) & mask;
            array[outOff + i] ^= (A_mask1 >>> jc) | (A_mask2 << j);
            A_mask1 = A_mask2;
        }
    }

    public void setXorRangeAndMaskRotateOverflow(int outOff, Pointer p, int inOff, int len, long mask, int j)
    {
        int jc = 64 - j, i;
        long A_mask1 = p.get(inOff) & mask, A_mask2;
        outOff += cp;
        array[outOff] ^= A_mask1 << j;
        for (i = 1; i < len; ++i)
        {
            A_mask2 = p.get(inOff + i) & mask;
            array[outOff + i] ^= (A_mask1 >>> jc) | (A_mask2 << j);
            A_mask1 = A_mask2;
        }
        array[outOff + i] ^= A_mask1 >>> jc;
    }

    public void move(int p)
    {
        cp += p;
    }

    public void moveIncremental()
    {
        cp++;
    }

    public void moveDecremental()
    {
        cp--;
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

    public void setRangeClear(int startPos, int size)
    {
        for (int i = 0; i < size; ++i)
        {
            array[cp + i + startPos] = 0;
        }
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
        Arrays.fill(array, 0);
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

    public void setXorRange(Pointer a, Pointer b, int len)
    {
        for (int i = 0; i < len; ++i)
        {
            set(i, a.get(i) ^ b.get(i));
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
}
