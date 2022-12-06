package org.bouncycastle.pqc.crypto.gemss;

import java.security.SecureRandom;

class PointerUnion
    extends Pointer
{
    protected int remainder;

    public PointerUnion(byte[] arr)
    {
        super((arr.length >> 3) + ((arr.length & 7) != 0 ? 1 : 0));
        for (int i = 0, q = 0, r; i < arr.length && q < array.length; ++q)
        {
            for (r = 0; r < 8 && i < arr.length; ++r, ++i)
            {
                array[q] |= (arr[i] & 0xFFL) << (r << 3);
            }
        }
        remainder = 0;
    }

    public PointerUnion(int p)
    {
        super((p >>> 3) + ((p & 7) != 0 ? 1 : 0));
        remainder = 0;
    }

    public PointerUnion(PointerUnion p)
    {
        super(p);
        remainder = p.remainder;
    }

    public PointerUnion(Pointer p)
    {
        super(p);
        remainder = 0;
    }

    public void moveNextBytes(int p)
    {
        remainder += p;
        cp += remainder >>> 3;
        remainder &= 7;
    }

    public void moveNextByte()
    {
        remainder++;
        cp += remainder >>> 3;
        remainder &= 7;
    }

    @Override
    public long get()
    {
        if (remainder == 0)
        {
            return array[cp];
        }
        return (array[cp] >>> (remainder << 3)) | (array[cp + 1] << ((8 - remainder) << 3));
    }

    public long getWithCheck()
    {
        if (cp >= array.length)
        {
            return 0;
        }
        if (remainder == 0)
        {
            return array[cp];
        }
        if (cp == array.length - 1)
        {
            return array[cp] >>> (remainder << 3);
        }
        return (array[cp] >>> (remainder << 3)) | (array[cp + 1] << ((8 - remainder) << 3));
    }

    public long getWithCheck(int p)
    {
        p += cp;
        if (p >= array.length)
        {
            return 0;
        }
        if (remainder == 0)
        {
            return array[p];
        }
        if (p == array.length - 1)
        {
            return array[p] >>> (remainder << 3);
        }
        return (array[p] >>> (remainder << 3)) | (array[p + 1] << ((8 - remainder) << 3));
    }

    @Override
    public long get(int q)
    {
        if (remainder == 0)
        {
            return array[cp + q];
        }
        return (array[cp + q] >>> (remainder << 3)) | (array[cp + q + 1] << ((8 - remainder) << 3));
    }

    public byte getByte()
    {
        return (byte)(array[cp] >>> (remainder << 3));
    }

    public byte getByte(int p)
    {
        int q = cp + ((p + remainder) >>> 3);
        int r = (remainder + p) & 7;
        return (byte)(array[q] >>> (r << 3));
    }

    @Override
    public void setRangeClear(int startPos, int endPos)
    {
        if (remainder == 0)
        {
            super.setRangeClear(startPos, endPos);
        }
        else
        {
            array[cp + startPos] &= -1L >>> ((8 - remainder) << 3);
            super.setRangeClear(startPos + 1, endPos);
            array[cp + endPos + 1] &= -1L << (remainder << 3);
        }
    }

    @Override
    public void setAnd(int p, long v)
    {
        if (remainder == 0)
        {
            super.setAnd(p, v);
        }
        else
        {
            int shift1 = remainder << 3, shift2 = (8 - remainder) << 3;
            array[cp + p] &= (v << shift1) | (-1L >>> shift2);
            array[cp + p + 1] &= (v >>> shift2) | (-1L << shift1);
        }
    }

    @Override
    public void indexReset()
    {
        cp = 0;
        remainder = 0;
    }

    public void setByteIndex(int p)
    {
        remainder = p & 7;
        cp = p >>> 3;
    }

    @Override
    public byte[] toBytes(int length)
    {
        byte[] res = new byte[length];
        for (int i = remainder; i < res.length + remainder; ++i)
        {
            res[i - remainder] = (byte)(array[cp + (i >>> 3)] >>> ((i & 7) << 3));
        }
        return res;
    }

    public int toBytesMove(byte[] output, int outOff, int length)
    {
        for (int i = 0; i < length; ++i)
        {
            output[outOff++] = (byte)(array[cp] >>> (remainder++ << 3));
            if (remainder == 8)
            {
                remainder = 0;
                cp++;
            }
        }
        return outOff;
    }

    @Override
    public void setXor(int p, long v)
    {
        if (remainder == 0)
        {
            super.setXor(p, v);
        }
        else
        {
            array[cp + p] ^= v << (remainder << 3);
            array[cp + p + 1] ^= v >>> ((8 - remainder) << 3);
        }
    }

    @Override
    public void setXor(long v)
    {
        if (remainder == 0)
        {
            super.setXor(v);
        }
        else
        {
            array[cp] ^= v << (remainder << 3);
            array[cp + 1] ^= v >>> ((8 - remainder) << 3);
        }
    }

    public void setXorRangeAndMask(Pointer p, int len, long mask)
    {
        if (remainder == 0)
        {
            super.setXorRangeAndMask(p, len, mask);
            return;
        }
        int outOff = cp, inOff = p.cp;
        long v;
        int left = remainder << 3, right = ((8 - remainder) << 3);
        for (int i = 0; i < len; ++i)
        {
            //v = p.get(i) & mask;
            v = p.array[inOff++] & mask;
            array[outOff] ^= v << left;
            array[++outOff] ^= v >>> right;
        }
    }

    public void setXorByte(int v)
    {
        array[cp] ^= (v & 0xFFL) << (remainder << 3);
    }

    public void setAndByte(int p, long v)
    {
        int r = p + remainder + (cp << 3);
        int q = r >>> 3;
        r &= 7;
        array[q] &= ((v & 0xFFL) << (r << 3)) | ~(0xFFL << (r << 3));
    }

    public void setAndThenXorByte(int p, long v1, long v2)
    {
        int r = p + remainder + (cp << 3);
        int q = r >>> 3;
        r &= 7;
        array[q] &= ((v1 & 0xFFL) << (r << 3)) | ~(0xFFL << (r << 3));
        array[q] ^= (v2 & 0xFFL) << (r << 3);
    }

    @Override
    public void set(int p, long v)
    {
        if (remainder == 0)
        {
            super.setXor(p, v);
        }
        else
        {
            int shift1 = remainder << 3, shift2 = (8 - remainder) << 3;
            array[cp + p] = (v << shift1) | (array[cp + p] & (-1L >>> shift2));
            array[cp + p + 1] = (v >>> shift2) | (array[cp + p + 1] & (-1L << shift1));
        }
    }

    public void setByte(int v)
    {
        array[cp] = ((v & 0xFFL) << (remainder << 3)) | (array[cp] & (-1L >>> ((8 - remainder) << 3)));
    }

    @Override
    public void fill(int shift, byte[] arr, int input_cp, int len)
    {
        if (remainder != 0)
        {
            int q = cp + shift, r = remainder, i;
            array[q] &= ~(-1L << (r << 3));
            for (i = 0; r < 8 && i < len; ++r)
            {
                array[q] |= (arr[input_cp] & 0xFFL) << (r << 3);
                ++input_cp;
                ++i;
            }
            shift++;
            len -= 8 - remainder;
        }
        super.fill(shift, arr, input_cp, len);
    }

    public void fillBytes(int shift, byte[] arr, int input_cp, int len)
    {
        int r = shift + remainder;
        int q = cp + (r >>> 3);
        r &= 7;
        if (r != 0)
        {
            array[q] &= ~(-1L << (r << 3));
            int i = 0;
            for (; r < 8 && i < len; ++r)
            {
                array[q] |= (arr[input_cp] & 0xFFL) << (r << 3);
                ++input_cp;
                ++i;
            }
            q++;
            len -= i;
        }
        super.fill(q - cp, arr, input_cp, len);
    }

    public void fillRandomBytes(int shift, SecureRandom random, int length)
    {
        byte[] rv = new byte[length];
        random.nextBytes(rv);
        fillBytes(shift, rv, 0, rv.length);
    }

    public void changeIndex(PointerUnion p)
    {
        array = p.array;
        cp = p.cp;
        remainder = p.remainder;
    }
}
