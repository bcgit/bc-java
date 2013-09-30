package org.bouncycastle.math.ec;

import org.bouncycastle.util.Arrays;

import java.math.BigInteger;

class IntArray
{
    // For toString(); must have length 32
    private static final String ZEROES = "00000000000000000000000000000000";

    private final static byte[] bitLengths =
    {
        0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
    };

    // TODO make m fixed for the IntArray, and hence compute T once and for all

    private int[] m_ints;

    public IntArray(int intLen)
    {
        m_ints = new int[intLen];
    }

    public IntArray(int[] ints)
    {
        m_ints = ints;
    }

    public IntArray(BigInteger bigInt)
    {
        this(bigInt, 0);
    }

    public IntArray(BigInteger bigInt, int minIntLen)
    {
        if (bigInt.signum() == -1)
        {
            throw new IllegalArgumentException("Only positive Integers allowed");
        }
        if (bigInt.equals(ECConstants.ZERO))
        {
            m_ints = new int[] { 0 };
            return;
        }

        byte[] barr = bigInt.toByteArray();
        int barrLen = barr.length;
        int barrStart = 0;
        if (barr[0] == 0)
        {
            // First byte is 0 to enforce highest (=sign) bit is zero.
            // In this case ignore barr[0].
            barrLen--;
            barrStart = 1;
        }
        int intLen = (barrLen + 3) / 4;
        if (intLen < minIntLen)
        {
            m_ints = new int[minIntLen];
        }
        else
        {
            m_ints = new int[intLen];
        }

        int iarrJ = intLen - 1;
        int rem = barrLen % 4 + barrStart;
        int temp = 0;
        int barrI = barrStart;
        if (barrStart < rem)
        {
            for (; barrI < rem; barrI++)
            {
                temp <<= 8;
                int barrBarrI = barr[barrI];
                if (barrBarrI < 0)
                {
                    barrBarrI += 256;
                }
                temp |= barrBarrI;
            }
            m_ints[iarrJ--] = temp;
        }

        for (; iarrJ >= 0; iarrJ--)
        {
            temp = 0;
            for (int i = 0; i < 4; i++)
            {
                temp <<= 8;
                int barrBarrI = barr[barrI++];
                if (barrBarrI < 0)
                {
                    barrBarrI += 256;
                }
                temp |= barrBarrI;
            }
            m_ints[iarrJ] = temp;
        }
    }

    public boolean isZero()
    {
        return m_ints.length == 0
            || (m_ints[0] == 0 && getUsedLength() == 0);
    }

    public int getUsedLength()
    {
        return getUsedLengthFrom(m_ints.length);
    }

    public int getUsedLengthFrom(int from)
    {
        if (from < 1)
        {
            return 0;
        }

        // Check if first element will act as sentinel
        if (m_ints[0] != 0)
        {
            while (m_ints[--from] == 0)
            {
            }
            return from + 1;
        }

        do
        {
            if (m_ints[--from] != 0)
            {
                return from + 1;
            }
        }
        while (from > 0);

        return 0;
    }

    public int degree()
    {
        int i = m_ints.length, w;
        do
        {
            if (i == 0)
            {
                return 0;
            }
            w = m_ints[--i];
        }
        while (w == 0);

        int t = w >>> 16, k;
        if (t == 0)
        {
            t = w >>> 8;
            k = (t == 0) ? bitLengths[w] : 8 + bitLengths[t];
        }
        else
        {
            int u = t >>> 8;
            k = (u == 0) ? 16 + bitLengths[t] : 24 + bitLengths[u];
        }

        return (i << 5) + k + 1;
    }

    private int[] resizedInts(int newLen)
    {
        int[] newInts = new int[newLen];
        System.arraycopy(m_ints, 0, newInts, 0, Math.min(m_ints.length, newLen));
        return newInts;
    }

    public BigInteger toBigInteger()
    {
        int usedLen = getUsedLength();
        if (usedLen == 0)
        {
            return ECConstants.ZERO;
        }

        int highestInt = m_ints[usedLen - 1];
        byte[] temp = new byte[4];
        int barrI = 0;
        boolean trailingZeroBytesDone = false;
        for (int j = 3; j >= 0; j--)
        {
            byte thisByte = (byte) (highestInt >>> (8 * j));
            if (trailingZeroBytesDone || (thisByte != 0))
            {
                trailingZeroBytesDone = true;
                temp[barrI++] = thisByte;
            }
        }

        int barrLen = 4 * (usedLen - 1) + barrI;
        byte[] barr = new byte[barrLen];
        for (int j = 0; j < barrI; j++)
        {
            barr[j] = temp[j];
        }
        // Highest value int is done now

        for (int iarrJ = usedLen - 2; iarrJ >= 0; iarrJ--)
        {
            for (int j = 3; j >= 0; j--)
            {
                barr[barrI++] = (byte) (m_ints[iarrJ] >>> (8 * j));
            }
        }
        return new BigInteger(1, barr);
    }

    public void shiftLeft()
    {
        int usedLen = getUsedLength();
        if (usedLen == 0)
        {
            return;
        }
        if (m_ints[usedLen - 1] < 0)
        {
            // highest bit of highest used byte is set, so shifting left will
            // make the IntArray one byte longer
            usedLen++;
            if (usedLen > m_ints.length)
            {
                // make the m_ints one byte longer, because we need one more
                // byte which is not available in m_ints
                m_ints = resizedInts(m_ints.length + 1);
            }
        }

        int prev = 0;
        for (int i = 0; i < usedLen; ++i)
        {
            int next = m_ints[i];
            m_ints[i] = (next << 1) | (prev >>> 31);
            prev = next;
        }
    }

    private int shiftLeftQuick()
    {
        int len = m_ints.length;

        int prev = 0;
        for (int i = 0; i < len; ++i)
        {
            int next = m_ints[i];
            m_ints[i] = (next << 1) | (prev >>> 31);
            prev = next;
        }
        return prev >>> 31;
    }

    public IntArray shiftLeft(int n)
    {
        if (n == 0)
        {
            return this;
        }

        int usedLen = getUsedLength();
        if (usedLen == 0)
        {
            return this;
        }

        if (n > 31)
        {
            throw new IllegalArgumentException("shiftLeft() for max 31 bits "
                + ", " + n + " bit shift is not possible");
        }

        int[] newInts = new int[usedLen + 1];

        int nm32 = 32 - n, prev = 0;
        for (int i = 0; i < usedLen; i++)
        {
            int next = m_ints[i];
            newInts[i] = (next << n) | (prev >>> nm32);
            prev = next;
        }
        newInts[usedLen] = prev >>> nm32;

        return new IntArray(newInts);
    }

    public void addOneShifted(int shift)
    {
        int newMinUsedLen = 1 + shift;
        if (newMinUsedLen > m_ints.length)
        {
            m_ints = resizedInts(newMinUsedLen);
        }

        m_ints[shift] ^= 1;
    }

    public void addShiftedByBits(IntArray other, int bits)
    {
        int words = bits >>> 5;
        int shift = bits & 0x1F;

//        IntArray vzShift = other.shiftLeft(shift);
//        addShiftedByWords(vzShift, words);

        if (shift == 0)
        {
            addShiftedByWords(other, words);
            return;
        }

        int otherUsedLen = other.getUsedLength();
        if (otherUsedLen == 0)
        {
            return;
        }

        int minLen = otherUsedLen + words + 1;
        if (minLen > m_ints.length)
        {
            m_ints = resizedInts(minLen);
        }

        int shiftInv = 32 - shift, prev = 0;
        for (int i = 0; i < otherUsedLen; ++i)
        {
            int next = other.m_ints[i];
            m_ints[i + words] ^= (next << shift) | (prev >>> shiftInv);
            prev = next;
        }
        m_ints[otherUsedLen + words] ^= prev >>> shiftInv;
    }

    public void addShiftedByWords(IntArray other, int words)
    {
        int otherUsedLen = other.getUsedLength();
        if (otherUsedLen == 0)
        {
            return;
        }

        int minLen = otherUsedLen + words;
        if (minLen > m_ints.length)
        {
            m_ints = resizedInts(minLen);
        }

        for (int i = 0; i < otherUsedLen; i++)
        {
            m_ints[words + i] ^= other.m_ints[i];
        }
    }

    private void addShiftedByWordsQuick(IntArray other, int words)
    {
        int otherLen = other.m_ints.length;
        for (int i = 0; i < otherLen; ++i)
        {
            m_ints[words + i] ^= other.m_ints[i];
        }
    }

    public int getLength()
    {
        return m_ints.length;
    }

    public void flipWord(int bit, int word)
    {
        int len = m_ints.length;
        int n = bit >>> 5;
        if (n < len)
        {
            int shift = bit & 31;
            if (shift == 0)
            {
                m_ints[n] ^= word;
            }
            else
            {
                m_ints[n] ^= word << shift;
                if (++n < len)
                {
                    m_ints[n] ^= word >>> (32 - shift);
                }
            }
        }
    }

    public int getWord(int bit)
    {
        int len = m_ints.length;
        int n = bit >>> 5;
        if (n >= len)
        {
            return 0;
        }
        int shift = bit & 31;
        if (shift == 0)
        {
            return m_ints[n];
        }
        int result = m_ints[n] >>> shift;
        if (++n < len)
        {
            result |= m_ints[n] << (32 - shift);
        }
        return result;
    }

    public boolean testBit(int n)
    {
        // theInt = n / 32
        int theInt = n >>> 5;
        // theBit = n % 32
        int theBit = n & 0x1F;
        int tester = 1 << theBit;
        return ((m_ints[theInt] & tester) != 0);
    }

    public void flipBit(int n)
    {
        // theInt = n / 32
        int theInt = n >>> 5;
        // theBit = n % 32
        int theBit = n & 0x1F;
        int flipper = 1 << theBit;
        m_ints[theInt] ^= flipper;
    }

    public void setBit(int n)
    {
        // theInt = n / 32
        int theInt = n >>> 5;
        // theBit = n % 32
        int theBit = n & 0x1F;
        int setter = 1 << theBit;
        m_ints[theInt] |= setter;
    }

    public void clearBit(int n)
    {
        // theInt = n / 32
        int theInt = n >>> 5;
        // theBit = n % 32
        int theBit = n & 0x1F;
        int setter = 1 << theBit;
        m_ints[theInt] &= ~setter;
    }

    /*
     * At the moment this is slower than multiply then reduce, but it ought to be possible to
     * improve this by reducing 'b' after each word, and only reducing a single extra word for 'c'
     * at the end.
     */
//    public IntArray modMult(IntArray other, int m, int[] ks)
//    {
//        int usedLen = getUsedLength();
//        if (usedLen == 0)
//        {
//            return new IntArray(1);
//        }
//
//        int mLen = (m + 31) >>> 5;
//        int t = Math.min(usedLen, mLen);
//
//        int bLen = other.getUsedLength() + 1;
//        IntArray b = new IntArray(other.resizedInts(bLen));
//        IntArray c = new IntArray(t + bLen);
//
//        for (int j = 0; j < t; ++j)
//        {
//            int w = m_ints[j];
//            int bits = j << 5;
//
//            for (int k = 0; k < 32; ++k)
//            {
//                if ((w & (1 << k)) != 0)
//                {
//                    c.addShiftedByBits(b, bits + k);
//                }
//            }
//        }
//
//        c.reduce(m, ks);
//
//        return c;
//    }

    public IntArray multiply(IntArray other, int m)
    {
        int usedLen = getUsedLength();
        if (usedLen == 0)
        {
            return new IntArray(1);
        }

        int mLen = (m + 31) >>> 5;
        int t = Math.min(usedLen, mLen);

        IntArray b = new IntArray(other.resizedInts(other.getUsedLength() + 1));
        IntArray c = new IntArray(t + b.getLength());

        int testBit = 1;
        for (;;)
        {
            for (int j = 0; j < t; j++)
            {
                if ((m_ints[j] & testBit) != 0)
                {
                    // The kth bit of m_ints[j] is set
                    c.addShiftedByWordsQuick(b, j);
                }
            }
            if ((testBit <<= 1) == 0)
            {
                break;
            }
            b.shiftLeftQuick();
        }
        return c;
    }

    // public IntArray multiplyLeftToRight(IntArray other, int m) {
    // // Lenght of c is 2m bits rounded up to the next int (32 bit)
    // int t = (m + 31) / 32;
    // if (m_ints.length < t) {
    // m_ints = resizedInts(t);
    // }
    //
    // IntArray b = new IntArray(other.resizedInts(other.getLength() + 1));
    // IntArray c = new IntArray((m + m + 31) / 32);
    // // IntArray c = new IntArray(t + t);
    // int testBit = 1 << 31;
    // for (int k = 31; k >= 0; k--) {
    // for (int j = 0; j < t; j++) {
    // if ((m_ints[j] & testBit) != 0) {
    // // The kth bit of m_ints[j] is set
    // c.addShifted(b, j);
    // }
    // }
    // testBit >>>= 1;
    // if (k > 0) {
    // c.shiftLeft();
    // }
    // }
    // return c;
    // }

    public void reduce(int m, int[] ks)
    {
        int len = getUsedLength();
        int mLen = (m + 31) >>> 5;
        if (len < mLen)
        {
            return;
        }

        int _2m = m << 1;
        int pos = Math.min(_2m - 2, (len << 5) - 1);

        int kMax = ks[ks.length - 1];
        if (kMax < m - 31)
        {
            reduceWordWise(pos, m, ks);
        }
        else
        {
            reduceBitWise(pos, m, ks);
        }

        // Instead of flipping the high bits in the loop, explicitly clear any partial word above m bits
        int partial = m & 31;
        if (partial != 0)
        {
            m_ints[mLen - 1] &= (1 << partial) - 1;
        }

        if (len > mLen)
        {
            m_ints = resizedInts(mLen);
        }
    }

    private void reduceBitWise(int from, int m, int[] ks)
    {
        for (int i = from; i >= m; --i)
        {
            if (testBit(i))
            {
//                clearBit(i);
                int bit = i - m;
                flipBit(bit);
                int j = ks.length;
                while (--j >= 0)
                {
                    flipBit(ks[j] + bit);
                }
            }
        }
    }

    private void reduceWordWise(int from, int m, int[] ks)
    {
        int pos = m + ((from - m) & ~31);
        for (int i = pos; i >= m; i -= 32)
        {
            int word = getWord(i);
            if (word != 0)
            {
//                flipWord(i);
                int bit = i - m;
                flipWord(bit, word);
                int j = ks.length;
                while (--j >= 0)
                {
                    flipWord(ks[j] + bit, word);
                }
            }
        }
    }

    public IntArray square(int m)
    {
        // TODO make the table static final
        final int[] table = { 0x0, 0x1, 0x4, 0x5, 0x10, 0x11, 0x14, 0x15, 0x40,
            0x41, 0x44, 0x45, 0x50, 0x51, 0x54, 0x55 };

        int mLen = (m + 31) >>> 5;
        if (m_ints.length < mLen)
        {
            m_ints = resizedInts(mLen);
        }

        IntArray c = new IntArray(mLen + mLen);

        // TODO twice the same code, put in separate private method
        for (int i = 0; i < mLen; i++)
        {
            int v0 = 0;
            for (int j = 0; j < 4; j++)
            {
                v0 = v0 >>> 8;
                int u = (m_ints[i] >>> (j * 4)) & 0xF;
                int w = table[u] << 24;
                v0 |= w;
            }
            c.m_ints[i + i] = v0;

            v0 = 0;
            int upper = m_ints[i] >>> 16;
            for (int j = 0; j < 4; j++)
            {
                v0 = v0 >>> 8;
                int u = (upper >>> (j * 4)) & 0xF;
                int w = table[u] << 24;
                v0 |= w;
            }
            c.m_ints[i + i + 1] = v0;
        }
        return c;
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof IntArray))
        {
            return false;
        }
        IntArray other = (IntArray) o;
        int usedLen = getUsedLength();
        if (other.getUsedLength() != usedLen)
        {
            return false;
        }
        for (int i = 0; i < usedLen; i++)
        {
            if (m_ints[i] != other.m_ints[i])
            {
                return false;
            }
        }
        return true;
    }

    public int hashCode()
    {
        int usedLen = getUsedLength();
        int hash = 1;
        for (int i = 0; i < usedLen; i++)
        {
            hash = hash * 31 + m_ints[i];
        }
        return hash;
    }

    public Object clone()
    {
        return new IntArray(Arrays.clone(m_ints));
    }

    public String toString()
    {
        int i = getUsedLength();
        if (i == 0)
        {
            return "0";
        }

        StringBuffer sb = new StringBuffer(Integer.toBinaryString(m_ints[--i]));
        while (--i >= 0)
        {
            String s = Integer.toBinaryString(m_ints[i]);

            // Add leading zeroes, except for highest significant word
            int len = s.length();
            if (len < 32)
            {
                sb.append(ZEROES.substring(len));
            }

            sb.append(s);
        }
        return sb.toString();
    }
}