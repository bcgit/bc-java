package org.bouncycastle.math.ec;

import org.bouncycastle.util.Arrays;

import java.math.BigInteger;

class IntArray
{
    /*
     * This expands 8 bit indices into 16 bit contents, by inserting 0s between bits.
     * In a binary field, this operation is the same as squaring an 8 bit number.
     */
    private static final int[] EXPANSION_TABLE = new int[] { 0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014,
        0x0015, 0x0040, 0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055, 0x0100, 0x0101, 0x0104, 0x0105, 0x0110,
        0x0111, 0x0114, 0x0115, 0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155, 0x0400, 0x0401, 0x0404,
        0x0405, 0x0410, 0x0411, 0x0414, 0x0415, 0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455, 0x0500,
        0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515, 0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554,
        0x0555, 0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015, 0x1040, 0x1041, 0x1044, 0x1045, 0x1050,
        0x1051, 0x1054, 0x1055, 0x1100, 0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115, 0x1140, 0x1141, 0x1144,
        0x1145, 0x1150, 0x1151, 0x1154, 0x1155, 0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415, 0x1440,
        0x1441, 0x1444, 0x1445, 0x1450, 0x1451, 0x1454, 0x1455, 0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514,
        0x1515, 0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555, 0x4000, 0x4001, 0x4004, 0x4005, 0x4010,
        0x4011, 0x4014, 0x4015, 0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055, 0x4100, 0x4101, 0x4104,
        0x4105, 0x4110, 0x4111, 0x4114, 0x4115, 0x4140, 0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155, 0x4400,
        0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415, 0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454,
        0x4455, 0x4500, 0x4501, 0x4504, 0x4505, 0x4510, 0x4511, 0x4514, 0x4515, 0x4540, 0x4541, 0x4544, 0x4545, 0x4550,
        0x4551, 0x4554, 0x4555, 0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015, 0x5040, 0x5041, 0x5044,
        0x5045, 0x5050, 0x5051, 0x5054, 0x5055, 0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115, 0x5140,
        0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155, 0x5400, 0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414,
        0x5415, 0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455, 0x5500, 0x5501, 0x5504, 0x5505, 0x5510,
        0x5511, 0x5514, 0x5515, 0x5540, 0x5541, 0x5544, 0x5545, 0x5550, 0x5551, 0x5554, 0x5555 };

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
            m_ints[i] = (next << 1) | prev;
            prev = next >>> 31;
        }
    }

    private static int shiftLeftQuick(int[] x, int count)
    {
        int prev = 0;
        for (int i = 0; i < count; ++i)
        {
            int next = x[i];
            x[i] = (next << 1) | prev;
            prev = next >>> 31;
        }
        return prev;
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
        if (shift >= m_ints.length)
        {
            m_ints = resizedInts(shift + 1);
        }

        m_ints[shift] ^= 1;
    }

    public void addShiftedByBits(IntArray other, int bits)
    {
        int words = bits >>> 5;
        int shift = bits & 0x1F;

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
            m_ints[i + words] ^= (next << shift) | prev;
            prev = next >>> shiftInv;
        }
        m_ints[otherUsedLen + words] ^= prev;
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

    private void addShiftedByWordsQuick(int[] x, int xOff, int[] y, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            x[xOff + i] ^= y[i];
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
            int shift = bit & 0x1F;
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
        int shift = bit & 0x1F;
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

        int otherUsedLen = other.getUsedLength();
        if (otherUsedLen == 0)
        {
            return new IntArray(1);
        }

        int[] a = m_ints;
        int bLen = otherUsedLen + 1;
        int[] b = other.resizedInts(bLen);
        int[] c = new int[usedLen + otherUsedLen];

        int testBit = 1;
        for (;;)
        {
            for (int j = 0; j < usedLen; ++j)
            {
                // If the kth bit of a[j] is set...
                if ((a[j] & testBit) != 0)
                {
                    addShiftedByWordsQuick(c, j, b, bLen);
                }
            }
            if ((testBit <<= 1) == 0)
            {
                break;
            }

            shiftLeftQuick(b, bLen);
        }
        return new IntArray(c);
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
        int partial = m & 0x1F;
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
        int pos = m + ((from - m) & ~0x1F);
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
        int len = getUsedLength(), _2len = len << 1;
        int[] r = new int[_2len];

        int pos = 0;
        while (pos < _2len)
        {
            int mi = m_ints[pos >>> 1];
            r[pos++] = square16(mi & 0xFFFF);
            r[pos++] = square16(mi >>> 16);
        }

        return new IntArray(r);
    }

    private static int square16(int n)
    {
        return EXPANSION_TABLE[n & 0xFF] | EXPANSION_TABLE[n >>> 8] << 16;
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