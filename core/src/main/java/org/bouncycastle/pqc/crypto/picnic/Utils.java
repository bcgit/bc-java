package org.bouncycastle.pqc.crypto.picnic;

class Utils
{
    protected static int numBytes(int numBits)
    {
        return (numBits == 0) ? 0 : ((numBits - 1) / 8 + 1);
    }

    protected static int ceil_log2(int x)
    {
        if (x == 0)
        {
            return 0;
        }
        return 32 - nlz(x - 1);
    }

    private static int nlz(int x)
    {
        int n;

        if (x == 0)
        {
            return (32);
        }
        n = 1;
        if((x >>> 16) == 0)
        {
            n = n + 16; x = x << 16;
        }
        if ((x >>> 24) == 0)
        {
            n = n + 8;
            x = x << 8;
        }
        if ((x >>> 28) == 0)
        {
            n = n + 4;
            x = x << 4;
        }
        if ((x >>> 30) == 0)
        {
            n = n + 2;
            x = x << 2;
        }
        n = n - (x >>> 31);

        return n;
    }


    protected static int parity(byte[] data, int len)
    {
        byte x = data[0];

        for (int i = 1; i < len; i++)
        {
            x ^= data[i];
        }

        /* Compute parity of x using code from Section 5-2 of
         * H.S. Warren, *Hacker's Delight*, Pearson Education, 2003.
         * https://www.hackersdelight.org/hdcodetxt/parity.c.txt
         */
        int y = x ^ (x >>> 1);
        y ^= (y >>> 2);
        y ^= (y >>> 4);
        y ^= (y >>> 8);
        y ^= (y >>> 16);
        return y & 1;
    }

    protected static int parity16(int x)
    {
        int y = x ^ (x >>> 1);

        y ^= (y >>> 2);
        y ^= (y >>> 4);
        y ^= (y >>> 8);
        return y & 1;
    }

    protected static int parity32(int x)
    {
        /* Compute parity of x using code from Section 5-2 of
         * H.S. Warren, *Hacker's Delight*, Pearson Education, 2003.
         * https://www.hackersdelight.org/hdcodetxt/parity.c.txt
         */
        int y = (x ^ (x >>> 1));
        y ^= (y >>> 2);
        y ^= (y >>> 4);
        y ^= (y >>> 8);
        y ^= (y >>> 16);
        return (y & 1);
    }


    /* Set a specific bit in a byte array to a given value */
    protected static void setBitInWordArray(int[] array, int bitNumber, int val)
    {
        setBit(array, bitNumber, val);
    }

    /* Get one bit from a 32-bit int array */
    protected static int getBitFromWordArray(int[] array, int bitNumber)
    {
        return getBit(array, bitNumber);
    }

    /* Get one bit from a byte array */
    protected static byte getBit(byte[] array, int bitNumber)
    {
        int arrayPos = bitNumber >>> 3, bitPos = (bitNumber & 7) ^ 7;
        return (byte)((array[arrayPos] >>> bitPos) & 1);
    }

    protected static int getBit(int word, int bitNumber)
    {
        int bitPos = bitNumber ^ 7;
        return (word >>> bitPos) & 1;
    }

    /* Get one bit from a byte array */
    protected static int getBit(int[] array, int bitNumber)
    {
        int arrayPos = bitNumber >>> 5, bitPos = (bitNumber & 31) ^ 7;
        return (array[arrayPos] >>> bitPos) & 1;
    }

    protected static void setBit(byte[] array, int bitNumber, byte val)
    {
        int arrayPos = bitNumber >>> 3, bitPos = (bitNumber & 7) ^ 7;
        int t = array[arrayPos];
        t &= ~(1 << bitPos);
        t |= (int)val << bitPos;
        array[arrayPos] = (byte)t;
    }

    protected static int setBit(int word, int bitNumber, int bit)
    {
        int bitPos = bitNumber ^ 7;
        word &= ~(1 << bitPos);
        word |= bit << bitPos;
        return word;
    }

    /* Set a specific bit in a int array to a given value */
    protected static void setBit(int[] array, int bitNumber, int val)
    {
        int arrayPos = bitNumber >>> 5, bitPos = (bitNumber & 31) ^ 7;
        int t = array[arrayPos];
        t &= ~(1 << bitPos);
        t |= val << bitPos;
        array[arrayPos] = t;
    }
}
