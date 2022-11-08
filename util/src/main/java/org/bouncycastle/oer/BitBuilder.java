package org.bouncycastle.oer;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

public class BitBuilder
{
    private static final byte[] bits = new byte[]{(byte)128, 64, 32, 16, 8, 4, 2, 1};


    byte[] buf = new byte[1];
    int pos = 0;

    /**
     * write a bit
     *
     * @param bit where 0 = 0 bit and not zero is 1 bit.
     * @return
     */
    public BitBuilder writeBit(int bit)
    {

        if (pos / 8 >= buf.length)
        {
            byte[] newBytes = new byte[buf.length + 4];
            System.arraycopy(buf, 0, newBytes, 0, pos / 8);
            Arrays.clear(buf);
            buf = newBytes;
        }

        if (bit == 0)
        {
            buf[pos / 8] &= ~bits[pos % 8];
        }
        else
        {
            buf[pos / 8] |= bits[pos % 8];
        }
        pos++;

        return this;
    }

    public BitBuilder writeBits(long value, int start)
    {

        for (int p = start - 1; p >= 0; p--)
        {
            int set = (value & (1L << p)) > 0 ? 1 : 0;
            writeBit(set);
        }

        return this;
    }

    public BitBuilder writeBits(long value, int start, int len)
    {

        for (int p = start - 1; p >= start - len; p--)
        {
            int set = (value & (1L << p)) != 0 ? 1 : 0;
            writeBit(set);
        }

        return this;
    }


    public int write(OutputStream outputStream)
        throws IOException
    {

        int l = (pos + (pos % 8)) / 8;
        outputStream.write(buf, 0, l);
        outputStream.flush();
        return l;
    }

    public int writeAndClear(OutputStream outputStream)
        throws IOException
    {

        int l = (pos + (pos % 8)) / 8;
        outputStream.write(buf, 0, l);
        outputStream.flush();
        zero();
        return l;
    }


    public void pad()
    {
        pos = pos + pos % 8;
    }


    public void write7BitBytes(int value)
    {

        // Skip leading zero bytes.
        boolean writing = false;
        for (int t = 4; t >= 0; t--)
        {
            if (!writing && (value & 0xFE000000) != 0)
            {
                writing = true;
            }
            if (writing)
            {
                writeBit(t).writeBits(value, 32, 7);
            }
            value <<= 7;
        }
    }

    public void write7BitBytes(BigInteger value)
    {
        int size = ((value.bitLength() + value.bitLength() % 8) / 8);
        BigInteger mask = BigInteger.valueOf(0xFE).shiftLeft(size * 8);


        // Skip leading zero bytes.
        boolean writing = false;
        for (int t = size; t >= 0; t--)
        {
            if (!writing && (value.and(mask)).compareTo(BigInteger.ZERO) != 0)
            {
                writing = true;
            }
            if (writing)
            {
                BigInteger b = value.and(mask).shiftRight(8 * size - 8);
                writeBit(t).writeBits(b.intValue(), 8, 7);
            }
            value = value.shiftLeft(7);
        }
    }

    public void zero()
    {
        Arrays.clear(buf);
        pos = 0;
    }
}
