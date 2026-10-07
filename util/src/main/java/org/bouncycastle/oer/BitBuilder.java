package org.bouncycastle.oer;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

public class BitBuilder
{
    // a CHOICE tag, the one thing built here, is at most six octets (an int tag number is five
    // continuation octets), so 16 never grows in practice
    private byte[] buf = new byte[16];
    private int pos = 0;

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
            byte[] newBytes = new byte[buf.length * 2];
            System.arraycopy(buf, 0, newBytes, 0, pos / 8);
            Arrays.clear(buf);
            buf = newBytes;
        }

        if (bit == 0)
        {
            buf[pos / 8] &= ~(0x80 >>> (pos % 8));
        }
        else
        {
            buf[pos / 8] |= 0x80 >>> (pos % 8);
        }
        pos++;

        return this;
    }

    public BitBuilder writeBits(long value, int start)
    {

        for (int p = start - 1; p >= 0; p--)
        {
            writeBit((int)(value >>> p) & 1);
        }

        return this;
    }

    public BitBuilder writeBits(long value, int start, int len)
    {

        for (int p = start - 1; p >= start - len; p--)
        {
            writeBit((int)(value >>> p) & 1);
        }

        return this;
    }


    /**
     * Write the octets holding the bits so far, the last one padded with zero bits, and keep them.
     *
     * @deprecated the builder is left holding the octets it has just written, including a final octet
     * that further bits would go on filling, so a second write re-emits them; use
     * {@link #writeAndClear(OutputStream)}, which writes the same octets and resets the builder.
     */
    public int write(OutputStream outputStream)
        throws IOException
    {

        int l = (pos + 7) / 8; // the octets holding pos bits, the last one padded with zero bits
        outputStream.write(buf, 0, l);
        outputStream.flush();
        return l;
    }

    public int writeAndClear(OutputStream outputStream)
        throws IOException
    {

        int l = (pos + 7) / 8; // the octets holding pos bits, the last one padded with zero bits
        outputStream.write(buf, 0, l);
        outputStream.flush();
        zero();
        return l;
    }


    /** Advance to the next octet boundary without writing; the skipped bits are already zero. */
    public void pad()
    {
        pos = (pos + 7) & ~7;
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
            if (!writing && value.and(mask).signum() != 0)
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
