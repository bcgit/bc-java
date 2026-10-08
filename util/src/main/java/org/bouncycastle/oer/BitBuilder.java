package org.bouncycastle.oer;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

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
        Arrays.fill(buf, 0, l, (byte)0); // octets from l on were never written
        pos = 0;
        return l;
    }


    /** Advance to the next octet boundary without writing; the skipped bits are already zero. */
    public void pad()
    {
        pos = (pos + 7) & ~7;
    }


    /**
     * Write {@code value} as the subsequent octets of a CHOICE tag, X.696 sec. 8.7.2.3: seven bits
     * per octet, most significant group first, in the fewest octets that hold the value (so the
     * first group is never all zero), with bit 8 set on every octet but the last. A negative
     * argument is taken as its unsigned 32-bit value.
     */
    public void write7BitBytes(int value)
    {
        int groups = Math.max(1, (Integers.bitLength(value) + 6) / 7);
        for (int i = groups - 1; i >= 0; i--)
        {
            writeBit(i).writeBits(value >>> (7 * i), 7);
        }
    }

    /**
     * As {@link #write7BitBytes(int)}, for a non-negative value of any size.
     */
    public void write7BitBytes(BigInteger value)
    {
        int groups = Math.max(1, (value.bitLength() + 6) / 7);
        for (int i = groups - 1; i >= 0; i--)
        {
            writeBit(i).writeBits(value.shiftRight(7 * i).intValue(), 7);
        }
    }

    public void zero()
    {
        Arrays.clear(buf);
        pos = 0;
    }
}
