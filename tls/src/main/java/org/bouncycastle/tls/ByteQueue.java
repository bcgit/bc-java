package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A queue for bytes. This file could be more optimized.
 */
public class ByteQueue
{
    /**
     * @return The smallest number which can be written as 2^x which is bigger than i.
     */
    public static int nextTwoPow(int i)
    {
        /*
         * This code is based of a lot of code I found on the Internet which mostly
         * referenced a book called "Hacking delight".
         */
        i |= (i >> 1);
        i |= (i >> 2);
        i |= (i >> 4);
        i |= (i >> 8);
        i |= (i >> 16);
        return i + 1;
    }

    /**
     * The buffer where we store our data.
     */
    private byte[] databuf;

    /**
     * How many bytes at the beginning of the buffer are skipped.
     */
    private int skipped = 0;

    /**
     * How many bytes in the buffer are valid data.
     */
    private int available = 0;

    private boolean readOnlyBuf = false;

    public ByteQueue()
    {
        this(0);
    }

    public ByteQueue(int capacity)
    {
        databuf = capacity == 0 ? TlsUtils.EMPTY_BYTES : new byte[capacity];
    }

    public ByteQueue(byte[] buf, int off, int len)
    {
        this.databuf = buf;
        this.skipped = off;
        this.available = len;
        this.readOnlyBuf = true;
    }

    /**
     * Add some data to our buffer.
     *
     * @param buf A byte-array to read data from.
     * @param off How many bytes to skip at the beginning of the array.
     * @param len How many bytes to read from the array.
     */
    public void addData(byte[] buf, int off, int len)
    {
        if (readOnlyBuf)
        {
            throw new IllegalStateException("Cannot add data to read-only buffer");
        }

        if ((skipped + available + len) > databuf.length)
        {
            int desiredSize = ByteQueue.nextTwoPow(available + len);
            if (desiredSize > databuf.length)
            {
                byte[] tmp = new byte[desiredSize];
                System.arraycopy(databuf, skipped, tmp, 0, available);
                databuf = tmp;
            }
            else
            {
                System.arraycopy(databuf, skipped, databuf, 0, available);
            }
            skipped = 0;
        }

        System.arraycopy(buf, off, databuf, skipped + available, len);
        available += len;
    }

    /**
     * @return The number of bytes which are available in this buffer.
     */
    public int available()
    {
        return available;
    }

    /**
     * Copy some bytes from the beginning of the data to the provided {@link OutputStream}.
     *
     * @param output The {@link OutputStream} to copy the bytes to.
     * @param length How many bytes to copy.
     */
    public void copyTo(OutputStream output, int length) throws IOException
    {
        if (length > available)
        {
            throw new IllegalStateException("Cannot copy " + length + " bytes, only got " + available);
        }

        output.write(databuf, skipped, length);
    }

    /**
     * Read data from the buffer.
     *
     * @param buf    The buffer where the read data will be copied to.
     * @param offset How many bytes to skip at the beginning of buf.
     * @param len    How many bytes to read at all.
     * @param skip   How many bytes from our data to skip.
     */
    public void read(byte[] buf, int offset, int len, int skip)
    {
        if ((buf.length - offset) < len)
        {
            throw new IllegalArgumentException("Buffer size of " + buf.length
                + " is too small for a read of " + len + " bytes");
        }
        if ((available - skip) < len)
        {
            throw new IllegalStateException("Not enough data to read");
        }
        System.arraycopy(databuf, skipped + skip, buf, offset, len);
    }

    /**
     * Return a {@link HandshakeMessageInput} over some bytes at the beginning of the data.
     * 
     * @param length
     *            How many bytes will be readable.
     * @return A {@link HandshakeMessageInput} over the data.
     */
    public HandshakeMessageInput readHandshakeMessage(int length)
    {
        if (length > available)
        {
            throw new IllegalStateException("Cannot read " + length + " bytes, only got " + available);
        }

        int position = skipped;

        available -= length;
        skipped += length;

        return new HandshakeMessageInput(databuf, position, length);
    }

    public int readInt32()
    {
        if (available < 4)
        {
            throw new IllegalStateException("Not enough data to read");
        }
        return TlsUtils.readInt32(databuf, skipped);
    }

    /**
     * Remove some bytes from our data from the beginning.
     *
     * @param i How many bytes to remove.
     */
    public void removeData(int i)
    {
        if (i > available)
        {
            throw new IllegalStateException("Cannot remove " + i + " bytes, only got " + available);
        }

        /*
         * Skip the data.
         */
        available -= i;
        skipped += i;
    }

    /**
     * Remove data from the buffer.
     *
     * @param buf The buffer where the removed data will be copied to.
     * @param off How many bytes to skip at the beginning of buf.
     * @param len How many bytes to read at all.
     * @param skip How many bytes from our data to skip.
     */
    public void removeData(byte[] buf, int off, int len, int skip)
    {
        read(buf, off, len, skip);
        removeData(skip + len);
    }

    public byte[] removeData(int len, int skip)
    {
        byte[] buf = new byte[len];
        removeData(buf, 0, len, skip);
        return buf;
    }

    public void shrink()
    {
        if (available == 0)
        {
            databuf = TlsUtils.EMPTY_BYTES;
            skipped = 0;
        }
        else
        {
            int desiredSize = ByteQueue.nextTwoPow(available);
            if (desiredSize < databuf.length)
            {
                byte[] tmp = new byte[desiredSize];
                System.arraycopy(databuf, skipped, tmp, 0, available);
                databuf = tmp;
                skipped = 0;
            }
        }
    }
}
