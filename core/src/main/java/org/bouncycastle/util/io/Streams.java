package org.bouncycastle.util.io;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;

/**
 * Utility methods to assist with stream processing.
 */
public final class Streams
{
    private static int BUFFER_SIZE = 4096;

    /**
     * Read stream till EOF is encountered.
     *
     * @param inStr stream to be emptied.
     * @throws IOException in case of underlying IOException.
     */
    public static void drain(InputStream inStr)
        throws IOException
    {
        byte[] bs = new byte[BUFFER_SIZE];
        while (inStr.read(bs, 0, bs.length) >= 0)
        {
        }
    }

    /**
     * Write the full contents of inStr to the destination stream outStr.
     *
     * @param inStr source input stream.
     * @param outStr destination output stream.
     * @throws IOException in case of underlying IOException.
     */
    public static void pipeAll(InputStream inStr, OutputStream outStr)
        throws IOException
    {
        pipeAll(inStr, outStr, BUFFER_SIZE);
    }

    /**
     * Write the full contents of inStr to the destination stream outStr.
     *
     * @param inStr source input stream.
     * @param outStr destination output stream.
     * @param bufferSize the size of temporary buffer to use.
     * @throws IOException in case of underlying IOException.
     */
    public static void pipeAll(InputStream inStr, OutputStream outStr, int bufferSize)
        throws IOException
    {
        byte[] bs = new byte[bufferSize];
        int numRead;
        while ((numRead = inStr.read(bs, 0, bs.length)) >= 0)
        {
            outStr.write(bs, 0, numRead);
        }
    }

    /**
     * Write up to limit bytes of data from inStr to the destination stream outStr.
     *
     * @param inStr source input stream.
     * @param limit the maximum number of bytes allowed to be read.
     * @param outStr destination output stream.
     * @throws IOException in case of underlying IOException, or if limit is reached on inStr still has data in it.
     */
    public static long pipeAllLimited(InputStream inStr, long limit, OutputStream outStr)
        throws IOException
    {
        long total = 0;
        byte[] bs = new byte[BUFFER_SIZE];
        int numRead;
        while ((numRead = inStr.read(bs, 0, bs.length)) >= 0)
        {
            if ((limit - total) < numRead)
            {
                throw new StreamOverflowException("Data Overflow");
            }
            total += numRead;
            outStr.write(bs, 0, numRead);
        }
        return total;
    }

    /**
     * Read stream fully, returning contents in a byte array.
     *
     * @param inStr stream to be read.
     * @return a byte array representing the contents of inStr.
     * @throws IOException in case of underlying IOException.
     */
    public static byte[] readAll(InputStream inStr)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        pipeAll(inStr, buf);
        return buf.toByteArray();
    }

    /**
     * Read from inStr up to a maximum number of bytes, throwing an exception if more the maximum amount
     * of requested data is available.
     *
     * @param inStr stream to be read.
     * @param limit maximum number of bytes that can be read.
     * @return a byte array representing the contents of inStr.
     * @throws IOException in case of underlying IOException, or if limit is reached on inStr still has data in it.
     */
    public static byte[] readAllLimited(InputStream inStr, int limit)
        throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        pipeAllLimited(inStr, limit, buf);
        return buf.toByteArray();
    }

    /**
     * Fully read in buf's length in data, or up to EOF, whichever occurs first,
     *
     * @param inStr the stream to be read.
     * @param buf the buffer to be read into.
     * @return the number of bytes read into the buffer.
     * @throws IOException in case of underlying IOException.
     */
    public static int readFully(InputStream inStr, byte[] buf)
        throws IOException
    {
        return readFully(inStr, buf, 0, buf.length);
    }

    /**
     * Fully read in len's bytes of data into buf, or up to EOF, whichever occurs first,
     *
     * @param inStr the stream to be read.
     * @param buf the buffer to be read into.
     * @param off offset into buf to start putting bytes into.
     * @param len  the number of bytes to be read.
     * @return the number of bytes read into the buffer.
     * @throws IOException in case of underlying IOException.
     */
    public static int readFully(InputStream inStr, byte[] buf, int off, int len)
        throws IOException
    {
        int totalRead = 0;
        while (totalRead < len)
        {
            int numRead = inStr.read(buf, off + totalRead, len - totalRead);
            if (numRead < 0)
            {
                break;
            }
            totalRead += numRead;
        }

        return totalRead;
    }

    /**
     * Read exactly {@code len} bytes from {@code inStr} and return them as a newly allocated array.
     * <p>
     * Unlike {@code new byte[len]} followed by {@link #readFully(InputStream, byte[])}, the returned
     * array is grown incrementally as data arrives rather than allocated at the full declared length
     * up front. A caller passing an untrusted (possibly hostile) length therefore cannot drive a large
     * allocation from a short input - the allocation tracks the bytes the stream actually delivers, and
     * a stream that ends before {@code len} bytes have been read fails with an {@link EOFException}.
     *
     * @param inStr the stream to read from.
     * @param len   the exact number of bytes to read.
     * @return a {@code byte[len]} containing the bytes read.
     * @throws EOFException if the stream ends before {@code len} bytes are available.
     * @throws IOException  on an underlying read error.
     * @throws IllegalArgumentException if {@code len} is negative.
     */
    public static byte[] readLenBytesFully(InputStream inStr, int len)
        throws IOException
    {
        if (len < 0)
        {
            throw new IllegalArgumentException("len cannot be negative");
        }

        // Start with a bounded buffer and grow it towards len (doubling) as bytes actually arrive,
        // reading straight into the result rather than allocating new byte[len] up front. A hostile
        // len therefore cannot drive a large allocation from a short input, and a small len still
        // allocates its exact size once.
        byte[] bytes = new byte[Math.min(len, BUFFER_SIZE)];
        int count = 0;
        while (count < len)
        {
            if (count == bytes.length)
            {
                int expandedLength = (int)Math.min((long)len, 8L * bytes.length);
                byte[] expanded = new byte[expandedLength];
                System.arraycopy(bytes, 0, expanded, 0, count);
                bytes = expanded;
            }

            int numRead = inStr.read(bytes, count, bytes.length - count);
            if (numRead < 0)
            {
                throw new EOFException("premature end of stream");
            }
            count += numRead;
        }

        return bytes;
    }

    public static void validateBufferArguments(byte[] buf, int off, int len)
    {
        Arrays.validateSegment(buf, off, len);
    }

    public static void writeBufTo(ByteArrayOutputStream buf, OutputStream output)
        throws IOException
    {
        buf.writeTo(output);
    }
}
