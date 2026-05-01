package org.bouncycastle.openpgp.api;

import java.io.IOException;
import java.io.InputStream;

/**
 * Implementation of an {@link InputStream} that double-buffers data from an underlying input stream.
 * Upon reaching the end of the underlying data stream, the underlying data stream is
 * automatically closed.
 * Any exceptions while reading from the underlying input stream cause the {@link DoubleBufferedInputStream}
 * to withhold pending data.
 * This is done in order to minimize the risk of emitting unauthenticated plaintext, while at the same
 * time being somewhat resource-efficient.
 * The minimum number of bytes to withhold can be configured ({@link #BUFFER_SIZE} by default).
 */
public class DoubleBufferedInputStream<I extends InputStream>
    extends InputStream
{
    private static final int BUFFER_SIZE = 1024 * 1024 * 32; // 32 MiB
    private byte[] buf1;
    private byte[] buf2;
    private int b1Pos;
    private int b1Max;
    private int b2Max;
    private final I in;
    private boolean closed = false;

    /**
     * Create a {@link DoubleBufferedInputStream}, which buffers twice 32MiB.
     *
     * @param in input stream
     */
    public DoubleBufferedInputStream(I in)
    {
        this(in, BUFFER_SIZE);
    }

    /**
     * Create a {@link DoubleBufferedInputStream}, which buffers twice the given buffer size in bytes.
     *
     * @param in         input stream
     * @param bufferSize buffer size
     */
    public DoubleBufferedInputStream(I in, int bufferSize)
    {
        if (bufferSize <= 0)
        {
            throw new IllegalArgumentException("Buffer size cannot be zero nor negative.");
        }
        this.buf1 = new byte[bufferSize];
        this.buf2 = new byte[bufferSize];
        this.in = in;
        b1Pos = -1; // indicate to fill() that we need to initialize
    }

    /**
     * Return the underlying {@link InputStream}.
     *
     * @return underlying input stream
     */
    public I getInputStream()
    {
        return in;
    }

    /**
     * Buffer some data from the underlying {@link InputStream}.
     *
     * @throws IOException re-throw exceptions from the underlying input stream
     */
    private void fill()
        throws IOException
    {
        // init
        if (b1Pos == -1)
        {
            // fill both buffers with data
            b1Max = in.read(buf1);
            b2Max = in.read(buf2);

            if (b2Max == -1)
            {
                // data fits into b1 -> close underlying stream
                close();
            }

            b1Pos = 0;
            return;
        }

        // no data
        if (b1Max <= 0)
        {
            return;
        }

        // Reached end of buf1
        if (b1Pos == b1Max)
        {
            // swap buffers
            byte[] t = buf1;
            buf1 = buf2;
            buf2 = t;
            b1Max = b2Max;

            // reset reader pos
            b1Pos = 0;

            // fill buf2
            try
            {
                b2Max = in.read(buf2);
                // could not fill the buffer, or swallowed an IOException
                if (b2Max != buf2.length)
                {
                    // provoke the IOException otherwise swallowed by read(buf)
                    int i = in.read();
                    // no exception was thrown, so either data became available, or EOF
                    if (i != -1)
                    {
                        // data became available, push to buf2
                        buf2[b2Max++] = (byte)i;
                    }
                }
            }
            catch (IOException e)
            {
                // set buffer max's to -1 to indicate to stop emitting data immediately
                b1Max = -1;
                b2Max = -1;
                close();

                throw e;
            }

            // EOF
            if (b2Max == -1)
            {
                close();
            }
        }
    }

    @Override
    public void close()
        throws IOException
    {
        // close the inner stream only once
        if (!closed)
        {
            closed = true;
            in.close();
        }
    }

    @Override
    public int read()
        throws IOException
    {
        // fill the buffer(s)
        fill();

        // EOF / exception?
        if (b1Max == -1)
        {
            close();
            return -1;
        }

        // return byte from the buffer
        return buf1[b1Pos++];
    }

    @Override
    public int read(byte[] b, int off, int len)
        throws IOException
    {
        // Fill the buffer(s)
        fill();

        // EOF / exception?
        if (b1Max == -1)
        {
            close();
            return -1;
        }

        int ret = Math.min(b1Max - b1Pos, len);
        // emit data from the buffer
        System.arraycopy(buf1, b1Pos, b, off, ret);
        b1Pos += ret;
        return ret;
    }
}
