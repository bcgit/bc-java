package org.bouncycastle.openpgp.api;

import java.io.IOException;
import java.io.InputStream;

/**
 * Implementation of {@link InputStream} double-buffers data from an underlying input stream.
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

    public DoubleBufferedInputStream(I in)
    {
        this(in, BUFFER_SIZE);
    }

    public DoubleBufferedInputStream(I in, int bufferSize)
    {
        if (bufferSize <= 0)
        {
            throw new IllegalArgumentException("Buffer size cannot be null nor negative.");
        }
        this.buf1 = new byte[bufferSize];
        this.buf2 = new byte[bufferSize];
        this.in = in;
        b1Pos = -1;
    }

    public I getInputStream()
    {
        return in;
    }

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
                        buf2[b2Max++] = (byte) i;
                    }
                }
            }
            catch (IOException e)
            {
                b1Max = -1;
                b2Max = -1;
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

        // EOF
        if (b1Max == -1)
        {
            close();
            return -1;
        }
        int i = buf1[b1Pos];
        b1Pos++;
        return i;
    }

    @Override
    public int read(byte[] b, int off, int len)
            throws IOException
    {
        // Fill the buffer(s)
        fill();

        // EOF
        if (b1Max == -1)
        {
            close();
            return -1;
        }
        // available bytes in b1
        int avail = b1Max - b1Pos;

        // math.min(avail, len)
        int ret = avail < len ? avail : len;

        // emit data
        System.arraycopy(buf1, b1Pos, b, off, ret);

        b1Pos += ret;
        return ret;
    }
}
