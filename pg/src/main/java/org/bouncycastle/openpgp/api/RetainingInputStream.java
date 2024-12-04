package org.bouncycastle.openpgp.api;

import java.io.IOException;
import java.io.InputStream;

/**
 * Implementation of {@link InputStream} that withholds a number of bytes from the end of the original
 * message until the message has been processed entirely.
 * Furthermore, upon reaching the end of the underlying data stream, the underlying data stream is
 * automatically closed.
 * This is done in order to minimize the risk of emitting unauthenticated plaintext, while at the same
 * time being somewhat resource-efficient.
 * The number of bytes to withhold can be configured ({@link #CIRCULAR_BUFFER_SIZE} by default).
 */
public class RetainingInputStream<I extends InputStream>
        extends InputStream
{
    private static final int CIRCULAR_BUFFER_SIZE = 1024 * 1024 * 32; // 32 MiB

    private final byte[] circularBuffer;
    private int lastWrittenPos = 0;
    private int bufReadPos = 0;
    private final I in;
    private boolean closed = false;

    public RetainingInputStream(I in)
    {
        this(in, CIRCULAR_BUFFER_SIZE);
    }

    public RetainingInputStream(I in, int bufferSize)
    {
        if (bufferSize <= 0)
        {
            throw new IllegalArgumentException("Buffer size cannot be null nor negative.");
        }
        this.circularBuffer = new byte[bufferSize];
        this.in = in;
    }

    public I getInputStream()
    {
        return in;
    }

    private void fill()
            throws IOException
    {
        if (closed)
        {
            return;
        }

        // readerPos - 1 % buf.len
        int lastAvailPos = (circularBuffer.length + bufReadPos - 1) % circularBuffer.length;
        int read;
        if (lastWrittenPos < lastAvailPos)
        {
            read = in.read(circularBuffer, lastWrittenPos, lastAvailPos - lastWrittenPos);
        }
        else
        {
            read = in.read(circularBuffer, lastWrittenPos, circularBuffer.length - lastWrittenPos);
            if (read >= 0)
            {
                lastWrittenPos += read;
            }
            read = in.read(circularBuffer, 0, lastAvailPos);
        }

        if (read >= 0)
        {
            lastWrittenPos += read;
        }
        else
        {
            close();
        }

        lastWrittenPos %= circularBuffer.length;
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
        fill();
        if (bufReadPos == lastWrittenPos)
        {
            return -1;
        }
        int i = circularBuffer[bufReadPos++];
        bufReadPos %= circularBuffer.length;
        return i;
    }
}
