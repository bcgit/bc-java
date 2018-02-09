package org.bouncycastle.tls;

import java.io.InputStream;

/**
 * InputStream based on a ByteQueue implementation.
 */
public class ByteQueueInputStream
    extends InputStream
{
    private ByteQueue buffer;

    public ByteQueueInputStream()
    {
        buffer = new ByteQueue();
    }

    public void addBytes(byte[] buf)
    {
        buffer.addData(buf, 0, buf.length);
    }

    public void addBytes(byte[] buf, int bufOff, int bufLen)
    {
        buffer.addData(buf, bufOff, bufLen);
    }

    public int peek(byte[] buf)
    {
        int bytesToRead = Math.min(buffer.available(), buf.length);
        buffer.read(buf, 0, bytesToRead, 0);
        return bytesToRead;
    }

    public int read()
    {
        if (buffer.available() == 0)
        {
            return -1;
        }
        return buffer.removeData(1, 0)[0] & 0xFF;
    }

    public int read(byte[] b)
    {
        return read(b, 0, b.length);
    }

    public int read(byte[] b, int off, int len)
    {
        int bytesToRead = Math.min(buffer.available(), len);
        buffer.removeData(b, off, bytesToRead, 0);
        return bytesToRead;
    }

    public long skip(long n)
    {
        int bytesToRemove = Math.min((int)n, buffer.available());
        buffer.removeData(bytesToRemove);
        return bytesToRemove;
    }

    public int available()
    {
        return buffer.available();
    }

    public void close()
    {
    }
}
