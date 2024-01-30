package org.bouncycastle.util.io;

import java.io.OutputStream;

public class LimitedBuffer extends OutputStream
{
    private final byte[] buf;
    private int count;

    public LimitedBuffer(int limit)
    {
        buf = new byte[limit];
        count = 0;
    }

    public int copyTo(byte[] b, int off)
    {
        System.arraycopy(buf, 0, b, off, count);
        return count;
    }

    public int limit()
    {
        return buf.length;
    }

    public void reset()
    {
        count = 0;
    }

    public int size()
    {
        return count;
    }

    public void write(int b)
    {
        buf[count++] = (byte)b;
    }

    public void write(byte[] b)
    {
        System.arraycopy(b, 0, buf, count, b.length);
        count += b.length;
    }

    public void write(byte b[], int off, int len)
    {
        System.arraycopy(b, off, buf, count, len);
        count += len;
    }
}
