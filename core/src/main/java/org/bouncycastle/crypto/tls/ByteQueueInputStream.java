package org.bouncycastle.crypto.tls;

import java.io.InputStream;

public class ByteQueueInputStream extends InputStream
{

    private ByteQueue buffer;
    
    public ByteQueueInputStream()
    {
        buffer = new ByteQueue();
    }
    
    public void addBytes(byte[] bytes)
    {
        buffer.addData(bytes, 0, bytes.length);
    }
    
    public int peek(byte[] buf)
    {
        int bytesToRead = Math.min(buffer.available(), buf.length);
        buffer.read(buf, 0, bytesToRead, 0);
        return bytesToRead;
    }
    
    @Override
    public int read()
    {
        if (buffer.available() == 0)
        {
            return -1;
        }
        return buffer.removeData(1, 0)[0] & 0xFF;
    }

    @Override
    public int read(byte[] b)
    {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte[] b, int off, int len)
    {
        int bytesToRead = Math.min(buffer.available(), len);
        buffer.removeData(b, off, bytesToRead, 0);
        return bytesToRead;
    }

    @Override
    public long skip(long n)
    {
        int bytesToRemove = Math.min((int) n, buffer.available());
        buffer.removeData(bytesToRemove);
        return bytesToRemove;
    }

    @Override
    public int available()
    {
        return buffer.available();
    }

    @Override
    public void close()
    {
    }

}
