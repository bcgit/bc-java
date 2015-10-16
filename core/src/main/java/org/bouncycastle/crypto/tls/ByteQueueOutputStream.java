package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.crypto.tls.ByteQueue;

public class ByteQueueOutputStream
    extends OutputStream
{
    private ByteQueue buffer;

    public ByteQueueOutputStream()
    {
        buffer = new ByteQueue();
    }

    public ByteQueue getBuffer()
    {
        return buffer;
    }

    public void write(int b) throws IOException
    {
        buffer.addData(new byte[]{ (byte)b }, 0, 1);
    }

    public void write(byte[] b, int off, int len) throws IOException
    {
        buffer.addData(b, off, len);
    }
}
