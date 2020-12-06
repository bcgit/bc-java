package org.bouncycastle.tls.test;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Tracks and enforces close() calls, without closing the underlying OutputStream
 */
class NetworkOutputStream extends FilterOutputStream
{
    boolean closed = false;

    public NetworkOutputStream(OutputStream output)
    {
        super(output);
    }

    synchronized boolean isClosed()
    {
        return closed;
    }

    public synchronized void close() throws IOException
    {
        closed = true;
        out.close();
    }

    public void write(int b) throws IOException
    {
        checkNotClosed();
        out.write(b);
    }

    public void write(byte[] b) throws IOException
    {
        checkNotClosed();
        out.write(b);
    }

    public void write(byte[] b, int off, int len) throws IOException
    {
        checkNotClosed();
        out.write(b, off, len);
    }

    protected synchronized void checkNotClosed() throws IOException
    {
        if (closed)
        {
            throw new IOException("NetworkOutputStream closed");
        }
    }
}
