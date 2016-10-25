package org.bouncycastle.tls.test;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Tracks and enforces close() calls, without closing the underlying InputStream
 */
class NetworkInputStream extends FilterInputStream
{
    boolean closed = false;

    public NetworkInputStream(InputStream input)
    {
        super(input);
    }

    synchronized boolean isClosed()
    {
        return closed;
    }

    public int available() throws IOException
    {
        checkNotClosed();
        return in.available();
    }

    public synchronized void close() throws IOException
    {
        closed = true;
    }

    public int read() throws IOException
    {
        checkNotClosed();
        return in.read();
    }

    public int read(byte[] b) throws IOException
    {
        checkNotClosed();
        return in.read(b);
    }

    public int read(byte[] b, int off, int len) throws IOException
    {
        checkNotClosed();
        return in.read(b, off, len);
    }

    protected synchronized void checkNotClosed() throws IOException
    {
        if (closed)
        {
            throw new IOException("NetworkInputStream closed");
        }
    }
}