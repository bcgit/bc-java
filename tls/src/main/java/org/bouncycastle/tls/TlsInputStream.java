package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;

/**
 * An InputStream for a TLS connection.
 */
class TlsInputStream extends InputStream
{
    private final TlsProtocol handler;

    TlsInputStream(TlsProtocol handler)
    {
        this.handler = handler;
    }

    public int read() throws IOException
    {
        byte[] buf = new byte[1];
        int ret = read(buf, 0, 1);
        return ret <= 0 ? -1 : buf[0] & 0xFF;
    }

    public int read(byte[] buf, int offset, int len) throws IOException
    {
        return handler.readApplicationData(buf, offset, len);
    }

    public int available() throws IOException
    {
        return handler.applicationDataAvailable();
    }

    public void close() throws IOException
    {
        handler.close();
    }
}
