package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;

/**
 * An OutputStream for a TLS connection.
 */
class TlsOutputStream extends OutputStream
{
    private final TlsProtocol handler;

    TlsOutputStream(TlsProtocol handler)
    {
        this.handler = handler;
    }

    public void write(int b) throws IOException
    {
        write(new byte[]{ (byte)b }, 0, 1);
    }

    public void write(byte buf[], int offset, int len) throws IOException
    {
        handler.writeApplicationData(buf, offset, len);
    }

    public void close() throws IOException
    {
        handler.close();
    }
}
