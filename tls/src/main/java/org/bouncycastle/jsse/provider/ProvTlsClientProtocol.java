package org.bouncycastle.jsse.provider;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.TlsClientProtocol;

class ProvTlsClientProtocol extends TlsClientProtocol
{
    private final Closeable closeable;

    ProvTlsClientProtocol(InputStream input, OutputStream output, Closeable closeable)
    {
        super(input, output);

        this.closeable = closeable;
    }

    @Override
    protected void closeConnection() throws IOException
    {
        closeable.close();
    }
}
