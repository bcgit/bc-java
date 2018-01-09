package org.bouncycastle.jsse.provider;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.TlsServerProtocol;

class ProvTlsServerProtocol extends TlsServerProtocol
{
    private final Closeable closeable;

    ProvTlsServerProtocol(InputStream input, OutputStream output, Closeable closeable)
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
