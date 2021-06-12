package org.bouncycastle.jsse.provider;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.RenegotiationPolicy;
import org.bouncycastle.tls.TlsClientProtocol;

class ProvTlsClientProtocol extends TlsClientProtocol
{
    private static final boolean provAcceptRenegotiation = PropertyUtils.getBooleanSystemProperty(
        "org.bouncycastle.jsse.client.acceptRenegotiation", false);

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

    @Override
    protected int getRenegotiationPolicy()
    {
        return provAcceptRenegotiation ? RenegotiationPolicy.ACCEPT : RenegotiationPolicy.DENY;
    }
}
