package org.bouncycastle.jsse.provider;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.RenegotiationPolicy;
import org.bouncycastle.tls.TlsServerProtocol;

class ProvTlsServerProtocol extends TlsServerProtocol
{
    private final Closeable closeable;
    private final int renegotiationPolicy;
    private final boolean deferHandshake;

    /**
     * Blocking mode (for the {@link ProvSSLSocketBase SSLSocket} implementations).
     */
    ProvTlsServerProtocol(InputStream input, OutputStream output, Closeable closeable)
    {
        super(input, output);

        this.closeable = closeable;
        // NOTE: BCJSSE servers refuse client-initiated renegotiation (there is no server-side property)
        this.renegotiationPolicy = RenegotiationPolicy.DENY;
        this.deferHandshake = false;
    }

    /**
     * Non-blocking mode (for {@link ProvSSLEngine}, which does not support renegotiation).
     *
     * @param deferHandshake whether handshake steps are deferred for the engine to hand out as delegated tasks.
     */
    ProvTlsServerProtocol(boolean deferHandshake)
    {
        super();

        this.closeable = null;
        this.renegotiationPolicy = RenegotiationPolicy.DENY;
        this.deferHandshake = deferHandshake;
    }

    @Override
    protected void closeConnection() throws IOException
    {
        if (null == closeable)
        {
            super.closeConnection();
        }
        else
        {
            closeable.close();
        }
    }

    @Override
    protected int getRenegotiationPolicy()
    {
        return renegotiationPolicy;
    }

    @Override
    protected boolean shouldDeferHandshakeMessage(short handshakeType)
    {
        // Post-handshake messages (KeyUpdate) are cheap and handled inline
        return deferHandshake && isHandshaking();
    }
}
