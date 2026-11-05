package org.bouncycastle.jsse.provider;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.tls.HandshakeMessageInput;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.RenegotiationPolicy;
import org.bouncycastle.tls.ServerHello;
import org.bouncycastle.tls.TlsClientProtocol;

class ProvTlsClientProtocol extends TlsClientProtocol
{
    private static final Logger LOG = Logger.getLogger(ProvTlsClientProtocol.class.getName());

    private static final boolean provAcceptRenegotiation = PropertyUtils.getBooleanSystemProperty(
        "org.bouncycastle.jsse.client.acceptRenegotiation", false);

    private final Closeable closeable;
    private final int renegotiationPolicy;
    private final boolean deferHandshake;

    /**
     * Blocking mode (for the {@link ProvSSLSocketBase SSLSocket} implementations).
     */
    ProvTlsClientProtocol(InputStream input, OutputStream output, Closeable closeable)
    {
        super(input, output);

        this.closeable = closeable;
        this.renegotiationPolicy = provAcceptRenegotiation ? RenegotiationPolicy.ACCEPT : RenegotiationPolicy.DENY;
        this.deferHandshake = false;
    }

    /**
     * Non-blocking mode (for {@link ProvSSLEngine}, which does not support renegotiation).
     *
     * @param deferHandshake whether handshake steps are deferred for the engine to hand out as delegated tasks.
     */
    ProvTlsClientProtocol(boolean deferHandshake)
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
    protected boolean shouldDeferClientHello()
    {
        return deferHandshake;
    }

    @Override
    protected boolean shouldDeferHandshakeMessage(short handshakeType)
    {
        // Post-handshake messages (KeyUpdate, NewSessionTicket, HelloRequest) are cheap and handled inline
        return deferHandshake && isHandshaking();
    }

    @Override
    protected int getRenegotiationPolicy()
    {
        return renegotiationPolicy;
    }

    @Override
    protected void handleHandshakeMessage(short type, HandshakeMessageInput buf) throws IOException
    {
        if (LOG.isLoggable(Level.FINEST))
        {
            int length = buf.available();
            LOG.finest(getClientID() + " inbound handshake message: " + HandshakeType.getText(type) + "[" + length + "]");
        }

        super.handleHandshakeMessage(type, buf);
    }

    @Override
    protected ServerHello receiveServerHelloMessage(ByteArrayInputStream buf) throws IOException
    {
        ServerHello serverHello = super.receiveServerHelloMessage(buf);

        if (LOG.isLoggable(Level.FINEST))
        {
            String title = getClientID() + " ServerHello extensions";
            LOG.finest(JsseUtils.getExtensionsReport(title, serverHello.getExtensions()));
        }

        return serverHello;
    }

    @Override
    protected void sendClientHelloMessage() throws IOException
    {
        if (LOG.isLoggable(Level.FINEST))
        {
            String title = getClientID() + " ClientHello extensions";
            LOG.finest(JsseUtils.getExtensionsReport(title, clientHello.getExtensions()));
        }

        super.sendClientHelloMessage();
    }

    private String getClientID()
    {
        return ((ProvTlsClient)tlsClient).getID();
    }
}
