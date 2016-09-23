package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServerProtocol;

class ProvSSLEngine
    extends SSLEngine
{
    protected final ProvSSLContextSpi context;

    protected boolean enableSessionCreation = false;
    protected boolean needClientAuth = false;
    protected boolean useClientMode = true;
    protected boolean wantClientAuth = false;

    protected boolean initialHandshakeBegun = false;

    ProvSSLEngine(ProvSSLContextSpi context)
    {
        this.context = context;
    }

    ProvSSLEngine(ProvSSLContextSpi context, String host, int port)
    {
        super(host, port);

        this.context = context;
    }

    @Override
    public synchronized void beginHandshake()
        throws SSLException
    {
        if (initialHandshakeBegun)
        {
            throw new UnsupportedOperationException("Renegotiation not supported");
        }

        this.initialHandshakeBegun = true;

        try
        {
            if (this.useClientMode)
            {
                ProvTlsClient client = new ProvTlsClient(context.getCrypto());
                TlsClientProtocol clientProtocol = new TlsClientProtocol();
                clientProtocol.connect(client);

                // TODO[tls-ops] Keep requesting task/unwrap/wrap until client.isHandshakeComplete() or error
            }
            else
            {
                ProvTlsServer server = new ProvTlsServer(context.getCrypto());
                TlsServerProtocol serverProtocol = new TlsServerProtocol();
                serverProtocol.accept(server);

                // TODO[tls-ops] Keep requesting task/unwrap/wrap until server.isHandshakeComplete() or error
            }
        }
        catch (IOException e)
        {
            throw new SSLException(e);
        }

        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized void closeInbound()
        throws SSLException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized void closeOutbound()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized Runnable getDelegatedTask()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized String[] getEnabledCipherSuites()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized String[] getEnabledProtocols()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized boolean getEnableSessionCreation()
    {
        return enableSessionCreation;
    }

//    @Override
//    public synchronized SSLSession getHandshakeSession()
//    {
//        return super.getHandshakeSession();
//    }

    @Override
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized boolean getNeedClientAuth()
    {
        return needClientAuth;
    }

    @Override
    public synchronized SSLSession getSession()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized String[] getSupportedCipherSuites()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized String[] getSupportedProtocols()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized boolean getUseClientMode()
    {
        return useClientMode;
    }

    @Override
    public synchronized boolean getWantClientAuth()
    {
        return wantClientAuth;
    }

    @Override
    public synchronized boolean isInboundDone()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized boolean isOutboundDone()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized void setEnabledCipherSuites(String[] strings)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized void setEnabledProtocols(String[] strings)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized void setEnableSessionCreation(boolean enableSessionCreation)
    {
        this.enableSessionCreation = enableSessionCreation;
    }

    @Override
    public synchronized void setNeedClientAuth(boolean needClientAuth)
    {
        this.needClientAuth = needClientAuth;
    }

    @Override
    public synchronized void setUseClientMode(boolean useClientMode)
    {
        if (initialHandshakeBegun && useClientMode != this.useClientMode)
        {
            throw new IllegalArgumentException("Mode cannot be changed after the initial handshake has begun");
        }

        this.useClientMode = useClientMode;
    }

    @Override
    public synchronized void setWantClientAuth(boolean wantClientAuth)
    {
        this.wantClientAuth = wantClientAuth;
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
        throws SSLException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
        throws SSLException
    {
        throw new UnsupportedOperationException();
    }
}
