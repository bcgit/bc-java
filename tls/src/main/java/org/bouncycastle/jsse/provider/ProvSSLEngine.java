package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsProtocol;
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
    protected HandshakeStatus handshakeStatus = HandshakeStatus.NOT_HANDSHAKING; 

    protected TlsProtocol protocol = null;
    protected TlsProtocolManager protocolManager = null;

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
                TlsClientProtocol clientProtocol = new TlsClientProtocol();
                this.protocol = clientProtocol;

                ProvTlsClient client = new ProvTlsClient(context.getCrypto());
                this.protocolManager = client;

                clientProtocol.connect(client);
            }
            else
            {
                TlsServerProtocol serverProtocol = new TlsServerProtocol();
                this.protocol = serverProtocol;

                ProvTlsServer server = new ProvTlsServer(context.getCrypto());
                this.protocolManager = server;

                serverProtocol.accept(server);
            }
        }
        catch (IOException e)
        {
            throw new SSLException(e);
        }

        determineHandshakeStatus();
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
        return handshakeStatus;
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
        // TODO[tls-ops] Argument checks - see javadoc

        if (!initialHandshakeBegun)
        {
            beginHandshake();
        }

        HandshakeStatus prevHandshakeStatus = handshakeStatus;
        int bytesConsumed = 0, bytesProduced = 0;

        if (!protocol.isClosed())
        {
            byte[] buf = new byte[src.remaining()];
            src.get(buf);
    
            try
            {
                protocol.offerInput(buf);
            }
            catch (IOException e)
            {
                // TODO[tls-ops] Throw a subclass of SSLException?
                throw new SSLException(e);
            }
    
            bytesConsumed += buf.length;
        }

        int appDataAvailable = protocol.getAvailableInputBytes();
        for (int dstIndex = 0; dstIndex < length && appDataAvailable > 0; ++dstIndex)
        {
            ByteBuffer dst = dsts[dstIndex];
            int count = Math.min(dst.remaining(), appDataAvailable);

            byte[] input = new byte[count];
            int numRead = protocol.readInput(input, 0, count);
            assert numRead == count;

            dst.put(input);

            bytesProduced += count;
            appDataAvailable -= count;
        }

        Status returnStatus = Status.OK;
        if (appDataAvailable > 0)
        {
            returnStatus = Status.BUFFER_OVERFLOW;
        }
        else if (protocol.isClosed())
        {
            returnStatus = Status.CLOSED;
        }

        determineHandshakeStatus();

        HandshakeStatus returnHandshakeStatus = handshakeStatus;
        if (handshakeStatus == HandshakeStatus.NOT_HANDSHAKING && prevHandshakeStatus != HandshakeStatus.NOT_HANDSHAKING)
        {
            returnHandshakeStatus = HandshakeStatus.FINISHED;
        }

        return new SSLEngineResult(returnStatus, returnHandshakeStatus, bytesConsumed, bytesProduced);
    }

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
        throws SSLException
    {
        throw new UnsupportedOperationException();
    }

    protected void determineHandshakeStatus()
    {
        // NOTE: We currently never delegate tasks (will never have status HandshakeStatus.NEED_TASK)

        if (!initialHandshakeBegun || protocolManager.isHandshakeComplete())
        {
            handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
        }
        else if (protocol.getAvailableOutputBytes() > 0)
        {
            handshakeStatus = HandshakeStatus.NEED_WRAP;
        }
        else if (protocol.isClosed())
        {
            handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
        }
        else
        {
            handshakeStatus = HandshakeStatus.NEED_UNWRAP;
        }
    }
}
