package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsServerProtocol;

/*
 * TODO[jsse] Currently doesn't properly support NIO usage, or conform very well with SSLEngine javadoc
 * - e.g. "The wrap() and unwrap() methods may execute concurrently of each other." is not true yet.
 */
class ProvSSLEngine
    extends SSLEngine
    implements ProvTlsManager
{
    protected final ProvSSLContextSpi context;
    protected final ContextData contextData;

    protected ProvSSLParameters sslParameters;
    protected boolean enableSessionCreation = false;
    protected boolean useClientMode = true;

    protected boolean initialHandshakeBegun = false;
    protected HandshakeStatus handshakeStatus = HandshakeStatus.NOT_HANDSHAKING; 
    protected TlsProtocol protocol = null;
    protected ProvTlsPeer protocolPeer = null;
    protected SSLSession session = ProvSSLSession.NULL_SESSION;
    protected SSLSession handshakeSession = null;

    protected ProvSSLEngine(ProvSSLContextSpi context, ContextData contextData)
    {
        super();

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);
    }

    protected ProvSSLEngine(ProvSSLContextSpi context, ContextData contextData, String host, int port)
    {
        super(host, port);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);;
    }

    public ProvSSLContextSpi getContext()
    {
        return context;
    }

    public ContextData getContextData()
    {
        return contextData;
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

        // TODO[jsse] Check for session to re-use and apply to handshake
        // TODO[jsse] Allocate this.handshakeSession and update it during handshake

        try
        {
            if (this.useClientMode)
            {
                TlsClientProtocol clientProtocol = new TlsClientProtocol();
                this.protocol = clientProtocol;

                ProvTlsClient client = new ProvTlsClient(this);
                this.protocolPeer = client;

                clientProtocol.connect(client);
            }
            else
            {
                TlsServerProtocol serverProtocol = new TlsServerProtocol();
                this.protocol = serverProtocol;

                ProvTlsServer server = new ProvTlsServer(this);
                this.protocolPeer = server;

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
        return null;
    }

    @Override
    public synchronized String[] getEnabledCipherSuites()
    {
        return sslParameters.getCipherSuites();
    }

    @Override
    public synchronized String[] getEnabledProtocols()
    {
        return sslParameters.getProtocols();
    }

    @Override
    public synchronized boolean getEnableSessionCreation()
    {
        return enableSessionCreation;
    }

    @Override
    public synchronized SSLSession getHandshakeSession()
    {
        // TODO[jsse] this.handshakeSession needs to be reset (to null) whenever not handshaking

        return handshakeSession;
    }

    @Override
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus()
    {
        return handshakeStatus;
    }

    @Override
    public synchronized boolean getNeedClientAuth()
    {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public synchronized SSLSession getSession()
    {
        // TODO[jsse] this.session needs to be set after a successful handshake

        return session;
    }

    @Override
    public synchronized SSLParameters getSSLParameters()
    {
        return SSLParametersUtil.toSSLParameters(sslParameters);
    }

    public synchronized ProvSSLParameters getProvSSLParameters()
    {
        return sslParameters;
    }

    @Override
    public synchronized String[] getSupportedCipherSuites()
    {
        return context.getSupportedCipherSuites();
    }

    @Override
    public synchronized String[] getSupportedProtocols()
    {
        return context.getSupportedProtocols();
    }

    @Override
    public synchronized boolean getUseClientMode()
    {
        return useClientMode;
    }

    @Override
    public synchronized boolean getWantClientAuth()
    {
        return sslParameters.getWantClientAuth();
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
    public synchronized void setEnabledCipherSuites(String[] suites)
    {
        if (!context.isSupportedCipherSuites(suites))
        {
            throw new IllegalArgumentException("'suites' cannot be null, or contain unsupported cipher suites");
        }

        sslParameters.setCipherSuites(suites);
    }

    @Override
    public synchronized void setEnabledProtocols(String[] protocols)
    {
        if (!context.isSupportedProtocols(protocols))
        {
            throw new IllegalArgumentException("'protocols' cannot be null, or contain unsupported protocols");
        }

        sslParameters.setProtocols(protocols);
    }

    @Override
    public synchronized void setEnableSessionCreation(boolean flag)
    {
        this.enableSessionCreation = flag;
    }

    @Override
    public synchronized void setNeedClientAuth(boolean need)
    {
        sslParameters.setNeedClientAuth(need);
    }

    @Override
    public synchronized void setSSLParameters(SSLParameters sslParameters)
    {
        this.sslParameters = SSLParametersUtil.toProvSSLParameters(sslParameters);
    }

    @Override
    public synchronized void setUseClientMode(boolean mode)
    {
        if (initialHandshakeBegun && mode != this.useClientMode)
        {
            throw new IllegalArgumentException("Mode cannot be changed after the initial handshake has begun");
        }

        this.useClientMode = mode;
    }

    @Override
    public synchronized void setWantClientAuth(boolean want)
    {
        sslParameters.setWantClientAuth(want);
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
        throws SSLException
    {
        // TODO[jsse] Argument checks - see javadoc

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
                // TODO[jsse] Throw a subclass of SSLException?
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

        if (!initialHandshakeBegun || protocolPeer.isHandshakeComplete())
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

    public boolean isClientTrusted(X509Certificate[] chain, String authType)
    {
        // TODO[jsse] Consider X509ExtendedTrustManager and/or HostnameVerifier functionality

        X509TrustManager tm = contextData.getTrustManager();
        if (tm != null)
        {
            try
            {
                tm.checkClientTrusted(chain, authType);
                return true;
            }
            catch (CertificateException e)
            {
            }
        }
        return false;
    }

    public boolean isServerTrusted(X509Certificate[] chain, String authType)
    {
        // TODO[jsse] Consider X509ExtendedTrustManager and/or HostnameVerifier functionality

        X509TrustManager tm = contextData.getTrustManager();
        if (tm != null)
        {
            try
            {
                tm.checkServerTrusted(chain, authType);
                return true;
            }
            catch (CertificateException e)
            {
            }
        }
        return false;
    }

    public synchronized void notifyHandshakeComplete(SSLSession session)
    {
        this.session = session;
    }
}
