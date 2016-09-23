package org.bouncycastle.jsse.provider;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

class ProvSSLEngine
    extends SSLEngine
{
    protected boolean wantClientAuth;
    protected boolean needClientAuth;
    protected boolean useClientMode;
    protected boolean enableSessionCreation;

    ProvSSLEngine(ProvSSLContextSpi sslContext)
    {
    }

    ProvSSLEngine(ProvSSLContextSpi sslContext, String host, int port)
    {
        super(host, port);

        throw new UnsupportedOperationException();
    }

    @Override
    public void beginHandshake()
        throws SSLException
    {
        throw new UnsupportedOperationException();
    }

    public void closeInbound()
        throws SSLException
    {
        throw new UnsupportedOperationException();
    }

    public void closeOutbound()
    {
        throw new UnsupportedOperationException();
    }

    public Runnable getDelegatedTask()
    {
        throw new UnsupportedOperationException();
    }

    public String[] getEnabledCipherSuites()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getEnabledProtocols()
    {
        throw new UnsupportedOperationException();
    }

    public synchronized boolean getEnableSessionCreation()
    {
        return enableSessionCreation;
    }

//    @Override
//    public SSLSession getHandshakeSession()
//    {
//        return super.getHandshakeSession();
//    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized boolean getNeedClientAuth()
    {
        return needClientAuth;
    }

//    @Override
//    public String getPeerHost()
//    {
//        return super.getPeerHost();
//    }

//    @Override
//    public int getPeerPort()
//    {
//        return super.getPeerPort();
//    }

    @Override
    public SSLSession getSession()
    {
        throw new UnsupportedOperationException();
    }

//    @Override
//    public SSLParameters getSSLParameters()
//    {
//        return super.getSSLParameters();
//    }

    public String[] getSupportedCipherSuites()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getSupportedProtocols()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized boolean getUseClientMode()
    {
        return useClientMode;
    }

    public synchronized boolean getWantClientAuth()
    {
        return wantClientAuth;
    }

    public boolean isInboundDone()
    {
        throw new UnsupportedOperationException();
    }

    public boolean isOutboundDone()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setEnabledCipherSuites(String[] strings)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setEnabledProtocols(String[] strings)
    {
        throw new UnsupportedOperationException();
    }

    public synchronized void setEnableSessionCreation(boolean enableSessionCreation)
    {
        this.enableSessionCreation = enableSessionCreation;
    }

    @Override
    public synchronized void setNeedClientAuth(boolean needClientAuth)
    {
        this.needClientAuth = needClientAuth;
    }

//    @Override
//    public void setSSLParameters(SSLParameters params)
//    {
//        super.setSSLParameters(params);
//    }

    @Override
    public synchronized void setUseClientMode(boolean useClientMode)
    {
        this.useClientMode = useClientMode;
    }

    public synchronized void setWantClientAuth(boolean wantClientAuth)
    {
        this.wantClientAuth = wantClientAuth;
    }

//    @Override
//    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException
//    {
//        return super.unwrap(src, dst);
//    }

//    @Override
//    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException
//    {
//        return super.unwrap(src, dsts);
//    }

    public SSLEngineResult unwrap(ByteBuffer byteBuffer, ByteBuffer[] byteBuffers, int i, int i1)
        throws SSLException
    {
        throw new UnsupportedOperationException();
    }

//    @Override
//    public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException
//    {
//        return super.wrap(src, dst);
//    }

//    @Override
//    public SSLEngineResult wrap(ByteBuffer[] srcs, ByteBuffer dst) throws SSLException
//    {
//        return super.wrap(srcs, dst);
//    }

    public SSLEngineResult wrap(ByteBuffer[] byteBuffers, int i, int i1, ByteBuffer byteBuffer)
        throws SSLException
    {
        throw new UnsupportedOperationException();
    }
}
