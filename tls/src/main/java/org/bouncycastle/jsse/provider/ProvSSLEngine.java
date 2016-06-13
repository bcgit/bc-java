package org.bouncycastle.jsse.provider;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

class ProvSSLEngine
    extends SSLEngine
{
    private boolean wantClientAuth;
    private boolean needClientAuth;
    private boolean useClientMode;
    private boolean enableSessionCreation;

    ProvSSLEngine(ProvSSLContext sslContext)
    {
    }

    ProvSSLEngine(ProvSSLContext sslContext, String host, int port)
    {
        super(host, port);
    }

    public SSLEngineResult wrap(ByteBuffer[] byteBuffers, int i, int i1, ByteBuffer byteBuffer)
        throws SSLException
    {
        return null;
    }

    public SSLEngineResult unwrap(ByteBuffer byteBuffer, ByteBuffer[] byteBuffers, int i, int i1)
        throws SSLException
    {
        return null;
    }

    public Runnable getDelegatedTask()
    {
        return null;
    }

    public void closeInbound()
        throws SSLException
    {

    }

    public boolean isInboundDone()
    {
        return false;
    }

    public void closeOutbound()
    {

    }

    public boolean isOutboundDone()
    {
        return false;
    }

    public String[] getSupportedCipherSuites()
    {
        return new String[0];
    }

    public String[] getEnabledCipherSuites()
    {
        return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] strings)
    {

    }

    @Override
    public String[] getSupportedProtocols()
    {
        return new String[0];
    }

    @Override
    public String[] getEnabledProtocols()
    {
        return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] strings)
    {

    }

    @Override
    public SSLSession getSession()
    {
        return null;
    }

    @Override
    public void beginHandshake()
        throws SSLException
    {

    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus()
    {
        return null;
    }

    @Override
    public void setUseClientMode(boolean useClientMode)
    {
        this.useClientMode = useClientMode;
    }

    @Override
    public boolean getUseClientMode()
    {
        return useClientMode;
    }

    @Override
    public void setNeedClientAuth(boolean needClientAuth)
    {
        this.needClientAuth = needClientAuth;
    }

    @Override
    public boolean getNeedClientAuth()
    {
        return needClientAuth;
    }

    public void setWantClientAuth(boolean wantClientAuth)
    {
        this.wantClientAuth = wantClientAuth;
    }

    public boolean getWantClientAuth()
    {
        return wantClientAuth;
    }

    public void setEnableSessionCreation(boolean enableSessionCreation)
    {
        this.enableSessionCreation = enableSessionCreation;
    }

    public boolean getEnableSessionCreation()
    {
        return enableSessionCreation;
    }
}
