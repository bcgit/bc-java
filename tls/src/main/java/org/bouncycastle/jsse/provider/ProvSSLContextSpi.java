package org.bouncycastle.jsse.provider;

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.bouncycastle.tls.TlsCrypto;

class ProvSSLContextSpi
    extends SSLContextSpi
{
    protected final TlsCrypto crypto;

    protected boolean initialized = false;

    ProvSSLContextSpi(TlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    TlsCrypto getCrypto()
    {
        return crypto;
    }

    protected void checkInitialized()
    {
        if (!initialized)
        {
            // TODO[tls-ops] If initialization turns out to be optional, create default objects here instead (and set initialized = true)
            throw new IllegalStateException("SSLContext has not been initialized.");
        }
    }

    @Override
    protected SSLEngine engineCreateSSLEngine()
    {
        checkInitialized();
        return new ProvSSLEngine(this);
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port)
    {
        checkInitialized();
        return new ProvSSLEngine(this, host, port);
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext()
    {
        throw new UnsupportedOperationException();
    }

//  @Override
//  protected SSLParameters engineGetDefaultSSLParameters()
//  {
//      return super.engineGetDefaultSSLParameters();
//  }

    @Override
    protected SSLSessionContext engineGetServerSessionContext()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory()
    {
        checkInitialized();
        return new ProvSSLServerSocketFactory(this);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory()
    {
        checkInitialized();
        return new ProvSSLSocketFactory(this);
    }

//  @Override
//  protected SSLParameters engineGetSupportedSSLParameters()
//  {
//      return super.engineGetSupportedSSLParameters();
//  }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException
    {
        this.initialized = true;

        throw new UnsupportedOperationException();
    }
}
