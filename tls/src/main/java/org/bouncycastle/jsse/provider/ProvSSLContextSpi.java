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
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509KeyManager;

import org.bouncycastle.tls.TlsCrypto;

class ProvSSLContextSpi
    extends SSLContextSpi
{
    protected final TlsCrypto crypto;

    protected boolean initialized = false;

    private X509ExtendedKeyManager km;
    private X509ExtendedTrustManager tm;

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
    protected void engineInit(KeyManager[] kms, TrustManager[] tm, SecureRandom sr) throws KeyManagementException
    {
        this.initialized = false;

        this.km = selectKeyManager(kms);

        this.initialized = true;
    }

    public X509ExtendedKeyManager getKeyManager()
    {
        return km;
    }

    public X509ExtendedTrustManager getTrustManager()
    {
        return tm;
    }

    private X509ExtendedKeyManager selectKeyManager(KeyManager[] kms)
    {
        if (kms != null)
        {
            for (int i = 0; i != kms.length; i++)
            {
                KeyManager km = kms[i];

                if (km instanceof X509ExtendedKeyManager)
                {
                    return (X509ExtendedKeyManager)km;
                }
                if (km instanceof X509KeyManager)
                {
                    return new X509KeyManagerExtender((X509KeyManager)km);
                }
            }
        }

        // TODO: return default value
        return null;
    }
}
