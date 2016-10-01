package org.bouncycastle.jsse.provider;

import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
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
    protected static SSLSessionContext createSSLSessionContext()
    {
        return new ProvSSLSessionContext();
    }

    protected final SSLSessionContext clientSessionContext = createSSLSessionContext();
    protected final SSLSessionContext serverSessionContext = createSSLSessionContext();

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

    SSLParameters copySSLParameters(SSLParameters p)
    {
        SSLParameters r = new SSLParameters();
        r.setAlgorithmConstraints(r.getAlgorithmConstraints());
        r.setCipherSuites(p.getCipherSuites());
        r.setEndpointIdentificationAlgorithm(p.getEndpointIdentificationAlgorithm());
        r.setNeedClientAuth(p.getNeedClientAuth());
        r.setProtocols(p.getProtocols());
        // TODO[tls-ops] JDK 1.8 only
//        r.setServerNames(p.getServerNames());
//        r.setSNIMatchers(p.getSNIMatchers());
//        r.setUseCipherSuitesOrder(p.getUseCipherSuitesOrder());
        r.setWantClientAuth(p.getWantClientAuth());
        return r;
    }

    String[] getDefaultCipherSuites()
    {
        // TODO[tls-ops] Flesh out list and get strings by lookup of CipherSuite constants
        return new String[]{ "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" };
    }

    String[] getDefaultProtocols()
    {
        // TODO[tls-ops] Consider 
        return new String[]{ "TLSv1.2" };
    }

    String[] getSupportedCipherSuites()
    {
        // TODO[tls-ops] Add any supported, non-default cipherSuites
        return getDefaultCipherSuites();
    }

    String[] getSupportedProtocols()
    {
        // TODO[tls-ops] Get string constants by lookup
        return new String[]{
//            "SSLv3",
            "TLSv1",
            "TLSv1.1",
            "TLSv1.2",
        };
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
        return clientSessionContext;
    }

    @Override
    protected SSLParameters engineGetDefaultSSLParameters()
    {
        // TODO[tls-ops] Review initial values
        SSLParameters r = new SSLParameters();
        r.setCipherSuites(getDefaultCipherSuites());
        r.setProtocols(getDefaultProtocols());
        return r;
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext()
    {
        return serverSessionContext;
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

    @Override
    protected SSLParameters engineGetSupportedSSLParameters()
    {
        // TODO[tls-ops] Review initial values
        SSLParameters r = new SSLParameters();
        r.setCipherSuites(getSupportedCipherSuites());
        r.setProtocols(getSupportedProtocols());
        return r;
    }

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
