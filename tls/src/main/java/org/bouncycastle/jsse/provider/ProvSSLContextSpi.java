package org.bouncycastle.jsse.provider;

import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.tls.crypto.TlsCrypto;

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

    private X509KeyManager km;
    private X509TrustManager tm;

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
        return new String[]{ "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" };
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
        // TODO[jsse] Does the engine need immutable refs to km/tm/random in case of re-init?
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
    protected synchronized void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException
    {
        this.initialized = false;
        this.km = selectKeyManager(kms);
        this.tm = selectTrustManager(tms);
        // TODO[tls-ops] SecureRandom?
        this.initialized = true;
    }

    protected X509KeyManager findX509KeyManager(KeyManager[] kms)
    {
        if (kms != null)
        {
            for (KeyManager km : kms)
            {
                if (km instanceof X509KeyManager)
                {
                    return (X509KeyManager)km;
                }
            }
        }
        return null;
    }

    protected X509TrustManager findX509TrustManager(TrustManager[] tms)
    {
        if (tms != null)
        {
            for (TrustManager tm : tms)
            {
                if (tm instanceof X509TrustManager)
                {
                    return (X509TrustManager)tm;
                }
            }
        }
        return null;
    }
    
    protected synchronized X509KeyManager getX509KeyManager()
    {
        return km;
    }

    protected synchronized X509TrustManager getX509TrustManager()
    {
        return tm;
    }

    protected X509KeyManager selectKeyManager(KeyManager[] kms) throws KeyManagementException
    {
        if (kms == null)
        {
            try
            {
                /*
                 * "[...] the installed security providers will be searched for the highest priority
                 * implementation of the appropriate factory."
                 */

                // TODO[tls-ops] Is PKIX a reasonable algorithm to use here?
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
                // TODO[tls-ops] Is this supported generally?
                kmf.init(null, null);
                kms = kmf.getKeyManagers();
            }
            catch (GeneralSecurityException e)
            {
                throw new KeyManagementException(e);
            }
        }

        return findX509KeyManager(kms);
    }

    protected X509TrustManager selectTrustManager(TrustManager[] tms) throws KeyManagementException
    {
        if (tms == null)
        {
            try
            {
                /*
                 * "[...] the installed security providers will be searched for the highest priority
                 * implementation of the appropriate factory."
                 */

                // TODO[tls-ops] Is PKIX a reasonable algorithm to use here?
                TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
                // TODO[tls-ops] Is this supported generally?
                tmf.init((KeyStore)null);
                tms = tmf.getTrustManagers();
            }
            catch (GeneralSecurityException e)
            {
                throw new KeyManagementException(e);
            }
        }

        return findX509TrustManager(tms);
    }
}
