package org.bouncycastle.jsse.provider;

import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

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

import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoProvider;

class ProvSSLContextSpi
    extends SSLContextSpi
{
    private static final Map<String, Integer> supportedCipherSuites = createSupportedCipherSuites();
    private static final Map<String, ProtocolVersion> supportedProtocols = createSupportedProtocols();

    private static Map<String, Integer> createSupportedCipherSuites()
    {
        Map<String, Integer> cs = new HashMap<String, Integer>();
        cs.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        cs.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        cs.put("TLS_RSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        return cs;
    }

    private static Map<String, ProtocolVersion> createSupportedProtocols()
    {
        Map<String, ProtocolVersion> ps = new HashMap<String, ProtocolVersion>();
//        ps.put("SSLv3", ProtocolVersion.SSLv3);
        ps.put("TLSv1", ProtocolVersion.TLSv10);
        ps.put("TLSv1.1", ProtocolVersion.TLSv11);
        ps.put("TLSv1.2", ProtocolVersion.TLSv12);
        return ps;
    }

    protected static SSLSessionContext createSSLSessionContext()
    {
        return new ProvSSLSessionContext();
    }

    protected final SSLSessionContext clientSessionContext = createSSLSessionContext();
    protected final SSLSessionContext serverSessionContext = createSSLSessionContext();

    protected final TlsCryptoProvider cryptoProvider;

    protected boolean initialized = false;

    private TlsCrypto crypto;
    private X509KeyManager km;
    private X509TrustManager tm;

    ProvSSLContextSpi(TlsCryptoProvider cryptoProvider)
    {
        this.cryptoProvider = cryptoProvider;
    }

    int[] convertCipherSuites(String[] suites)
    {
        int[] result = new int[suites.length];
        for (int i = 0; i < suites.length; ++i)
        {
            result[i] = supportedCipherSuites.get(suites[i]);
        }
        return result;
    }

    SSLParameters copySSLParameters(SSLParameters p)
    {
        SSLParameters r = new SSLParameters();
        r.setCipherSuites(p.getCipherSuites());
        r.setProtocols(p.getProtocols());
        // TODO[tls-ops] From JDK 1.7
//        r.setAlgorithmConstraints(r.getAlgorithmConstraints());
//        r.setEndpointIdentificationAlgorithm(p.getEndpointIdentificationAlgorithm());
        // TODO[tls-ops] From JDK 1.8
//        r.setServerNames(p.getServerNames());
//        r.setSNIMatchers(p.getSNIMatchers());
//        r.setUseCipherSuitesOrder(p.getUseCipherSuitesOrder());

        // NOTE: The client-auth setters each clear the other client-auth property, so only one can be set
        if (p.getNeedClientAuth())
        {
            r.setNeedClientAuth(true);
        }
        else if (p.getWantClientAuth())
        {
            r.setWantClientAuth(true);
        }
        else
        {
            r.setWantClientAuth(false);
        }
        return r;
    }

    String[] getDefaultCipherSuites()
    {
        return new String[]{
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
        };
    }

    String[] getDefaultProtocols()
    {
        return new String[]{ "TLSv1.2" };
    }

    ProtocolVersion getMaximumVersion(String[] protocols)
    {
        ProtocolVersion max = null;
        if (protocols != null)
        {
            for (String protocol : protocols)
            {
                if (protocol != null)
                {
                    ProtocolVersion v = supportedProtocols.get(protocol);
                    if (v != null && (max == null || v.isLaterVersionOf(max)))
                    {
                        max = v;
                    }
                }
            }
        }
        return max;
    }

    ProtocolVersion getMinimumVersion(String[] protocols)
    {
        ProtocolVersion min = null;
        if (protocols != null)
        {
            for (String protocol : protocols)
            {
                if (protocol != null)
                {
                    ProtocolVersion v = supportedProtocols.get(protocol);
                    if (v != null && (min == null || min.isLaterVersionOf(v)))
                    {
                        min = v;
                    }
                }
            }
        }
        return min;
    }

    String[] getSupportedCipherSuites()
    {
        return supportedCipherSuites.keySet().toArray(new String[supportedCipherSuites.size()]);
    }

    String[] getSupportedProtocols()
    {
        return supportedProtocols.keySet().toArray(new String[supportedProtocols.size()]);
    }

    String getVersionString(ProtocolVersion v)
    {
        if (v != null)
        {
            for (Map.Entry<String, ProtocolVersion> entry : supportedProtocols.entrySet())
            {
                if (v.equals(entry.getValue()))
                {
                    return entry.getKey();
                }
            }
        }
        return null;
    }

    boolean isSupportedCipherSuites(String[] suites)
    {
        if (suites == null)
        {
            return false;
        }
        for (String suite : suites)
        {
            if (suite == null || !supportedCipherSuites.containsKey(suite))
            {
                return false;
            }
        }
        return true;
    }

    boolean isSupportedProtocols(String[] protocols)
    {
        if (protocols == null)
        {
            return false;
        }
        for (String protocol : protocols)
        {
            if (protocol == null || !supportedProtocols.containsKey(protocol))
            {
                return false;
            }
        }
        return true;
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
    protected synchronized SSLEngine engineCreateSSLEngine()
    {
        checkInitialized();
        return new ProvSSLEngine(this, createContextData());
    }

    @Override
    protected synchronized SSLEngine engineCreateSSLEngine(String host, int port)
    {
        checkInitialized();
        return new ProvSSLEngine(this, createContextData(), host, port);
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
        this.crypto = cryptoProvider.create(sr);
        this.initialized = true;
    }

    protected ContextData createContextData()
    {
        return new ContextData(crypto, km, tm);
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
