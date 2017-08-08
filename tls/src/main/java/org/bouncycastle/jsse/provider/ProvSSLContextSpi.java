package org.bouncycastle.jsse.provider;

import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoProvider;

class ProvSSLContextSpi
    extends SSLContextSpi
{
    private static final Map<String, Integer> SUPPORTED_CIPHERSUITE_MAP = createSupportedCipherSuiteMap();
    private static final Map<String, Integer> SUPPORTED_CIPHERSUITE_MAP_FIPS = createSupportedCipherSuiteMapFips(SUPPORTED_CIPHERSUITE_MAP);

    private static final Map<String, ProtocolVersion> supportedProtocols = createSupportedProtocols();

    private static final List<String> DEFAULT_CIPHERSUITE_LIST = createDefaultCipherSuiteList(SUPPORTED_CIPHERSUITE_MAP.keySet());
    private static final List<String> DEFAULT_CIPHERSUITE_LIST_FIPS = createDefaultCipherSuiteListFips(DEFAULT_CIPHERSUITE_LIST);

    private static List<String> createDefaultCipherSuiteList(Set<String> supportedCipherSuiteSet)
    {
        ArrayList<String> cs = new ArrayList<String>();

        cs.add("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_RSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_RSA_WITH_AES_128_GCM_SHA256");
        cs.add("TLS_RSA_WITH_AES_256_CBC_SHA256");
        cs.add("TLS_RSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_RSA_WITH_AES_128_CBC_SHA");

        cs.retainAll(supportedCipherSuiteSet);
        cs.trimToSize();
        return Collections.unmodifiableList(cs);
    }

    private static List<String> createDefaultCipherSuiteListFips(List<String> defaultCipherSuiteList)
    {
        ArrayList<String> cs = new ArrayList<String>(defaultCipherSuiteList);
        FipsUtils.removeNonFipsCipherSuites(cs);
        cs.trimToSize();
        return Collections.unmodifiableList(cs);
    }

    private static Map<String, Integer> createSupportedCipherSuiteMap()
    {
        @SuppressWarnings("serial")
        final Map<String, Integer> cs = new HashMap<String, Integer>()
        {
            public Integer put(String key, Integer value)
            {
                if (null != super.put(key, value))
                {
                    throw new IllegalStateException("Duplicate names in supported-cipher-suites");
                }
                return null;
            }
        };

        cs.put("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
        cs.put("TLS_DHE_DSS_WITH_AES_128_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        cs.put("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        cs.put("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
        cs.put("TLS_DHE_DSS_WITH_AES_256_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
        cs.put("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
        cs.put("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384);

        cs.put("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
        cs.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        cs.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
        cs.put("TLS_DHE_RSA_WITH_AES_128_CCM", CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM);
        cs.put("TLS_DHE_RSA_WITH_AES_128_CCM_8", CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8);
        cs.put("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        cs.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        cs.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
        cs.put("TLS_DHE_RSA_WITH_AES_256_CCM", CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM);
        cs.put("TLS_DHE_RSA_WITH_AES_256_CCM_8", CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8);
        cs.put("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);

        cs.put("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
        cs.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        cs.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        cs.put("TLS_ECDHE_ECDSA_WITH_AES_128_CCM", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM);
        cs.put("TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
        cs.put("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        cs.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
        cs.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
        cs.put("TLS_ECDHE_ECDSA_WITH_AES_256_CCM", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM);
        cs.put("TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8);
        cs.put("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        cs.put("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        cs.put("TLS_ECDHE_ECDSA_WITH_NULL_SHA", CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA);

        cs.put("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
        cs.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        cs.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        cs.put("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        cs.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        cs.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
        cs.put("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        cs.put("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        cs.put("TLS_ECDHE_RSA_WITH_NULL_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA);

        cs.put("TLS_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        cs.put("TLS_RSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        cs.put("TLS_RSA_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        cs.put("TLS_RSA_WITH_AES_128_CCM", CipherSuite.TLS_RSA_WITH_AES_128_CCM);
        cs.put("TLS_RSA_WITH_AES_128_CCM_8", CipherSuite.TLS_RSA_WITH_AES_128_CCM_8);
        cs.put("TLS_RSA_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        cs.put("TLS_RSA_WITH_AES_256_CBC_SHA", CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        cs.put("TLS_RSA_WITH_AES_256_CBC_SHA256", CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
        cs.put("TLS_RSA_WITH_AES_256_CCM", CipherSuite.TLS_RSA_WITH_AES_256_CCM);
        cs.put("TLS_RSA_WITH_AES_256_CCM_8", CipherSuite.TLS_RSA_WITH_AES_256_CCM_8);
        cs.put("TLS_RSA_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384);
        cs.put("TLS_RSA_WITH_NULL_SHA", CipherSuite.TLS_RSA_WITH_NULL_SHA);
        cs.put("TLS_RSA_WITH_NULL_SHA256", CipherSuite.TLS_RSA_WITH_NULL_SHA256);

        return Collections.unmodifiableMap(cs);
    }

    private static Map<String, Integer> createSupportedCipherSuiteMapFips(Map<String, Integer> supportedCipherSuites)
    {
        final Map<String, Integer> cs = new HashMap<String, Integer>(supportedCipherSuites);
        FipsUtils.removeNonFipsCipherSuites(cs.keySet());
        return Collections.unmodifiableMap(cs);
    }

    private static Map<String, ProtocolVersion> createSupportedProtocols()
    {
        Map<String, ProtocolVersion> ps = new HashMap<String, ProtocolVersion>();
        ps.put("TLSv1", ProtocolVersion.TLSv10);
        ps.put("TLSv1.1", ProtocolVersion.TLSv11);
        ps.put("TLSv1.2", ProtocolVersion.TLSv12);
        return Collections.unmodifiableMap(ps);
    }

    protected final boolean isInFipsMode;
    protected final TlsCryptoProvider cryptoProvider;
    protected final String[] defaultProtocols;

    protected final Map<String, Integer> supportedCipherSuites;
    protected final List<String> defaultCipherSuites;

    protected boolean initialized = false;

    private TlsCrypto crypto;
    private X509KeyManager km;
    private X509TrustManager tm;
    private ProvSSLSessionContext clientSessionContext;
    private ProvSSLSessionContext serverSessionContext;

    ProvSSLContextSpi(boolean isInFipsMode, TlsCryptoProvider cryptoProvider, String[] defaultProtocols)
    {
        this.isInFipsMode = isInFipsMode;
        this.cryptoProvider = cryptoProvider;
        this.defaultProtocols = defaultProtocols;

        this.supportedCipherSuites = isInFipsMode ? SUPPORTED_CIPHERSUITE_MAP_FIPS : SUPPORTED_CIPHERSUITE_MAP;
        this.defaultCipherSuites = isInFipsMode ? DEFAULT_CIPHERSUITE_LIST_FIPS : DEFAULT_CIPHERSUITE_LIST;
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

    ProvSSLSessionContext createSSLSessionContext()
    {
        return new ProvSSLSessionContext(this, crypto);
    }

    String getCipherSuiteString(int suite)
    {
        if (TlsUtils.isValidUint16(suite))
        {
            for (Map.Entry<String, Integer> entry : supportedCipherSuites.entrySet())
            {
                if (entry.getValue().intValue() == suite)
                {
                    return entry.getKey();
                }
            }
        }
        return null;
    }

    String[] getDefaultCipherSuites()
    {
        return defaultCipherSuites.toArray(new String[defaultCipherSuites.size()]);
    }

    String[] getDefaultProtocols()
    {
        return defaultProtocols;
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

    String getProtocolString(ProtocolVersion v)
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

    String[] getSupportedCipherSuites()
    {
        return supportedCipherSuites.keySet().toArray(new String[supportedCipherSuites.size()]);
    }

    String[] getSupportedProtocols()
    {
        return supportedProtocols.keySet().toArray(new String[supportedProtocols.size()]);
    }

    boolean isFips()
    {
        return isInFipsMode;
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

    void validateNegotiatedCipherSuite(int cipherSuite)
    {
        // NOTE: The redundancy among these various checks is intentional
        String cs = getCipherSuiteString(cipherSuite);
        if (cs == null
            || !supportedCipherSuites.containsKey(cs)
            || (isInFipsMode && !FipsUtils.isFipsCipherSuite(cs)))
        {
            throw new IllegalStateException("SSL connection negotiated unsupported ciphersuite: " + cipherSuite);
        }
    }

    protected void checkInitialized()
    {
        if (!initialized)
        {
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
    protected synchronized SSLSessionContext engineGetClientSessionContext()
    {
        return clientSessionContext;
    }

    @Override
    protected SSLParameters engineGetDefaultSSLParameters()
    {
        // TODO[jsse] Review initial values
        SSLParameters r = new SSLParameters();
        r.setCipherSuites(getDefaultCipherSuites());
        r.setProtocols(getDefaultProtocols());
        return r;
    }

    @Override
    protected synchronized SSLSessionContext engineGetServerSessionContext()
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
        // TODO[jsse] Review initial values
        SSLParameters r = new SSLParameters();
        r.setCipherSuites(getSupportedCipherSuites());
        r.setProtocols(getSupportedProtocols());
        return r;
    }

    @Override
    protected synchronized void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException
    {
        this.initialized = false;
        this.crypto = cryptoProvider.create(sr);
        this.km = selectKeyManager(kms);
        this.tm = selectTrustManager(tms);
        this.clientSessionContext = createSSLSessionContext();
        this.serverSessionContext = createSSLSessionContext();
        this.initialized = true;
    }

    protected ContextData createContextData()
    {
        return new ContextData(crypto, km, tm, clientSessionContext, serverSessionContext);
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
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
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
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
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
