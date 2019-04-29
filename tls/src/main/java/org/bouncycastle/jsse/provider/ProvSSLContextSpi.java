package org.bouncycastle.jsse.provider;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

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
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoProvider;

class ProvSSLContextSpi
    extends SSLContextSpi
{
    private static final Logger LOG = Logger.getLogger(ProvSSLContextSpi.class.getName());

    private static final String PROPERTY_CLIENT_PROTOCOLS = "jdk.tls.client.protocols";
    private static final String PROPERTY_SERVER_PROTOCOLS = "jdk.tls.server.protocols";

    /*
     * TODO[jsse] Should separate this into "understood" cipher suite int<->String maps
     * and a Set of supported cipher suite values, so we can cover TLS_NULL_WITH_NULL_NULL and
     * the SCSV values.
     */
    private static final Map<String, Integer> SUPPORTED_CIPHERSUITE_MAP = createSupportedCipherSuiteMap();
    private static final Map<String, Integer> SUPPORTED_CIPHERSUITE_MAP_FIPS = createSupportedCipherSuiteMapFips(SUPPORTED_CIPHERSUITE_MAP);

    private static final Map<String, ProtocolVersion> supportedProtocols = createSupportedProtocols();

    private static final List<String> DEFAULT_CIPHERSUITE_LIST = createDefaultCipherSuiteList(SUPPORTED_CIPHERSUITE_MAP.keySet());
    private static final List<String> DEFAULT_CIPHERSUITE_LIST_FIPS = createDefaultCipherSuiteListFips(DEFAULT_CIPHERSUITE_LIST);

    // TODO[tls13]
//    private static final String[] DEFAULT_PROTOCOLS = new String[]{ "TLSv1.2", "TLSv1.3" };
    private static final String[] DEFAULT_PROTOCOLS = new String[]{ "TLSv1.2" };

    private static List<String> createDefaultCipherSuiteList(Set<String> supportedCipherSuiteSet)
    {
        ArrayList<String> cs = new ArrayList<String>();

        // TODO[tls13]
//        /*
//         * TLS 1.3
//         */
//        cs.add("TLS_CHACHA20_POLY1305_SHA256");
//        cs.add("TLS_AES_256_GCM_SHA256");
//        cs.add("TLS_AES_128_GCM_SHA256");

        /*
         * pre-TLS 1.3
         */
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

        // TODO[tls13]
//        /*
//         * TLS 1.3
//         */
//        cs.put("TLS_AES_128_GCM_SHA256", CipherSuite.TLS_AES_128_GCM_SHA256);
//        cs.put("TLS_AES_256_GCM_SHA384", CipherSuite.TLS_AES_256_GCM_SHA384);
//        cs.put("TLS_CHACHA20_POLY1305_SHA256", CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
//        cs.put("TLS_AES_128_CCM_SHA256", CipherSuite.TLS_AES_128_CCM_SHA256);
//        cs.put("TLS_AES_128_CCM_8_SHA256", CipherSuite.TLS_AES_128_CCM_8_SHA256);

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
        // TODO[tls13]
//        ps.put("TLSv1.3", ProtocolVersion.TLSv13);
        return Collections.unmodifiableMap(ps);
    }

    private static String[] getDefaultProtocols(String[] specifiedProtocols, String propertyName)
    {
        if (specifiedProtocols != null)
        {
            return specifiedProtocols;
        }

        String[] propertyProtocols = getJdkTlsProtocols(propertyName);
        if (propertyProtocols != null)
        {
            return propertyProtocols;
        }

        return DEFAULT_PROTOCOLS;
    }

    private static String[] getDefaultProtocolsClient(String[] specifiedProtocols)
    {
        return getDefaultProtocols(specifiedProtocols, PROPERTY_CLIENT_PROTOCOLS);
    }

    private static String[] getDefaultProtocolsServer(String[] specifiedProtocols)
    {
        return getDefaultProtocols(specifiedProtocols, PROPERTY_SERVER_PROTOCOLS);
    }

    private static String[] getJdkTlsProtocols(String propertyName)
    {
        String prop = PropertyUtils.getStringSystemProperty(propertyName);
        if (prop == null)
        {
            return null;
        }

        String[] entries = JsseUtils.stripDoubleQuotes(prop.trim()).split(",");
        String[] result = new String[entries.length];
        int count = 0;
        for (String entry : entries)
        {
            String protocol = entry.trim();
            if (protocol.length() < 1)
                continue;

            if (!supportedProtocols.containsKey(protocol))
            {
                LOG.finest("'" + propertyName + "' contains unsupported protocol: " + protocol);
            }
            else if (!JsseUtils.contains(result, protocol))
            {
                result[count++] = protocol;
            }
        }
        if (count < 1)
        {
            LOG.severe("'" + propertyName + "' contained no usable protocol values (ignoring)");
            return null;
        }
        if (count < result.length)
        {
            result = JsseUtils.copyOf(result, count);
        }
        return result;
    }

    private static String[] getArray(Collection<String> c)
    {
        return c.toArray(new String[c.size()]);
    }

    private static String[] getKeysArray(Map<String, ?> m)
    {
        return getArray(m.keySet());
    }

    static KeyManager[] getDefaultKeyManagers() throws Exception
    {
        KeyStoreConfig keyStoreConfig = ProvKeyManagerFactorySpi.getDefaultKeyStore();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStoreConfig.keyStore, keyStoreConfig.password);
        return kmf.getKeyManagers();
    }

    static TrustManager[] getDefaultTrustManagers() throws Exception
    {
        KeyStore trustStore = ProvTrustManagerFactorySpi.getDefaultTrustStore();
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        return tmf.getTrustManagers();
    }

    protected final boolean isInFipsMode;
    protected final TlsCryptoProvider cryptoProvider;
    protected final String[] defaultProtocolsClient;
    protected final String[] defaultProtocolsServer;

    protected final Map<String, Integer> supportedCipherSuites;
    protected final String[] defaultCipherSuites;

    protected boolean initialized = false;

    private TlsCrypto crypto;
    private X509ExtendedKeyManager x509KeyManager;
    private BCX509ExtendedTrustManager x509TrustManager;
    private ProvSSLSessionContext clientSessionContext;
    private ProvSSLSessionContext serverSessionContext;

    ProvSSLContextSpi(boolean isInFipsMode, TlsCryptoProvider cryptoProvider, String[] specifiedProtocols)
    {
        this.isInFipsMode = isInFipsMode;
        this.cryptoProvider = cryptoProvider;
        this.defaultProtocolsClient = getDefaultProtocolsClient(specifiedProtocols);
        this.defaultProtocolsServer = getDefaultProtocolsServer(specifiedProtocols);

        this.supportedCipherSuites = isInFipsMode ? SUPPORTED_CIPHERSUITE_MAP_FIPS : SUPPORTED_CIPHERSUITE_MAP;

        List<String> defaultCipherSuiteList = isInFipsMode ? DEFAULT_CIPHERSUITE_LIST_FIPS : DEFAULT_CIPHERSUITE_LIST;
        this.defaultCipherSuites = getArray(defaultCipherSuiteList);
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
        // TODO[jsse] Place into "understood" cipher suite map
        if (CipherSuite.TLS_NULL_WITH_NULL_NULL == suite)
        {
            return "TLS_NULL_WITH_NULL_NULL";
        }

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
        return defaultCipherSuites.clone();
    }

    ProvSSLParameters getDefaultParameters(boolean isServer)
    {
        return new ProvSSLParameters(this, defaultCipherSuites, getDefaultProtocols(isServer));
    }

    String[] getDefaultProtocols(boolean isServer)
    {
        return isServer ? getDefaultProtocolsServer() : getDefaultProtocolsClient();
    }

    String[] getDefaultProtocolsClient()
    {
        return defaultProtocolsClient;
    }

    String[] getDefaultProtocolsServer()
    {
        return defaultProtocolsServer;
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

    ProtocolVersion[] getSupportedVersions(String[] protocols)
    {
        if (protocols == null)
        {
            return null;
        }

        SortedSet<ProtocolVersion> versions = new TreeSet<ProtocolVersion>(new Comparator<ProtocolVersion>(){
            public int compare(ProtocolVersion o1, ProtocolVersion o2)
            {
                return o1.isLaterVersionOf(o2) ? -1 : o2.isLaterVersionOf(o1) ? 1 : 0;
            }
        });

        for (String protocol : protocols)
        {
            if (protocol != null)
            {
                ProtocolVersion version = supportedProtocols.get(protocol);
                if (version != null)
                {
                    versions.add(version);
                }
            }
        }

        return versions.toArray(new ProtocolVersion[versions.size()]);
    }

    boolean isDefaultProtocols(String[] protocols)
    {
        return protocols == getDefaultProtocolsClient()
            || protocols == getDefaultProtocolsServer();
    }

    String[] getSupportedCipherSuites()
    {
        return getKeysArray(supportedCipherSuites);
    }

    String[] getSupportedProtocols()
    {
        return getKeysArray(supportedProtocols);
    }

    String[] getSupportedCipherSuites(String[] cipherSuites)
    {
        if (null == cipherSuites)
        {
            throw new NullPointerException("'cipherSuites' cannot be null");
        }

        ArrayList<String> result = new ArrayList<String>(cipherSuites.length);
        for (String cipherSuite : cipherSuites)
        {
            if (null == cipherSuite || cipherSuite.length() < 1)
            {
                throw new IllegalArgumentException("'cipherSuites' cannot contain null or empty string elements");
            }

            if (supportedCipherSuites.containsKey(cipherSuite))
            {
                result.add(cipherSuite);
            }
        }
        return getArray(result);
    }

    boolean isFips()
    {
        return isInFipsMode;
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

    void updateDefaultProtocols(ProvSSLParameters sslParameters, boolean isServer)
    {
        if (isDefaultProtocols(sslParameters.getProtocolsArray()))
        {
            sslParameters.setProtocolsArray(getDefaultProtocols(isServer));
        }
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
        return SSLEngineUtil.create(this, createContextData());
    }

    @Override
    protected synchronized SSLEngine engineCreateSSLEngine(String host, int port)
    {
        checkInitialized();
        return SSLEngineUtil.create(this, createContextData(), host, port);
    }

    @Override
    protected synchronized SSLSessionContext engineGetClientSessionContext()
    {
        return clientSessionContext;
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
        this.x509KeyManager = selectX509KeyManager(kms);
        this.x509TrustManager = selectX509TrustManager(tms);
        this.clientSessionContext = createSSLSessionContext();
        this.serverSessionContext = createSSLSessionContext();

        // Trigger (possibly expensive) RNG initialization here to avoid timeout in an actual handshake
        this.crypto.getSecureRandom().nextInt();

        this.initialized = true;
    }

    protected ContextData createContextData()
    {
        return new ContextData(crypto, x509KeyManager, x509TrustManager, clientSessionContext, serverSessionContext);
    }

    protected X509ExtendedKeyManager selectX509KeyManager(KeyManager[] kms) throws KeyManagementException
    {
        if (kms != null)
        {
            for (KeyManager km : kms)
            {
                if (km instanceof X509KeyManager)
                {
                    return X509KeyManagerUtil.importX509KeyManager((X509KeyManager)km);
                }
            }
        }
        return DummyX509KeyManager.INSTANCE;
    }

    protected BCX509ExtendedTrustManager selectX509TrustManager(TrustManager[] tms) throws KeyManagementException
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
            catch (Exception e)
            {
                LOG.log(Level.WARNING, "Failed to load default trust managers", e);
            }
        }
        if (tms != null)
        {
            for (TrustManager tm : tms)
            {
                if (tm instanceof X509TrustManager)
                {
                    return X509TrustManagerUtil.importX509TrustManager((X509TrustManager)tm);
                }
            }
        }
        return DummyX509TrustManager.INSTANCE;
    }
}
