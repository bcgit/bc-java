package org.bouncycastle.jsse.provider;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
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
    private static final Map<String, CipherSuiteInfo> SUPPORTED_CIPHERSUITE_MAP = createSupportedCipherSuiteMap();
    private static final Map<String, CipherSuiteInfo> SUPPORTED_CIPHERSUITE_MAP_FIPS = createSupportedCipherSuiteMapFips(SUPPORTED_CIPHERSUITE_MAP);

    private static final Map<String, ProtocolVersion> SUPPORTED_PROTOCOL_MAP = createSupportedProtocolMap();
    private static final Map<String, ProtocolVersion> SUPPORTED_PROTOCOL_MAP_FIPS = createSupportedProtocolMapFips(SUPPORTED_PROTOCOL_MAP);

    private static final List<String> DEFAULT_CIPHERSUITE_LIST = createDefaultCipherSuiteList(SUPPORTED_CIPHERSUITE_MAP.keySet());
    private static final List<String> DEFAULT_CIPHERSUITE_LIST_FIPS = createDefaultCipherSuiteListFips(DEFAULT_CIPHERSUITE_LIST);

    // TODO[tls13]
//    private static final String[] DEFAULT_ENABLED_PROTOCOLS = new String[]{ "TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1" };
    private static final String[] DEFAULT_ENABLED_PROTOCOLS = new String[]{ "TLSv1.2", "TLSv1.1", "TLSv1" };

    private static void addCipherSuite(Map<String, CipherSuiteInfo> cs, String name, int cipherSuite)
    {
        CipherSuiteInfo cipherSuiteInfo = CipherSuiteInfo.forCipherSuite(cipherSuite, name);

        if (null != cs.put(name, cipherSuiteInfo))
        {
            throw new IllegalStateException("Duplicate names in supported-cipher-suites");
        }
    }

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

    private static Map<String, CipherSuiteInfo> createSupportedCipherSuiteMap()
    {
        Map<String, CipherSuiteInfo> cs = new TreeMap<String, CipherSuiteInfo>();

        addCipherSuite(cs, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_128_CCM", CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_128_CCM_8", CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_256_CCM", CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_256_CCM_8", CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256);

        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA);

        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_NULL_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA);

        addCipherSuite(cs, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_128_CCM", CipherSuite.TLS_RSA_WITH_AES_128_CCM);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_128_CCM_8", CipherSuite.TLS_RSA_WITH_AES_128_CCM_8);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_256_CBC_SHA", CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_256_CBC_SHA256", CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_256_CCM", CipherSuite.TLS_RSA_WITH_AES_256_CCM);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_256_CCM_8", CipherSuite.TLS_RSA_WITH_AES_256_CCM_8);
        addCipherSuite(cs, "TLS_RSA_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_RSA_WITH_NULL_SHA", CipherSuite.TLS_RSA_WITH_NULL_SHA);
        addCipherSuite(cs, "TLS_RSA_WITH_NULL_SHA256", CipherSuite.TLS_RSA_WITH_NULL_SHA256);

        // TODO[tls13]
//        /*
//         * TLS 1.3
//         */
//        addCipherSuite(cs, "TLS_AES_128_GCM_SHA256", CipherSuite.TLS_AES_128_GCM_SHA256);
//        addCipherSuite(cs, "TLS_AES_256_GCM_SHA384", CipherSuite.TLS_AES_256_GCM_SHA384);
//        addCipherSuite(cs, "TLS_CHACHA20_POLY1305_SHA256", CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
//        addCipherSuite(cs, "TLS_AES_128_CCM_SHA256", CipherSuite.TLS_AES_128_CCM_SHA256);
//        addCipherSuite(cs, "TLS_AES_128_CCM_8_SHA256", CipherSuite.TLS_AES_128_CCM_8_SHA256);

        return Collections.unmodifiableMap(cs);
    }

    private static Map<String, CipherSuiteInfo> createSupportedCipherSuiteMapFips(
        Map<String, CipherSuiteInfo> supportedCipherSuiteMap)
    {
        final Map<String, CipherSuiteInfo> cs = new LinkedHashMap<String, CipherSuiteInfo>(supportedCipherSuiteMap);
        FipsUtils.removeNonFipsCipherSuites(cs.keySet());
        return Collections.unmodifiableMap(cs);
    }

    private static Map<String, ProtocolVersion> createSupportedProtocolMap()
    {
        Map<String, ProtocolVersion> ps = new LinkedHashMap<String, ProtocolVersion>();
        // TODO[tls13]
//        ps.put("TLSv1.3", ProtocolVersion.TLSv13);
        ps.put("TLSv1.2", ProtocolVersion.TLSv12);
        ps.put("TLSv1.1", ProtocolVersion.TLSv11);
        ps.put("TLSv1", ProtocolVersion.TLSv10);
        return Collections.unmodifiableMap(ps);
    }

    private static Map<String, ProtocolVersion> createSupportedProtocolMapFips(
        Map<String, ProtocolVersion> supportedProtocolMap)
    {
        final Map<String, ProtocolVersion> ps = new LinkedHashMap<String, ProtocolVersion>(supportedProtocolMap);
        FipsUtils.removeNonFipsCipherSuites(ps.keySet());
        return Collections.unmodifiableMap(ps);
    }

    private static String[] getDefaultCipherSuites(boolean isInFipsMode)
    {
        /*
         * TODO[jsse] SunJSSE also filters this initial list based on the default protocol versions.
         */

        List<String> candidates = isInFipsMode ? DEFAULT_CIPHERSUITE_LIST_FIPS : DEFAULT_CIPHERSUITE_LIST;
        String[] result = new String[candidates.size()];

        int count = 0;
        for (String candidate : candidates)
        {
            if (ProvAlgorithmConstraints.DEFAULT.permits(JsseUtils.TLS_CRYPTO_PRIMITIVES_BC, candidate, null))
            {
                result[count++] = candidate;
            }
        }
        return JsseUtils.resize(result, count);
    }

    private static String[] getDefaultEnabledProtocolCandidates(String[] specifiedProtocols,
        String protocolsPropertyName)
    {
        if (specifiedProtocols != null)
        {
            return specifiedProtocols;
        }

        String[] propertyProtocols = getJdkTlsProtocols(protocolsPropertyName);
        if (propertyProtocols != null)
        {
            return propertyProtocols;
        }

        return DEFAULT_ENABLED_PROTOCOLS;
    }

    private static String[] getDefaultEnabledProtocols(Map<String, ProtocolVersion> supportedProtocols,
        String[] specifiedProtocols, String protocolsPropertyName)
    {
        String[] candidates = getDefaultEnabledProtocolCandidates(specifiedProtocols, protocolsPropertyName);
        String[] result = new String[candidates.length];

        int count = 0;
        for (String candidate : candidates)
        {
            if (!supportedProtocols.containsKey(candidate))
            {
                continue;
            }
            if (!ProvAlgorithmConstraints.DEFAULT_TLS_ONLY.permits(JsseUtils.TLS_CRYPTO_PRIMITIVES_BC, candidate, null))
            {
                continue;
            }

            result[count++] = candidate;
        }
        return JsseUtils.resize(result, count);
    }

    private static String[] getDefaultEnabledProtocolsClient(Map<String, ProtocolVersion> supportedProtocols,
        String[] specifiedProtocols)
    {
        return getDefaultEnabledProtocols(supportedProtocols, specifiedProtocols, PROPERTY_CLIENT_PROTOCOLS);
    }

    private static String[] getDefaultEnabledProtocolsServer(Map<String, ProtocolVersion> supportedProtocols)
    {
        return getDefaultEnabledProtocols(supportedProtocols, null, PROPERTY_SERVER_PROTOCOLS);
    }

    private static String[] getJdkTlsProtocols(String protocolsPropertyName)
    {
        String[] protocols = PropertyUtils.getStringArraySystemProperty(protocolsPropertyName);
        if (null == protocols)
        {
            return null;
        }

        String[] result = new String[protocols.length];
        int count = 0;
        for (String protocol : protocols)
        {
            if (!SUPPORTED_PROTOCOL_MAP.containsKey(protocol))
            {
                LOG.warning("'" + protocolsPropertyName + "' contains unsupported protocol: " + protocol);
            }
            else if (!JsseUtils.contains(result, protocol))
            {
                result[count++] = protocol;
            }
        }
        if (count < 1)
        {
            LOG.severe("'" + protocolsPropertyName + "' contained no supported protocol values (ignoring)");
            return null;
        }
        return JsseUtils.resize(result, count);
    }

    private static String[] getArray(Collection<String> c)
    {
        return c.toArray(new String[c.size()]);
    }

    private static String[] getKeysArray(Map<String, ?> m)
    {
        return getArray(m.keySet());
    }

    static CipherSuiteInfo getCipherSuiteInfo(String cipherSuiteName)
    {
        return SUPPORTED_CIPHERSUITE_MAP.get(cipherSuiteName);
    }

    static String getCipherSuiteName(int cipherSuite)
    {
        // TODO[jsse] Place into "understood" cipher suite map
        if (CipherSuite.TLS_NULL_WITH_NULL_NULL == cipherSuite)
        {
            return "SSL_NULL_WITH_NULL_NULL";
        }
        if (TlsUtils.isValidUint16(cipherSuite))
        {
            // TODO[jsse] Add CipherSuiteInfo index by 'int'
            for (CipherSuiteInfo cipherSuiteInfo : SUPPORTED_CIPHERSUITE_MAP.values())
            {
                if (cipherSuiteInfo.getCipherSuite() == cipherSuite)
                {
                    return cipherSuiteInfo.getName();
                }
            }
        }
        return null;
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

    static String getProtocolVersionName(ProtocolVersion protocolVersion)
    {
        if (null != protocolVersion)
        {
            for (Map.Entry<String, ProtocolVersion> entry : SUPPORTED_PROTOCOL_MAP.entrySet())
            {
                if (entry.getValue().equals(protocolVersion))
                {
                    return entry.getKey();
                }
            }
        }
        return "NONE";
    }

    protected final boolean isInFipsMode;
    protected final TlsCryptoProvider cryptoProvider;

    protected final Map<String, CipherSuiteInfo> supportedCipherSuites;
    protected final Map<String, ProtocolVersion> supportedProtocols;
    protected final String[] defaultCipherSuites;
    protected final String[] defaultProtocolsClient;
    protected final String[] defaultProtocolsServer;

    protected boolean initialized = false;

    private TlsCrypto crypto;
    private X509ExtendedKeyManager x509KeyManager;
    private BCX509ExtendedTrustManager x509TrustManager;
    private ProvSSLSessionContext clientSessionContext;
    private ProvSSLSessionContext serverSessionContext;

    ProvSSLContextSpi(boolean isInFipsMode, TlsCryptoProvider cryptoProvider, String[] specifiedProtocolsClient)
    {
        this.isInFipsMode = isInFipsMode;
        this.cryptoProvider = cryptoProvider;

        this.supportedCipherSuites = isInFipsMode ? SUPPORTED_CIPHERSUITE_MAP_FIPS : SUPPORTED_CIPHERSUITE_MAP;
        this.supportedProtocols = isInFipsMode ? SUPPORTED_PROTOCOL_MAP_FIPS : SUPPORTED_PROTOCOL_MAP;
        this.defaultCipherSuites = getDefaultCipherSuites(isInFipsMode);
        this.defaultProtocolsClient = getDefaultEnabledProtocolsClient(supportedProtocols, specifiedProtocolsClient);
        this.defaultProtocolsServer = getDefaultEnabledProtocolsServer(supportedProtocols);
    }

    ProvSSLSessionContext createSSLSessionContext()
    {
        return new ProvSSLSessionContext(this, crypto);
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

    int[] getActiveCipherSuites(TlsCrypto crypto, ProvSSLParameters sslParameters,
        ProtocolVersion[] activeProtocolVersions)
    {
        String[] enabledCipherSuites = sslParameters.getCipherSuitesArray();
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();

        int[] result = new int[enabledCipherSuites.length];

        int count = 0;
        for (String enabledCipherSuite : enabledCipherSuites)
        {
            CipherSuiteInfo candidate = supportedCipherSuites.get(enabledCipherSuite);
            if (null == candidate)
            {
                continue;
            }
            if (!algorithmConstraints.permits(JsseUtils.TLS_CRYPTO_PRIMITIVES_BC, enabledCipherSuite, null))
            {
                continue;
            }

            /*
             * TODO[jsse] SunJSSE also checks that the cipher suite is usable for at least one of
             * the active protocol versions. Also, if the cipher suite involves a key exchange,
             * there must be at least one suitable NamedGroup available.
             */

            result[count++] = candidate.getCipherSuite();
        }

        return TlsUtils.getSupportedCipherSuites(crypto, result, count);
    }

    ProtocolVersion[] getActiveProtocolVersions(ProvSSLParameters sslParameters)
    {
//        String[] enabledCipherSuites = sslParameters.getCipherSuitesArray();
        String[] enabledProtocols = sslParameters.getProtocolsArray();
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();

        SortedSet<ProtocolVersion> result = new TreeSet<ProtocolVersion>(new Comparator<ProtocolVersion>(){
            public int compare(ProtocolVersion o1, ProtocolVersion o2)
            {
                return o1.isLaterVersionOf(o2) ? -1 : o2.isLaterVersionOf(o1) ? 1 : 0;
            }
        });

        for (String enabledProtocol : enabledProtocols)
        {
            ProtocolVersion candidate = supportedProtocols.get(enabledProtocol);
            if (null == candidate)
            {
                continue;
            }
            if (!algorithmConstraints.permits(JsseUtils.TLS_CRYPTO_PRIMITIVES_BC, enabledProtocol, null))
            {
                continue;
            }

            /*
             * TODO[jsse] SunJSSE also checks that there is at least one "activatable" cipher suite
             * that could be used for this protocol version.
             */

            result.add(candidate);
        }

        return result.toArray(new ProtocolVersion[result.size()]);
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

    String[] getSupportedProtocols()
    {
        return getKeysArray(supportedProtocols);
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

    void validateNegotiatedCipherSuite(ProvSSLParameters sslParameters, int cipherSuite)
    {
        // NOTE: The redundancy among these various checks is intentional
        String name = getCipherSuiteName(cipherSuite);
        if (null == name
            || !JsseUtils.contains(sslParameters.getCipherSuitesArray(), name)
            || !sslParameters.getAlgorithmConstraints().permits(JsseUtils.TLS_CRYPTO_PRIMITIVES_BC, name, null)
            || !supportedCipherSuites.containsKey(name)
            || (isInFipsMode && !FipsUtils.isFipsCipherSuite(name)))
        {
            throw new IllegalStateException("SSL connection negotiated unsupported ciphersuite: " + cipherSuite);
        }
    }

    void validateNegotiatedProtocol(ProvSSLParameters sslParameters, ProtocolVersion protocol)
    {
        // NOTE: The redundancy among these various checks is intentional
        String name = getProtocolVersionName(protocol);
        if (null == name
            || !JsseUtils.contains(sslParameters.getProtocolsArray(), name)
            || !sslParameters.getAlgorithmConstraints().permits(JsseUtils.TLS_CRYPTO_PRIMITIVES_BC, name, null)
            || !supportedProtocols.containsKey(name)
            || (isInFipsMode && !FipsUtils.isFipsProtocol(name)))
        {
            throw new IllegalStateException("SSL connection negotiated unsupported protocol: " + protocol);
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
