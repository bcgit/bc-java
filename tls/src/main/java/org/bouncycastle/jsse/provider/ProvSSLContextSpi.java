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
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;
import org.bouncycastle.jsse.java.security.BCAlgorithmConstraints;
import org.bouncycastle.jsse.java.security.BCCryptoPrimitive;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

class ProvSSLContextSpi
    extends SSLContextSpi
{
    private static final Logger LOG = Logger.getLogger(ProvSSLContextSpi.class.getName());

    private static final String PROPERTY_CLIENT_PROTOCOLS = "jdk.tls.client.protocols";
    private static final String PROPERTY_SERVER_PROTOCOLS = "jdk.tls.server.protocols";

    private static final Set<BCCryptoPrimitive> TLS_CRYPTO_PRIMITIVES_BC = JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;

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

    // TODO[tls13] Enable TLSv1.3 by default in due course
    private static final String[] DEFAULT_ENABLED_PROTOCOLS = new String[]{ "TLSv1.2", "TLSv1.1", "TLSv1" };

    private static void addCipherSuite(Map<String, CipherSuiteInfo> cs, String name, int cipherSuite)
    {
        addCipherSuite(cs, name, cipherSuite, false);
    }

    private static void addCipherSuite13(Map<String, CipherSuiteInfo> cs, String name, int cipherSuite)
    {
        addCipherSuite(cs, name, cipherSuite, true);
    }

    private static void addCipherSuite(Map<String, CipherSuiteInfo> cs, String name, int cipherSuite, boolean isTLSv13)
    {
        CipherSuiteInfo cipherSuiteInfo = CipherSuiteInfo.forCipherSuite(cipherSuite, name, isTLSv13);

        if (null != cs.put(name, cipherSuiteInfo))
        {
            throw new IllegalStateException("Duplicate names in supported-cipher-suites");
        }
    }

    private static List<String> createDefaultCipherSuiteList(Set<String> supportedCipherSuiteSet)
    {
        ArrayList<String> cs = new ArrayList<String>();

        // TLS 1.3+
        cs.add("TLS_CHACHA20_POLY1305_SHA256");
        cs.add("TLS_AES_256_GCM_SHA384");
        cs.add("TLS_AES_128_GCM_SHA256");

        // TLS 1.2-
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

        // TLS 1.3+
        addCipherSuite13(cs, "TLS_AES_128_CCM_8_SHA256", CipherSuite.TLS_AES_128_CCM_8_SHA256);
        addCipherSuite13(cs, "TLS_AES_128_CCM_SHA256", CipherSuite.TLS_AES_128_CCM_SHA256);
        addCipherSuite13(cs, "TLS_AES_128_GCM_SHA256", CipherSuite.TLS_AES_128_GCM_SHA256);
        addCipherSuite13(cs, "TLS_AES_256_GCM_SHA384", CipherSuite.TLS_AES_256_GCM_SHA384);
        addCipherSuite13(cs, "TLS_CHACHA20_POLY1305_SHA256", CipherSuite.TLS_CHACHA20_POLY1305_SHA256);

        // TLS 1.2-
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", CipherSuite.TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", CipherSuite.TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384);

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
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", CipherSuite.TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", CipherSuite.TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256);
        addCipherSuite(cs, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384);
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
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA);

        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384);
        addCipherSuite(cs, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384);
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
        addCipherSuite(cs, "TLS_RSA_WITH_ARIA_128_CBC_SHA256", CipherSuite.TLS_RSA_WITH_ARIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_RSA_WITH_ARIA_128_GCM_SHA256", CipherSuite.TLS_RSA_WITH_ARIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_RSA_WITH_ARIA_256_CBC_SHA384", CipherSuite.TLS_RSA_WITH_ARIA_256_CBC_SHA384);
        addCipherSuite(cs, "TLS_RSA_WITH_ARIA_256_GCM_SHA384", CipherSuite.TLS_RSA_WITH_ARIA_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256);
        addCipherSuite(cs, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_RSA_WITH_NULL_SHA", CipherSuite.TLS_RSA_WITH_NULL_SHA);
        addCipherSuite(cs, "TLS_RSA_WITH_NULL_SHA256", CipherSuite.TLS_RSA_WITH_NULL_SHA256);

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
        ps.put("TLSv1.3", ProtocolVersion.TLSv13);
        ps.put("TLSv1.2", ProtocolVersion.TLSv12);
        ps.put("TLSv1.1", ProtocolVersion.TLSv11);
        ps.put("TLSv1", ProtocolVersion.TLSv10);
        ps.put("SSLv3", ProtocolVersion.SSLv3);
        return Collections.unmodifiableMap(ps);
    }

    private static Map<String, ProtocolVersion> createSupportedProtocolMapFips(
        Map<String, ProtocolVersion> supportedProtocolMap)
    {
        final Map<String, ProtocolVersion> ps = new LinkedHashMap<String, ProtocolVersion>(supportedProtocolMap);
        FipsUtils.removeNonFipsProtocols(ps.keySet());
        return Collections.unmodifiableMap(ps);
    }

    private static String[] getDefaultEnabledCipherSuites(boolean isInFipsMode)
    {
        /*
         * TODO[jsse] SunJSSE also filters this initial list based on the default protocol versions.
         */

        List<String> candidates = isInFipsMode ? DEFAULT_CIPHERSUITE_LIST_FIPS : DEFAULT_CIPHERSUITE_LIST;
        String[] result = new String[candidates.size()];

        int count = 0;
        for (String candidate : candidates)
        {
            if (ProvAlgorithmConstraints.DEFAULT.permits(TLS_CRYPTO_PRIMITIVES_BC, candidate, null))
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
            if (!ProvAlgorithmConstraints.DEFAULT_TLS_ONLY.permits(TLS_CRYPTO_PRIMITIVES_BC, candidate, null))
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

    static ProtocolVersion getProtocolVersion(String protocolVersionName)
    {
        return SUPPORTED_PROTOCOL_MAP.get(protocolVersionName);
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
    protected final JcaTlsCryptoProvider cryptoProvider;

    protected final Map<String, CipherSuiteInfo> supportedCipherSuites;
    protected final Map<String, ProtocolVersion> supportedProtocols;
    protected final String[] defaultCipherSuites;
    protected final String[] defaultProtocolsClient;
    protected final String[] defaultProtocolsServer;

    private ContextData contextData = null;

    ProvSSLContextSpi(boolean isInFipsMode, JcaTlsCryptoProvider cryptoProvider, String[] specifiedProtocolsClient)
    {
        this.isInFipsMode = isInFipsMode;
        this.cryptoProvider = cryptoProvider;

        this.supportedCipherSuites = isInFipsMode ? SUPPORTED_CIPHERSUITE_MAP_FIPS : SUPPORTED_CIPHERSUITE_MAP;
        this.supportedProtocols = isInFipsMode ? SUPPORTED_PROTOCOL_MAP_FIPS : SUPPORTED_PROTOCOL_MAP;
        this.defaultCipherSuites = getDefaultEnabledCipherSuites(isInFipsMode);
        this.defaultProtocolsClient = getDefaultEnabledProtocolsClient(supportedProtocols, specifiedProtocolsClient);
        this.defaultProtocolsServer = getDefaultEnabledProtocolsServer(supportedProtocols);
    }

    int[] getActiveCipherSuites(JcaTlsCrypto crypto, ProvSSLParameters sslParameters,
        ProtocolVersion[] activeProtocolVersions)
    {
        String[] enabledCipherSuites = sslParameters.getCipherSuitesArray();
        BCAlgorithmConstraints algorithmConstraints = sslParameters.getAlgorithmConstraints();

        ProtocolVersion latest = ProtocolVersion.getLatestTLS(activeProtocolVersions);
        ProtocolVersion earliest = ProtocolVersion.getEarliestTLS(activeProtocolVersions);

        boolean post13Active = TlsUtils.isTLSv13(latest);
        boolean pre13Active = !TlsUtils.isTLSv13(earliest);

        int[] candidates = new int[enabledCipherSuites.length];

        int count = 0;
        for (String enabledCipherSuite : enabledCipherSuites)
        {
            CipherSuiteInfo candidate = supportedCipherSuites.get(enabledCipherSuite);
            if (null == candidate)
            {
                continue;
            }
            if (candidate.isTLSv13())
            {
                if (!post13Active)
                {
                    continue;
                }
            }
            else
            {
                if (!pre13Active)
                {
                    continue;
                }
            }
            if (!algorithmConstraints.permits(TLS_CRYPTO_PRIMITIVES_BC, enabledCipherSuite, null))
            {
                continue;
            }

            /*
             * TODO[jsse] SunJSSE also checks that the cipher suite is usable for at least one of
             * the active protocol versions. Also, if the cipher suite involves a key exchange,
             * there must be at least one suitable NamedGroup available.
             */

            candidates[count++] = candidate.getCipherSuite();
        }

        /*
         * TODO Move cipher suite management into CipherSuiteInfo (PerConnection/PerContext pattern
         * like NamedGroupInfo) to avoid unnecessary repetition of these sorts of checks.
         */
        int[] result = TlsUtils.getSupportedCipherSuites(crypto, candidates, count);

        if (result.length < 1)
        {
            // TODO[jsse] Refactor so that this can be an SSLHandshakeException?
            throw new IllegalStateException("No usable cipher suites enabled");
        }

        return result;
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
            if (!algorithmConstraints.permits(TLS_CRYPTO_PRIMITIVES_BC, enabledProtocol, null))
            {
                continue;
            }

            /*
             * TODO[jsse] SunJSSE also checks that there is at least one "activatable" cipher suite
             * that could be used for this protocol version.
             */

            result.add(candidate);
        }

        if (result.isEmpty())
        {
            // TODO[jsse] Refactor so that this can be an SSLHandshakeException?
            throw new IllegalStateException("No usable protocols enabled");
        }

        return result.toArray(new ProtocolVersion[result.size()]);
    }

    String[] getDefaultCipherSuites(boolean isClient)
    {
        return implGetDefaultCipherSuites(isClient).clone();
    }

    String[] getDefaultProtocols(boolean isClient)
    {
        return implGetDefaultProtocols(isClient).clone();
    }

    ProvSSLParameters getDefaultSSLParameters(boolean isClient)
    {
        return new ProvSSLParameters(this, implGetDefaultCipherSuites(isClient), implGetDefaultProtocols(isClient));
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

        // NOTE: This method must always return a copy, so no fast path when all supported
        return getArray(result);
    }

    String[] getSupportedProtocols()
    {
        return getKeysArray(supportedProtocols);
    }

    ProvSSLParameters getSupportedSSLParameters(boolean isClient)
    {
        return new ProvSSLParameters(this, getSupportedCipherSuites(), getSupportedProtocols());
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

    void updateDefaultSSLParameters(ProvSSLParameters sslParameters, boolean isClient)
    {
        if (sslParameters.getCipherSuitesArray() == implGetDefaultCipherSuites(!isClient))
        {
            sslParameters.setCipherSuitesArray(implGetDefaultCipherSuites(isClient));
        }
        if (sslParameters.getProtocolsArray() == implGetDefaultProtocols(!isClient))
        {
            sslParameters.setProtocolsArray(implGetDefaultProtocols(isClient));
        }
    }

    String validateNegotiatedCipherSuite(ProvSSLParameters sslParameters, int cipherSuite)
    {
        // NOTE: The redundancy among these various checks is intentional
        String name = getCipherSuiteName(cipherSuite);
        if (null == name
            || !JsseUtils.contains(sslParameters.getCipherSuitesArray(), name)
            || !sslParameters.getAlgorithmConstraints().permits(TLS_CRYPTO_PRIMITIVES_BC, name, null)
            || !supportedCipherSuites.containsKey(name)
            || (isInFipsMode && !FipsUtils.isFipsCipherSuite(name)))
        {
            throw new IllegalStateException("SSL connection negotiated unsupported ciphersuite: " + cipherSuite);
        }
        return name;
    }

    String validateNegotiatedProtocol(ProvSSLParameters sslParameters, ProtocolVersion protocol)
    {
        // NOTE: The redundancy among these various checks is intentional
        String name = getProtocolVersionName(protocol);
        if (null == name
            || !JsseUtils.contains(sslParameters.getProtocolsArray(), name)
            || !sslParameters.getAlgorithmConstraints().permits(TLS_CRYPTO_PRIMITIVES_BC, name, null)
            || !supportedProtocols.containsKey(name)
            || (isInFipsMode && !FipsUtils.isFipsProtocol(name)))
        {
            throw new IllegalStateException("SSL connection negotiated unsupported protocol: " + protocol);
        }
        return name;
    }

    @Override
    protected synchronized SSLEngine engineCreateSSLEngine()
    {
        return SSLEngineUtil.create(getContextData());
    }

    @Override
    protected synchronized SSLEngine engineCreateSSLEngine(String host, int port)
    {
        return SSLEngineUtil.create(getContextData(), host, port);
    }

    @Override
    protected synchronized SSLSessionContext engineGetClientSessionContext()
    {
        return getContextData().getClientSessionContext();
    }

    @Override
    protected synchronized SSLSessionContext engineGetServerSessionContext()
    {
        return getContextData().getServerSessionContext();
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory()
    {
        return new ProvSSLServerSocketFactory(getContextData());
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory()
    {
        return new ProvSSLSocketFactory(getContextData());
    }

    // An SSLContextSpi method from JDK 6
    protected SSLParameters engineGetDefaultSSLParameters()
    {
        // Fail if uninitialized
        getContextData();

        // Implicitly for a client socket
        return SSLParametersUtil.getSSLParameters(getDefaultSSLParameters(true));
    }

    // An SSLContextSpi method from JDK 6
    protected SSLParameters engineGetSupportedSSLParameters()
    {
        // Fail if uninitialized
        getContextData();

        // Implicitly for a client socket
        return SSLParametersUtil.getSSLParameters(getSupportedSSLParameters(true));
    }

    @Override
    protected synchronized void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException
    {
        this.contextData = null;

        JcaTlsCrypto crypto = cryptoProvider.create(sr);
        BCX509ExtendedKeyManager x509KeyManager = selectX509KeyManager(crypto.getHelper(), kms);
        BCX509ExtendedTrustManager x509TrustManager = selectX509TrustManager(crypto.getHelper(), tms);

        // Trigger (possibly expensive) RNG initialization here to avoid timeout in an actual handshake
        crypto.getSecureRandom().nextInt();

        this.contextData = new ContextData(this, crypto, x509KeyManager, x509TrustManager);
    }

    protected synchronized ContextData getContextData()
    {
        if (null == contextData)
        {
            throw new IllegalStateException("SSLContext has not been initialized.");
        }

        return contextData;
    }

    protected BCX509ExtendedKeyManager selectX509KeyManager(JcaJceHelper helper, KeyManager[] kms)
        throws KeyManagementException
    {
        if (kms != null)
        {
            for (KeyManager km : kms)
            {
                if (km instanceof X509KeyManager)
                {
                    return X509KeyManagerUtil.importX509KeyManager(helper, (X509KeyManager)km);
                }
            }
        }
        return DummyX509KeyManager.INSTANCE;
    }

    protected BCX509ExtendedTrustManager selectX509TrustManager(JcaJceHelper helper, TrustManager[] tms)
        throws KeyManagementException
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
                    return X509TrustManagerUtil.importX509TrustManager(isInFipsMode, helper, (X509TrustManager)tm);
                }
            }
        }
        return DummyX509TrustManager.INSTANCE;
    }

    private String[] implGetDefaultCipherSuites(boolean isClient)
    {
        return defaultCipherSuites;
    }

    private String[] implGetDefaultProtocols(boolean isClient)
    {
        return isClient ? defaultProtocolsClient : defaultProtocolsServer;
    }
}
