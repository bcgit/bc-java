package org.bouncycastle.jsse.provider;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
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
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsDHUtils;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

class ProvSSLContextSpi
    extends SSLContextSpi
{
    private static final Logger LOG = Logger.getLogger(ProvSSLContextSpi.class.getName());

    private static final String PROPERTY_CLIENT_CIPHERSUITES = "jdk.tls.client.cipherSuites";
    private static final String PROPERTY_SERVER_CIPHERSUITES = "jdk.tls.server.cipherSuites";

    private static final String PROPERTY_CLIENT_PROTOCOLS = "jdk.tls.client.protocols";
    private static final String PROPERTY_SERVER_PROTOCOLS = "jdk.tls.server.protocols";

    /*
     * TODO[jsse] Should separate this into "understood" cipher suite int<->String maps
     * and a Set of supported cipher suite values, so we can cover TLS_NULL_WITH_NULL_NULL and
     * the SCSV values.
     */
    private static final Map<String, CipherSuiteInfo> SUPPORTED_CIPHERSUITE_MAP = createSupportedCipherSuiteMap();
    private static final Map<String, CipherSuiteInfo> SUPPORTED_CIPHERSUITE_MAP_FIPS =
        createSupportedCipherSuiteMapFips(SUPPORTED_CIPHERSUITE_MAP, false);
    private static final Map<String, CipherSuiteInfo> SUPPORTED_CIPHERSUITE_MAP_FIPS_GCM12 =
        createSupportedCipherSuiteMapFips(SUPPORTED_CIPHERSUITE_MAP, true);

    private static final Map<String, ProtocolVersion> SUPPORTED_PROTOCOL_MAP = createSupportedProtocolMap();
    private static final Map<String, ProtocolVersion> SUPPORTED_PROTOCOL_MAP_FIPS = createSupportedProtocolMapFips(SUPPORTED_PROTOCOL_MAP);

    private static final List<String> DEFAULT_CIPHERSUITE_LIST =
        createDefaultCipherSuiteList(SUPPORTED_CIPHERSUITE_MAP.keySet());
    private static final List<String> DEFAULT_CIPHERSUITE_LIST_FIPS =
        createDefaultCipherSuiteListFips(DEFAULT_CIPHERSUITE_LIST, false);
    private static final List<String> DEFAULT_CIPHERSUITE_LIST_FIPS_GCM12 =
        createDefaultCipherSuiteListFips(DEFAULT_CIPHERSUITE_LIST, true);

    private static final List<String> DEFAULT_PROTOCOL_LIST = createDefaultProtocolList(SUPPORTED_PROTOCOL_MAP.keySet());
    private static final List<String> DEFAULT_PROTOCOL_LIST_FIPS = createDefaultProtocolListFips(DEFAULT_PROTOCOL_LIST);

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

        // TLS 1.3+

        cs.add("TLS_CHACHA20_POLY1305_SHA256");
        cs.add("TLS_AES_256_GCM_SHA384");
        cs.add("TLS_AES_128_GCM_SHA256");

        // TLS 1.2-

        cs.add("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");

        cs.add("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");

        cs.add("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256");
        cs.add("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384");
        cs.add("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384");

        cs.add("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");
        cs.add("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256");

        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");

        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");

        cs.add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256");
        cs.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256");

        cs.add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256");
        cs.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256");

        // Legacy

        cs.add("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");

        cs.add("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");

        cs.add("TLS_DHE_RSA_WITH_AES_256_CBC_SHA");
        cs.add("TLS_DHE_DSS_WITH_AES_256_CBC_SHA");

        cs.add("TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
        cs.add("TLS_DHE_DSS_WITH_AES_128_CBC_SHA");

        cs.retainAll(supportedCipherSuiteSet);
        cs.trimToSize();
        return Collections.unmodifiableList(cs);
    }

    private static List<String> createDefaultCipherSuiteListFips(List<String> defaultCipherSuiteList,
        boolean includeGCM12)
    {
        ArrayList<String> cs = new ArrayList<String>(defaultCipherSuiteList);
        FipsUtils.removeNonFipsCipherSuites(cs, includeGCM12);
        cs.trimToSize();
        return Collections.unmodifiableList(cs);
    }

    private static List<String> createDefaultProtocolList(Set<String> supportedProtocolSet)
    {
        ArrayList<String> ps = new ArrayList<String>();

        ps.add("TLSv1.3");
        ps.add("TLSv1.2");
        ps.add("TLSv1.1");
        ps.add("TLSv1");

        ps.retainAll(supportedProtocolSet);
        ps.trimToSize();
        return Collections.unmodifiableList(ps);
    }

    private static List<String> createDefaultProtocolListFips(List<String> defaultProtocolList)
    {
        ArrayList<String> ps = new ArrayList<String>(defaultProtocolList);
        FipsUtils.removeNonFipsProtocols(ps);
        ps.trimToSize();
        return Collections.unmodifiableList(ps);
    }

    private static Map<String, CipherSuiteInfo> createSupportedCipherSuiteMap()
    {
        Map<String, CipherSuiteInfo> cs = new TreeMap<String, CipherSuiteInfo>();

        // TLS 1.3+
        addCipherSuite(cs, "TLS_AES_128_CCM_8_SHA256", CipherSuite.TLS_AES_128_CCM_8_SHA256);
        addCipherSuite(cs, "TLS_AES_128_CCM_SHA256", CipherSuite.TLS_AES_128_CCM_SHA256);
        addCipherSuite(cs, "TLS_AES_128_GCM_SHA256", CipherSuite.TLS_AES_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_AES_256_GCM_SHA384", CipherSuite.TLS_AES_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_CHACHA20_POLY1305_SHA256", CipherSuite.TLS_CHACHA20_POLY1305_SHA256);

        // TLS 1.2-
        addCipherSuite(cs, "TLS_DH_anon_WITH_AES_128_CBC_SHA", CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA);
        addCipherSuite(cs, "TLS_DH_anon_WITH_AES_128_CBC_SHA256", CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_DH_anon_WITH_AES_128_GCM_SHA256", CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_DH_anon_WITH_AES_256_CBC_SHA", CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA);
        addCipherSuite(cs, "TLS_DH_anon_WITH_AES_256_CBC_SHA256", CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256);
        addCipherSuite(cs, "TLS_DH_anon_WITH_AES_256_GCM_SHA384", CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", CipherSuite.TLS_DH_anon_WITH_ARIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", CipherSuite.TLS_DH_anon_WITH_ARIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", CipherSuite.TLS_DH_anon_WITH_ARIA_256_CBC_SHA384);
        addCipherSuite(cs, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", CipherSuite.TLS_DH_anon_WITH_ARIA_256_GCM_SHA384);
        addCipherSuite(cs, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA);
        addCipherSuite(cs, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256);
        addCipherSuite(cs, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256);
        addCipherSuite(cs, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA);
        addCipherSuite(cs, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256);
        addCipherSuite(cs, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384);

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

        addCipherSuite(cs, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA);
        addCipherSuite(cs, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA);
        addCipherSuite(cs, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA);

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
        Map<String, CipherSuiteInfo> supportedCipherSuiteMap, boolean includeGCM12)
    {
        final Map<String, CipherSuiteInfo> cs = new LinkedHashMap<String, CipherSuiteInfo>(supportedCipherSuiteMap);
        FipsUtils.removeNonFipsCipherSuites(cs.keySet(), includeGCM12);
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

    private static String[] getDefaultEnabledCipherSuites(Map<String, CipherSuiteInfo> supportedCipherSuiteMap,
        List<String> defaultCipherSuiteList, boolean disableDHDefaultSuites, String cipherSuitesPropertyName)
    {
        List<String> candidates = getJdkTlsCipherSuites(cipherSuitesPropertyName, defaultCipherSuiteList);

        String[] result = new String[candidates.size()];
        int count = 0;
        for (String candidate : candidates)
        {
            CipherSuiteInfo cipherSuiteInfo = supportedCipherSuiteMap.get(candidate);
            if (null == cipherSuiteInfo)
            {
                continue;
            }
            if (disableDHDefaultSuites &&
                candidates == defaultCipherSuiteList &&
                TlsDHUtils.isDHCipherSuite(cipherSuiteInfo.getCipherSuite()))
            {
                continue;
            }
            if (!ProvAlgorithmConstraints.DEFAULT.permits(JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC, candidate,
                null))
            {
                continue;
            }

            result[count++] = candidate;
        }
        return JsseUtils.resize(result, count);
    }

    private static String[] getDefaultEnabledCipherSuitesClient(Map<String, CipherSuiteInfo> supportedCipherSuiteMap,
        List<String> defaultCipherSuiteList)
    {
        boolean disableDHDefaultSuites = PropertyUtils
            .getBooleanSystemProperty("org.bouncycastle.jsse.client.dh.disableDefaultSuites", false);

        return getDefaultEnabledCipherSuites(supportedCipherSuiteMap, defaultCipherSuiteList, disableDHDefaultSuites,
            PROPERTY_CLIENT_CIPHERSUITES);
    }

    private static String[] getDefaultEnabledCipherSuitesServer(Map<String, CipherSuiteInfo> supportedCipherSuiteMap,
        List<String> defaultCipherSuiteList)
    {
        boolean disableDHDefaultSuites = PropertyUtils
            .getBooleanSystemProperty("org.bouncycastle.jsse.server.dh.disableDefaultSuites", false);

        return getDefaultEnabledCipherSuites(supportedCipherSuiteMap, defaultCipherSuiteList, disableDHDefaultSuites,
            PROPERTY_SERVER_CIPHERSUITES);
    }

    private static String[] getDefaultEnabledProtocols(Map<String, ProtocolVersion> supportedProtocolMap,
        String protocolsPropertyName, List<String> defaultProtocolList, List<String> specifiedProtocols)
    {
        List<String> candidates = specifiedProtocols;
        if (null == candidates)
        {
            candidates = getJdkTlsProtocols(protocolsPropertyName, defaultProtocolList);
        }

        String[] result = new String[candidates.size()];
        int count = 0;
        for (String candidate : candidates)
        {
            if (!supportedProtocolMap.containsKey(candidate))
            {
                continue;
            }
            if (!ProvAlgorithmConstraints.DEFAULT_TLS_ONLY.permits(JsseUtils.KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC,
                candidate, null))
            {
                continue;
            }

            result[count++] = candidate;
        }
        return JsseUtils.resize(result, count);
    }

    private static String[] getDefaultEnabledProtocolsClient(Map<String, ProtocolVersion> supportedProtocolMap,
        List<String> defaultProtocolList, List<String> specifiedProtocols)
    {
        return getDefaultEnabledProtocols(supportedProtocolMap, PROPERTY_CLIENT_PROTOCOLS, defaultProtocolList,
            specifiedProtocols);
    }

    private static String[] getDefaultEnabledProtocolsServer(Map<String, ProtocolVersion> supportedProtocolMap,
        List<String> defaultProtocolList)
    {
        return getDefaultEnabledProtocols(supportedProtocolMap, PROPERTY_SERVER_PROTOCOLS, defaultProtocolList, null);
    }

    private static List<String> getJdkTlsCipherSuites(String cipherSuitesPropertyName,
        List<String> defaultCipherSuiteList)
    {
        String[] cipherSuites = PropertyUtils.getStringArraySystemProperty(cipherSuitesPropertyName);
        if (null == cipherSuites)
        {
            return defaultCipherSuiteList;
        }

        ArrayList<String> result = new ArrayList<String>(cipherSuites.length);
        for (String cipherSuite : cipherSuites)
        {
            if (result.contains(cipherSuite))
            {
                continue;
            }
            if (!SUPPORTED_CIPHERSUITE_MAP.containsKey(cipherSuite))
            {
                LOG.warning("'" + cipherSuitesPropertyName + "' contains unsupported cipher suite: " + cipherSuite);
                continue;
            }

            result.add(cipherSuite);
        }
        if (result.isEmpty())
        {
            LOG.severe("'" + cipherSuitesPropertyName + "' contained no supported cipher suites (ignoring)");
            return defaultCipherSuiteList;
        }
        return result;
    }

    private static List<String> getJdkTlsProtocols(String protocolsPropertyName, List<String> defaultProtocolList)
    {
        String[] protocols = PropertyUtils.getStringArraySystemProperty(protocolsPropertyName);
        if (null == protocols)
        {
            return defaultProtocolList;
        }

        ArrayList<String> result = new ArrayList<String>(protocols.length);
        for (String protocol : protocols)
        {
            if (result.contains(protocol))
            {
                continue;
            }
            if (!SUPPORTED_PROTOCOL_MAP.containsKey(protocol))
            {
                LOG.warning("'" + protocolsPropertyName + "' contains unsupported protocol: " + protocol);
                continue;
            }

            result.add(protocol);
        }
        if (result.isEmpty())
        {
            LOG.severe("'" + protocolsPropertyName + "' contained no supported protocols (ignoring)");
            return defaultProtocolList;
        }
        return result;
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
        // TODO[jsse] Place into "understood" cipher suite map
        if (CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV == cipherSuite)
        {
            return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
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

    protected final boolean fipsMode;
    protected final JcaTlsCryptoProvider cryptoProvider;
    protected final List<String> specifiedProtocolsClient;

    private ContextData contextData = null;

    ProvSSLContextSpi(boolean fipsMode, JcaTlsCryptoProvider cryptoProvider, List<String> specifiedProtocolsClient)
    {
        this.fipsMode = fipsMode;
        this.cryptoProvider = cryptoProvider;
        this.specifiedProtocolsClient = specifiedProtocolsClient;
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
        // Implicitly for a client socket
        return SSLParametersUtil.getSSLParameters(getContextData().getDefaultSSLParameters(true));
    }

    // An SSLContextSpi method from JDK 6
    protected SSLParameters engineGetSupportedSSLParameters()
    {
        // Implicitly for a client socket
        return SSLParametersUtil.getSSLParameters(getContextData().getSupportedSSLParameters(true));
    }

    @Override
    protected synchronized void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException
    {
        this.contextData = null;

        JcaTlsCrypto crypto = cryptoProvider.create(sr);
        JcaJceHelper helper = crypto.getHelper();

        BCX509ExtendedKeyManager x509KeyManager = selectX509KeyManager(helper, kms);
        BCX509ExtendedTrustManager x509TrustManager = selectX509TrustManager(helper, tms);

        // Trigger (possibly expensive) RNG initialization here to avoid timeout in an actual handshake
        crypto.getSecureRandom().nextInt();

        boolean includeGCM12 = crypto.getFipsGCMNonceGeneratorFactory() != null;

        Map<String, CipherSuiteInfo> supportedCipherSuites =
                !fipsMode       ?   SUPPORTED_CIPHERSUITE_MAP
            :   !includeGCM12   ?   SUPPORTED_CIPHERSUITE_MAP_FIPS
            :                       SUPPORTED_CIPHERSUITE_MAP_FIPS_GCM12;

        Map<String, ProtocolVersion> supportedProtocols =
            fipsMode ? SUPPORTED_PROTOCOL_MAP_FIPS : SUPPORTED_PROTOCOL_MAP;

        List<String> defaultCipherSuiteList =
                !fipsMode       ?   DEFAULT_CIPHERSUITE_LIST
            :   !includeGCM12   ?   DEFAULT_CIPHERSUITE_LIST_FIPS
            :                       DEFAULT_CIPHERSUITE_LIST_FIPS_GCM12;

        String[] defaultCipherSuitesClient = getDefaultEnabledCipherSuitesClient(supportedCipherSuites,
            defaultCipherSuiteList);
        String[] defaultCipherSuitesServer = getDefaultEnabledCipherSuitesServer(supportedCipherSuites,
            defaultCipherSuiteList);

        List<String> defaultProtocolList = fipsMode ? DEFAULT_PROTOCOL_LIST_FIPS : DEFAULT_PROTOCOL_LIST;

        String[] defaultProtocolsClient = getDefaultEnabledProtocolsClient(supportedProtocols, defaultProtocolList,
            specifiedProtocolsClient);
        String[] defaultProtocolsServer = getDefaultEnabledProtocolsServer(supportedProtocols, defaultProtocolList);

        this.contextData = new ContextData(fipsMode, crypto, x509KeyManager, x509TrustManager, supportedCipherSuites,
            supportedProtocols, defaultCipherSuitesClient, defaultCipherSuitesServer, defaultProtocolsClient,
            defaultProtocolsServer);
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
                    return X509TrustManagerUtil.importX509TrustManager(fipsMode, helper, (X509TrustManager)tm);
                }
            }
        }
        return DummyX509TrustManager.INSTANCE;
    }
}
