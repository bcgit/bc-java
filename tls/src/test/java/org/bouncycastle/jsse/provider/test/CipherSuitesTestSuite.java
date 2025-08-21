package org.bouncycastle.jsse.provider.test;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLContext;

import junit.extensions.TestSetup;
import junit.framework.Assert;
import junit.framework.Test;
import junit.framework.TestSuite;

public class CipherSuitesTestSuite
    extends TestSuite
{
    public CipherSuitesTestSuite()
    {
        super("CipherSuites");
    }

    public static Test suite()
        throws Exception
    {
        ProviderUtils.setupHighPriority(false);

        TestSuite suite = createSuite(new CipherSuitesTestSuite(), null, false, new CipherSuitesFilter()
        {
            public boolean isIgnored(String cipherSuite)
            {
                /*
                 * TODO[jsse] jdk.tls.disabledAlgorithms default value doesn't permit these. Perhaps
                 * we could modify that security property when running this test suite.
                 */
                return cipherSuite.contains("_WITH_NULL_") || cipherSuite.contains("_WITH_3DES_EDE_CBC_")
                    || cipherSuite.contains("_anon_") || cipherSuite.startsWith("TLS_SHA");
            }

            public boolean isPermitted(String cipherSuite)
            {
                return true;
            }
        });

        return new TestSetup(suite)
        {
            @Override
            protected void setUp() throws Exception
            {
                ProviderUtils.setupHighPriority(false);
            }
        };
    }

    static TestSuite createSuite(TestSuite testSuite, String category, boolean fips, CipherSuitesFilter filter)
        throws Exception
    {
        char[] serverPassword = "serverPassword".toCharArray();

        KeyPair caKeyPairDSA = TestUtils.generateDSAKeyPair();
        KeyPair caKeyPairEC = TestUtils.generateECKeyPair();
        KeyPair caKeyPairRSA = TestUtils.generateRSAKeyPair();

        X509Certificate caCertDSA = TestUtils.generateRootCert(caKeyPairDSA);
        X509Certificate caCertEC = TestUtils.generateRootCert(caKeyPairEC);
        X509Certificate caCertRSA = TestUtils.generateRootCert(caKeyPairRSA);

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("serverDSA", caKeyPairDSA.getPrivate(), serverPassword, new X509Certificate[]{ caCertDSA });
        ks.setKeyEntry("serverEC", caKeyPairEC.getPrivate(), serverPassword, new X509Certificate[]{ caCertEC });
        ks.setKeyEntry("serverRSA", caKeyPairRSA.getPrivate(), serverPassword, new X509Certificate[]{ caCertRSA });

        KeyStore ts = KeyStore.getInstance("JKS");
        ts.load(null, null);
        ts.setCertificateEntry("caDSA", caCertDSA);
        ts.setCertificateEntry("caEC", caCertEC);
        ts.setCertificateEntry("caRSA", caCertRSA);

        SSLContext defaultSSLContext = SSLContext.getInstance("Default", ProviderUtils.PROVIDER_NAME_BCJSSE);

        String[] cipherSuites = defaultSSLContext.getSocketFactory().getSupportedCipherSuites();
        for (int i = 0; i < cipherSuites.length; ++i)
        {
            if (!filter.isPermitted(cipherSuites[i]))
            {
                Assert.fail("Cipher suite not permitted in supported cipher suites: " + cipherSuites[i]);
            }
        }
        Arrays.sort(cipherSuites);

        for (String protocol : TestUtils.getTestableProtocols(defaultSSLContext, fips))
        {
            boolean isTLSv13Protocol = "TLSv1.3".equals(protocol);
            boolean isTLSv12Protocol = "TLSv1.2".equals(protocol);

            for (int t = 0; t < cipherSuites.length; t++)
            {
                String cipherSuite = cipherSuites[t];
                if (filter.isIgnored(cipherSuite))
                {
                    continue;
                }

                boolean isTLSv13CipherSuite = !cipherSuite.contains("_WITH_");
                if (isTLSv13CipherSuite != isTLSv13Protocol)
                {
                    // TLS 1.3 uses a distinct set of cipher suites that don't specify a key exchange
                    continue;
                }

                boolean isTLSv12CipherSuite = !isTLSv13CipherSuite
                    && (cipherSuite.contains("_CHACHA20_POLY1305_") ||
                        cipherSuite.contains("_GCM_") ||
                        cipherSuite.endsWith("_CBC_SHA256") ||
                        cipherSuite.endsWith("_CBC_SHA384") ||
                        cipherSuite.endsWith("_CCM") ||
                        cipherSuite.endsWith("_CCM_8") ||
                        cipherSuite.endsWith("_NULL_SHA256"));
                if (isTLSv12CipherSuite && !isTLSv12Protocol)
                {
                    //  AEAD ciphers and configurable CBC PRFs are both 1.2 features
                    continue;
                }

                /*
                 * TODO[jsse] Note that there may be failures for cipher suites that are listed as supported
                 * even though the TlsCrypto instance doesn't implement them (JcaTlsCrypto is dependent on the
                 * configured crypto providers).
                 */

                CipherSuitesTestConfig config = new CipherSuitesTestConfig();
                config.category = category;
                config.cipherSuite = cipherSuite;
                config.clientTrustStore = ts;
                config.protocol = protocol;
                config.serverKeyStore = ks;
                config.serverPassword = serverPassword;

                testSuite.addTest(new CipherSuitesTestCase(config));
            }
        }

        return testSuite;
    }
}
