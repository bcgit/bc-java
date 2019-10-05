package org.bouncycastle.jsse.provider.test;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLContext;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

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
        String javaVersion = System.getProperty("java.version");
        boolean oldJDK = javaVersion.startsWith("1.5") || javaVersion.startsWith("1.6");

        Provider bc = new BouncyCastleProvider();
        Provider bcjsse = oldJDK ? new BouncyCastleJsseProvider(bc) : new BouncyCastleJsseProvider();

        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(bc, 1);

        Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        Security.insertProviderAt(bcjsse, 2);


        CipherSuitesTestSuite testSuite = new CipherSuitesTestSuite();

        char[] serverPassword = "serverPassword".toCharArray();

        KeyPair caKeyPairDSA = TestUtils.generateDSAKeyPair();
        KeyPair caKeyPairEC = TestUtils.generateECKeyPair();
        KeyPair caKeyPairRSA = TestUtils.generateRSAKeyPair();

        X509Certificate caCertDSA = TestUtils.generateRootCert(caKeyPairDSA);
        X509Certificate caCertEC = TestUtils.generateRootCert(caKeyPairEC);
        X509Certificate caCertRSA = TestUtils.generateRootCert(caKeyPairRSA);

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        ks.setKeyEntry("serverDSA", caKeyPairDSA.getPrivate(), serverPassword, new X509Certificate[]{caCertDSA});
        ks.setKeyEntry("serverEC", caKeyPairEC.getPrivate(), serverPassword, new X509Certificate[]{caCertEC});
        ks.setKeyEntry("serverRSA", caKeyPairRSA.getPrivate(), serverPassword, new X509Certificate[]{caCertRSA});

        KeyStore ts = KeyStore.getInstance("JKS");
        ts.load(null, null);
        ts.setCertificateEntry("caDSA", caCertDSA);
        ts.setCertificateEntry("caEC", caCertEC);
        ts.setCertificateEntry("caRSA", caCertRSA);

        SSLContext defaultSSLContext = SSLContext.getInstance("Default", BouncyCastleJsseProvider.PROVIDER_NAME);

        String[] cipherSuites = defaultSSLContext.getSocketFactory().getSupportedCipherSuites();

        Arrays.sort(cipherSuites);


        for (int t = 0; t < cipherSuites.length; t++)
        {
            String cipherSuite = cipherSuites[t];

            if (cipherSuite.contains("_WITH_NULL_") || cipherSuite.contains("_WITH_3DES_EDE_CBC_"))
            {
                /*
                 * TODO[jsse] jdk.tls.disabledAlgorithms default value doesn't permit these. Perhaps
                 * we could modify that security property when running this test suite.
                 */
                continue;
            }

            /*
             * TODO[jsse] Note that there may be failures for cipher suites that are listed as supported
             * even though the TlsCrypto instance doesn't implement them (JcaTlsCrypto is dependent on the
             * configured crypto providers).
             */

            CipherSuitesTestConfig config = new CipherSuitesTestConfig();
            config.cipherSuite = cipherSuite;
            config.clientTrustStore = ts;
            config.serverKeyStore = ks;
            config.serverPassword = serverPassword;

            testSuite.addTest(new CipherSuitesTestCase(config));
        }

        return testSuite;
    }
}
