package org.bouncycastle.jsse.provider.test;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import junit.framework.Test;
import junit.framework.TestSuite;

public class CipherSuitesTestSuite extends TestSuite
{
    public CipherSuitesTestSuite()
    {
        super("CipherSuites");
    }

    public static Test suite() throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleJsseProvider());
        }

        CipherSuitesTestSuite testSuite = new CipherSuitesTestSuite();

        SSLContext sslContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
        SSLParameters sslParameters = sslContext.getSupportedSSLParameters();
        String[] cipherSuites = sslParameters.getCipherSuites();
        Arrays.sort(cipherSuites);

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

        for (String cipherSuite : cipherSuites)
        {
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
