package org.bouncycastle.jsse.provider.test;

import java.security.AccessController;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import junit.framework.Test;
import junit.framework.TestSuite;

public class CipherSuitesTestSuite
    extends TestSuite
{
    static final boolean hasSslParameters;

    static
    {
        Class<?> clazz;
        try
        {
            clazz = loadClass("javax.net.ssl.SSLParameters");
        }
        catch (Exception e)
        {
            clazz = null;
        }

        hasSslParameters = (clazz != null);
    }

    private static Class<?> loadClass(final String className)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Class<?>>()
        {
            public Class<?> run()
            {
                try
                {
                    ClassLoader classLoader = CipherSuitesTestSuite.class.getClassLoader();
                    return (null == classLoader)
                        ?   Class.forName(className)
                        :   classLoader.loadClass(className);
                }
                catch (Exception e)
                {
                }

                return null;
            }
        });
    }

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

        SSLContext sslContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
        String[] cipherSuites;
        if (hasSslParameters)
        {
            cipherSuites = sslContext.getSupportedSSLParameters().getCipherSuites();
        }
        else
        {
            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
                BouncyCastleJsseProvider.PROVIDER_NAME);

            trustMgrFact.init(ts);

            sslContext.init(null, trustMgrFact.getTrustManagers(),
                SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));
            cipherSuites = sslContext.getSocketFactory().getSupportedCipherSuites();
        }

        Arrays.sort(cipherSuites);


        for (int t = 0; t < cipherSuites.length; t++)
        {
            String cipherSuite = cipherSuites[t];

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
