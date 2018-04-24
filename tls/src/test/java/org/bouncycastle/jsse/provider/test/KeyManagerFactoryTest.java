package org.bouncycastle.jsse.provider.test;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Principal;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class KeyManagerFactoryTest
    extends TestCase
{
    private static final char[] PASSWORD = "fred".toCharArray();

    protected void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleJsseProvider());
        }
    }

    public void testBasicRSA()
        throws Exception
    {
        KeyManagerFactory fact = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);

        KeyStore ks = getRsaKeyStore(true);

        fact.init(ks, PASSWORD);

        KeyManager[] managers = fact.getKeyManagers();

        X509ExtendedKeyManager manager = (X509ExtendedKeyManager)managers[0];

        String alias = manager.chooseServerAlias("RSA", null, null);

        assertNotNull(alias);

        assertNotNull(manager.getCertificateChain(alias));

        assertNotNull(manager.getPrivateKey(alias));

        alias = manager.chooseServerAlias("RSA", new Principal[] { new X500Principal("CN=TLS Test") }, null);

        assertNull(alias);

        alias = manager.chooseServerAlias("RSA", new Principal[] { new X500Principal("CN=TLS Test CA") }, null);

        assertNotNull(alias);

        assertNotNull(manager.getCertificateChain(alias));

        assertNotNull(manager.getPrivateKey(alias));
    }

    public void testBasicEC()
        throws Exception
    {
        KeyManagerFactory fact = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);

        KeyStore ks = getEcKeyStore(false);

        fact.init(ks, PASSWORD);

        KeyManager[] managers = fact.getKeyManagers();

        X509ExtendedKeyManager manager = (X509ExtendedKeyManager)managers[0];

        String alias = manager.chooseServerAlias("ECDHE_ECDSA", null, null);

        assertNotNull(alias);

        assertNotNull(manager.getCertificateChain(alias));

        assertNotNull(manager.getPrivateKey(alias));

        alias = manager.chooseServerAlias("ECDHE_ECDSA", new Principal[] { new X500Principal("CN=TLS Test") }, null);

        assertNull(alias);

        alias = manager.chooseServerAlias("ECDHE_ECDSA", new Principal[] { new X500Principal("CN=TLS Test CA") }, null);

        assertNotNull(alias);

        assertNotNull(manager.getCertificateChain(alias));

        assertNotNull(manager.getPrivateKey(alias));
    }

    private KeyStore getRsaKeyStore(boolean encryption)
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance("JKS");

        KeyPair rPair = TestUtils.generateRSAKeyPair();
        KeyPair iPair = TestUtils.generateRSAKeyPair();
        KeyPair ePair = TestUtils.generateRSAKeyPair();

        X509Certificate rCert = TestUtils.generateRootCert(rPair);
        X509Certificate iCert = TestUtils.generateIntermediateCert(iPair.getPublic(), new X500Name("CN=TLS Test CA"), rPair.getPrivate(), rCert);

        X509Certificate eCert;
        if (encryption)
        {
            eCert = TestUtils.generateEndEntityCertEnc(ePair.getPublic(), new X500Name("CN=TLS Test"), iPair.getPrivate(), iCert);
        }
        else
        {
            eCert = TestUtils.generateEndEntityCertSign(ePair.getPublic(), new X500Name("CN=TLS Test"), iPair.getPrivate(), iCert);
        }

        ks.load(null, PASSWORD);

        ks.setKeyEntry("test", ePair.getPrivate(), PASSWORD, new Certificate[] { eCert, iCert });

        ks.setCertificateEntry("root", rCert);

        return ks;
    }

    private KeyStore getEcKeyStore(boolean agreement)
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance("JKS");

        KeyPair rPair = TestUtils.generateECKeyPair();
        KeyPair iPair = TestUtils.generateECKeyPair();
        KeyPair ePair = TestUtils.generateECKeyPair();

        X509Certificate rCert = TestUtils.generateRootCert(rPair);
        X509Certificate iCert = TestUtils.generateIntermediateCert(iPair.getPublic(), new X500Name("CN=TLS Test CA"), rPair.getPrivate(), rCert);

        X509Certificate eCert;
        if (agreement)
        {
            eCert = TestUtils.generateEndEntityCertAgree(ePair.getPublic(), new X500Name("CN=TLS Test"), iPair.getPrivate(), iCert);
        }
        else
        {
            eCert = TestUtils.generateEndEntityCertSign(ePair.getPublic(), new X500Name("CN=TLS Test"), iPair.getPrivate(), iCert);
        }

        ks.load(null, PASSWORD);

        ks.setKeyEntry("test", ePair.getPrivate(), PASSWORD, new Certificate[] { eCert, iCert });

        ks.setCertificateEntry("root", rCert);

        return ks;
    }

    public void testRSAServer()
        throws Exception
    {
        KeyStore ks = getRsaKeyStore(true);

        KeyStore trustStore = KeyStore.getInstance("JKS");

        trustStore.load(null, PASSWORD);

        trustStore.setCertificateEntry("server", ks.getCertificate("root"));

        SSLUtils.startServer(ks, PASSWORD, trustStore, false, 8886);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);

        trustManagerFactory.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS");

        context.init(null, trustManagerFactory.getTrustManagers(), null);

        SSLSocketFactory f = context.getSocketFactory();

        SSLSocket c = (SSLSocket)f.createSocket("localhost", 8886);
        c.setUseClientMode(true);

        SSLUtils.restrictKeyExchange(c, "RSA");

        c.getOutputStream().write('!');

        c.getInputStream().read();

    }

    public void testRSAServerTrustEE()
        throws Exception
    {
        KeyStore ks = getRsaKeyStore(true);

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, PASSWORD);
        trustStore.setCertificateEntry("server", ks.getCertificate("root"));

        SSLUtils.startServer(ks, PASSWORD, trustStore, false, 8886);

        /*
         * For this variation we add the server's certificate to the client's trust store directly, instead of the root (TA).
         */
        trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, PASSWORD);
        trustStore.setCertificateEntry("server", ks.getCertificate("test"));

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        trustManagerFactory.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS");

        context.init(null, trustManagerFactory.getTrustManagers(), null);

        SSLSocketFactory f = context.getSocketFactory();

        SSLSocket c = (SSLSocket)f.createSocket("localhost", 8886);
        c.setUseClientMode(true);

        SSLUtils.restrictKeyExchange(c, "RSA");

        c.getOutputStream().write('!');

        c.getInputStream().read();
    }

    public void testRSAServerWithClientAuth()
        throws Exception
    {
        KeyStore clientKS = getRsaKeyStore(false);
        KeyStore serverKS = getRsaKeyStore(true);

        KeyStore serverTS = KeyStore.getInstance("JKS");
        serverTS.load(null, PASSWORD);
        serverTS.setCertificateEntry("clientRoot", clientKS.getCertificate("root"));

        SSLUtils.startServer(serverKS, PASSWORD, serverTS, true, 8887);

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        keyManagerFactory.init(clientKS, PASSWORD);

        KeyStore clientTS = KeyStore.getInstance("JKS");
        clientTS.load(null, PASSWORD);
        clientTS.setCertificateEntry("serverRoot", serverKS.getCertificate("root"));

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
        trustManagerFactory.init(clientTS);

        SSLContext context = SSLContext.getInstance("TLS");

        context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        SSLSocketFactory f = context.getSocketFactory();

        SSLSocket c = (SSLSocket)f.createSocket("localhost", 8887);
        c.setUseClientMode(true);

        SSLUtils.restrictKeyExchange(c, "RSA");

        c.getOutputStream().write('!');

        c.getInputStream().read();

    }
}
