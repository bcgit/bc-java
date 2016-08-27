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
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
    }

    protected void tearDown()
    {
        Security.removeProvider("BCTLS");
    }

    public void testBasicRSA()
        throws Exception
    {
        KeyManagerFactory fact = KeyManagerFactory.getInstance("PKIX", "BCTLS");

        KeyStore ks = getRsaKeyStore();

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
        KeyManagerFactory fact = KeyManagerFactory.getInstance("PKIX", "BCTLS");

        KeyStore ks = getEcKeyStore();

        fact.init(ks, PASSWORD);

        KeyManager[] managers = fact.getKeyManagers();

        X509ExtendedKeyManager manager = (X509ExtendedKeyManager)managers[0];

        String alias = manager.chooseServerAlias("EC", null, null);

        assertNotNull(alias);

        assertNotNull(manager.getCertificateChain(alias));

        assertNotNull(manager.getPrivateKey(alias));

        alias = manager.chooseServerAlias("EC", new Principal[] { new X500Principal("CN=TLS Test") }, null);

        assertNull(alias);

        alias = manager.chooseServerAlias("EC", new Principal[] { new X500Principal("CN=TLS Test CA") }, null);

        assertNotNull(alias);

        assertNotNull(manager.getCertificateChain(alias));

        assertNotNull(manager.getPrivateKey(alias));
    }

    private KeyStore getRsaKeyStore()
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance("JKS");

        KeyPair rPair = TestUtils.generateRSAKeyPair();
        KeyPair iPair = TestUtils.generateRSAKeyPair();
        KeyPair ePair = TestUtils.generateRSAKeyPair();

        X509Certificate rCert = TestUtils.generateRootCert(rPair);
        X509Certificate iCert = TestUtils.generateIntermediateCert(iPair.getPublic(), new X500Name("CN=TLS Test CA"), rPair.getPrivate(), rCert);
        X509Certificate eCert = TestUtils.generateEndEntityCert(ePair.getPublic(), new X500Name("CN=TLS Test"), iPair.getPrivate(), iCert);

        ks.load(null, PASSWORD);

        ks.setKeyEntry("test", ePair.getPrivate(), PASSWORD, new Certificate[] { eCert, iCert });

        ks.setCertificateEntry("root", rCert);

        return ks;
    }

    private KeyStore getEcKeyStore()
        throws Exception
    {
        KeyStore ks = KeyStore.getInstance("JKS");

        KeyPair rPair = TestUtils.generateECKeyPair();
        KeyPair iPair = TestUtils.generateECKeyPair();
        KeyPair ePair = TestUtils.generateECKeyPair();

        X509Certificate rCert = TestUtils.generateRootCert(rPair);
        X509Certificate iCert = TestUtils.generateIntermediateCert(iPair.getPublic(), new X500Name("CN=TLS Test CA"), rPair.getPrivate(), rCert);
        X509Certificate eCert = TestUtils.generateEndEntityCert(ePair.getPublic(), new X500Name("CN=TLS Test"), iPair.getPrivate(), iCert);

        ks.load(null, PASSWORD);

        ks.setKeyEntry("test", ePair.getPrivate(), PASSWORD, new Certificate[] { eCert, iCert });

        ks.setCertificateEntry("root", rCert);

        return ks;
    }

    public void testRSAServer()
        throws Exception
    {
        KeyStore ks = getRsaKeyStore();

        KeyStore trustStore = KeyStore.getInstance("JKS");

        trustStore.load(null, PASSWORD);

        trustStore.setCertificateEntry("server", ks.getCertificate("root"));

        SSLUtils.startServer(ks, PASSWORD, trustStore);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "BCTLS");

        trustManagerFactory.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS");

        context.init(null, trustManagerFactory.getTrustManagers(), null);

        SSLSocketFactory f = context.getSocketFactory();

        SSLSocket c = (SSLSocket)f.createSocket("localhost", 8888);

        c.getOutputStream().write('!');

        c.getInputStream().read();

    }

    public void testRSAServerWithClientAuth()
        throws Exception
    {
        KeyStore ks = getRsaKeyStore();

        KeyStore trustStore = KeyStore.getInstance("JKS");

        trustStore.load(null, PASSWORD);

        trustStore.setCertificateEntry("server", ks.getCertificate("root"));

        SSLUtils.startServer(ks, PASSWORD, trustStore, true);

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("PKIX", "BCTLS");

        keyManagerFactory.init(ks, PASSWORD);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "BCTLS");

        trustManagerFactory.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS");

        context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        SSLSocketFactory f = context.getSocketFactory();

        SSLSocket c = (SSLSocket)f.createSocket("localhost", 8888);

        c.getOutputStream().write('!');

        c.getInputStream().read();

    }
}
