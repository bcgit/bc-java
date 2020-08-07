package org.bouncycastle.jsse.provider.test;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jsse.BCX509ExtendedKeyManager;
import org.bouncycastle.jsse.BCX509Key;

import junit.framework.TestCase;

public class KeyManagerFactoryTest
    extends TestCase
{
    private static final char[] PASSWORD = "fred".toCharArray();

    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    public void testBasicEC()
        throws Exception
    {
        KeyStore keyStore = getEcKeyStore(false);

        // NOTE: This depends on the value of JsseUtils.getKeyTypeLegacyServer(KeyExchangeAlgorithm.ECDHE_ECDSA)
        String keyType = "ECDHE_ECDSA";

        implTestKeyManagerFactory(keyStore, keyType);
    }

    public void testBasicRSA()
        throws Exception
    {
        KeyStore keyStore = getRsaKeyStore(true);

        // NOTE: This depends on the value of JsseUtils.getKeyTypeLegacyServer(KeyExchangeAlgorithm.RSA)
//        String keyType = "RSA";
        String keyType = "KE:RSA";

        implTestKeyManagerFactory(keyStore, keyType);
    }

    public void testRSAServer()
        throws Exception
    {
        KeyStore ks = getRsaKeyStore(true);

        KeyStore trustStore = KeyStore.getInstance("JKS");

        trustStore.load(null, PASSWORD);

        trustStore.setCertificateEntry("server", ks.getCertificate("root"));

        SSLUtils.startServer(ks, PASSWORD, trustStore, false, 8886);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX",
            ProviderUtils.PROVIDER_NAME_BCJSSE);

        trustManagerFactory.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);

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
         * For this variation we add the server's certificate to the client's trust store directly,
         * instead of the root (TA).
         * 
         * NOTE: For TLS 1.3 with certificate_authorities in ClientHello, or earlier versions with
         * trusted_ca_keys in ClientHello, this test only works when a) there are no actual CA
         * certificates in the client trust store, AND/OR b) the server is willing to (eventually)
         * select a certificate whose issuer is not mentioned in those extensions (or e.g.
         * trusted_ca_keys not enabled/supported).
         */
        trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, PASSWORD);
        trustStore.setCertificateEntry("server", ks.getCertificate("test"));

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX",
            ProviderUtils.PROVIDER_NAME_BCJSSE);
        trustManagerFactory.init(trustStore);

        SSLContext context = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);

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

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);
        keyManagerFactory.init(clientKS, PASSWORD);

        KeyStore clientTS = KeyStore.getInstance("JKS");
        clientTS.load(null, PASSWORD);
        clientTS.setCertificateEntry("serverRoot", serverKS.getCertificate("root"));

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX",
            ProviderUtils.PROVIDER_NAME_BCJSSE);
        trustManagerFactory.init(clientTS);

        SSLContext context = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);

        context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        SSLSocketFactory f = context.getSocketFactory();

        SSLSocket c = (SSLSocket)f.createSocket("localhost", 8887);
        c.setUseClientMode(true);

        SSLUtils.restrictKeyExchange(c, "RSA");

        c.getOutputStream().write('!');

        c.getInputStream().read();

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

    private void implTestKeyManager(BCX509ExtendedKeyManager manager, String keyType)
        throws Exception
    {
        String alias = manager.chooseServerAlias(keyType, null, null);
        assertNotNull(alias);
        assertNotNull(manager.getCertificateChain(alias));
        assertNotNull(manager.getPrivateKey(alias));
        assertNotNull(manager.getKeyBC(alias));

        BCX509Key key = manager.chooseServerKeyBC(keyType, null, null);
        assertNotNull(key);

        alias = manager.chooseServerAlias(keyType, new Principal[] { new X500Principal("CN=TLS Test") }, null);
        assertNull(alias);

        key = manager.chooseServerKeyBC(keyType, new Principal[] { new X500Principal("CN=TLS Test") }, null);
        assertNull(key);

        alias = manager.chooseServerAlias(keyType, new Principal[] { new X500Principal("CN=TLS Test CA") }, null);
        assertNotNull(alias);
        assertNotNull(manager.getCertificateChain(alias));
        assertNotNull(manager.getPrivateKey(alias));
        assertNotNull(manager.getKeyBC(alias));

        key = manager.chooseServerKeyBC(keyType, new Principal[] { new X500Principal("CN=TLS Test CA") }, null);
        assertNotNull(key);
    }

    private void implTestKeyManagerFactory(KeyManagerFactory kmf, String keyType)
        throws Exception
    {
        KeyManager[] keyManagers = kmf.getKeyManagers();
        BCX509ExtendedKeyManager keyManager = (BCX509ExtendedKeyManager)keyManagers[0];
        implTestKeyManager(keyManager, keyType);
    }

    private void implTestKeyManagerFactory(KeyStore ks, String keyType)
        throws Exception
    {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", ProviderUtils.PROVIDER_NAME_BCJSSE);

        kmf.init(ks, PASSWORD);
        implTestKeyManagerFactory(kmf, keyType);

        Builder builder = KeyStore.Builder.newInstance(ks, new KeyStore.PasswordProtection(PASSWORD));
        kmf.init(new KeyStoreBuilderParameters(builder));
        implTestKeyManagerFactory(kmf, keyType);
    }
}
