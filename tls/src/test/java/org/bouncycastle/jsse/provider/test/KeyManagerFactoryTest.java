package org.bouncycastle.jsse.provider.test;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import junit.framework.Test;
import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

public class KeyManagerFactoryTest
    extends TestCase
{
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

        KeyStore ks = KeyStore.getInstance("JKS");

        KeyPair rPair = TestUtils.generateRSAKeyPair();
        KeyPair iPair = TestUtils.generateRSAKeyPair();
        KeyPair ePair = TestUtils.generateRSAKeyPair();

        X509Certificate rCert = TestUtils.generateRootCert(rPair);
        X509Certificate iCert = TestUtils.generateIntermediateCert(iPair.getPublic(), rPair.getPrivate(), rCert);
        X509Certificate eCert = TestUtils.generateEndEntityCert(ePair.getPublic(), iPair.getPrivate(), iCert);

        ks.load(null, "fred".toCharArray());

        ks.setKeyEntry("test", ePair.getPrivate(), "fred".toCharArray(), new Certificate[] { eCert, iCert, rCert });

        fact.init(ks, "fred".toCharArray());

        KeyManager[] managers = fact.getKeyManagers();

        X509ExtendedKeyManager manager = (X509ExtendedKeyManager)managers[0];

        String alias = manager.chooseServerAlias("RSA", null, null);

        assertNotNull(alias);

        assertNotNull(manager.getCertificateChain(alias));

        assertNotNull(manager.getPrivateKey(alias));
    }
}
