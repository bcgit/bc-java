package org.bouncycastle.jcajce.provider.test;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.XECKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jcajce.interfaces.XDHPrivateKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;


/**
 * Exercise the Java 11 XEC keys and NamedParameterSpec
 */
public class XDHKeyTest
    extends TestCase
{

    public static final String BC = "BC";

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    public void testShouldRecogniseX448Key()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("X448", BC);

        KeyPair kp = kpGen.generateKeyPair();

        assertTrue(kp.getPrivate() instanceof XECPrivateKey);
        assertTrue(kp.getPublic() instanceof XECPublicKey);

        keyFactoryCheck(kp);
    }

    public void testShouldRecogniseX25519Key()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("X25519", BC);

        KeyPair kp = kpGen.generateKeyPair();

        assertTrue(kp.getPrivate() instanceof XECPrivateKey);
        assertTrue(kp.getPublic() instanceof XECPublicKey);

        keyFactoryCheck(kp);
    }

    public void testShouldRecogniseNamedParamSpec()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("XDH", BC);

        kpGen.initialize(new NamedParameterSpec("X448"));

        KeyPair kp = kpGen.generateKeyPair();

        assertTrue(kp.getPrivate() instanceof XECPrivateKey);
        assertTrue(kp.getPublic() instanceof XECPublicKey);
        assertTrue(kp.getPrivate() instanceof XDHPrivateKey);
        assertTrue(kp.getPublic() instanceof XDHPublicKey);

        kpGen.initialize(new NamedParameterSpec("X25519"));

        kp = kpGen.generateKeyPair();

        assertTrue(kp.getPrivate() instanceof XECPrivateKey);
        assertTrue(kp.getPublic() instanceof XECPublicKey);
        assertTrue(kp.getPrivate() instanceof XDHPrivateKey);
        assertTrue(kp.getPublic() instanceof XDHPublicKey);
    }

    public void testShouldReturnNamedParamSpec()
        throws Exception
    {
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("X25519", BC);
            KeyPair kp = kpGen.generateKeyPair();
            checkNamedParamSpecXECKey(kp.getPrivate(), "X25519");
            checkNamedParamSpecXECKey(kp.getPublic(), "X25519");
        }
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("X448", BC);
            KeyPair kp = kpGen.generateKeyPair();
            checkNamedParamSpecXECKey(kp.getPrivate(), "X448");
            checkNamedParamSpecXECKey(kp.getPublic(), "X448");
        }
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("XDH", BC);
            kpGen.initialize(255);
            KeyPair kp = kpGen.generateKeyPair();
            checkNamedParamSpecXECKey(kp.getPrivate(), "X25519");
            checkNamedParamSpecXECKey(kp.getPublic(), "X25519");
        }
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("XDH", BC);
            kpGen.initialize(448);
            KeyPair kp = kpGen.generateKeyPair();
            checkNamedParamSpecXECKey(kp.getPrivate(), "X448");
            checkNamedParamSpecXECKey(kp.getPublic(), "X448");
        }
    }

    public void testShouldEncodeJVMKey()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("XDH", "SunEC");

        kpGen.initialize(new NamedParameterSpec("X448"));

        KeyPair kp = kpGen.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("XDH", BC);

        PublicKey pubX448 = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(((XECPublicKey)kp.getPublic()).getU(), ((XECPublicKey)pubX448).getU());

        PrivateKey privX448 = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertTrue(Arrays.areEqual(
            ((XECPrivateKey)kp.getPrivate()).getScalar().get(), ((XECPrivateKey)privX448).getScalar().get()));

        kpGen.initialize(new NamedParameterSpec("X25519"));

        kp = kpGen.generateKeyPair();

        PublicKey pubX25519 = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(((XECPublicKey)kp.getPublic()).getU(), ((XECPublicKey)pubX25519).getU());

        PrivateKey privX25519 = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertTrue(Arrays.areEqual(
            ((XECPrivateKey)kp.getPrivate()).getScalar().get(), ((XECPrivateKey)privX25519).getScalar().get()));
    }

    private void keyFactoryCheck(KeyPair kp)
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("XDH", BC);

        PublicKey publicKey = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        PrivateKey privateKey = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertTrue(
            publicKey instanceof XDHPublicKey);
        assertTrue(
            privateKey instanceof XDHPrivateKey);
        assertTrue(
            publicKey instanceof XECPublicKey);
        assertTrue(
            privateKey instanceof XECPrivateKey);
    }

    public void testInteropX25519()
        throws Exception
    {
        implTestInterop("X25519");
    }

    public void testInteropX448()
        throws Exception
    {
        implTestInterop("X448");
    }

    private void implTestInterop(String algorithm)
        throws Exception
    {
        KeyPairGenerator kpgSunEC = KeyPairGenerator.getInstance(algorithm, "SunEC");
        KeyPairGenerator kpgBC = KeyPairGenerator.getInstance(algorithm, "BC");

        KeyAgreement keyAgreementSunEC = KeyAgreement.getInstance(algorithm, "SunEC");
        KeyAgreement keyAgreementBC = KeyAgreement.getInstance(algorithm, "BC");

        for (int i = 0; i < 10; ++i)
        {
            implTestInteropCase(kpgBC, kpgBC, keyAgreementBC);
            implTestInteropCase(kpgBC, kpgSunEC, keyAgreementBC);
            implTestInteropCase(kpgSunEC, kpgSunEC, keyAgreementBC);
            implTestInteropCase(kpgBC, kpgBC, keyAgreementSunEC);
            implTestInteropCase(kpgBC, kpgSunEC, keyAgreementSunEC);
//            implTestInteropCase(kpgSunEC, kpgSunEC, keyAgreementSunEC);
        }
    }

    private void implTestInteropCase(KeyPairGenerator kpg1, KeyPairGenerator kpg2, KeyAgreement keyAgreement)
        throws Exception
    {
        KeyPair kp1 = kpg1.generateKeyPair();
        KeyPair kp2 = kpg2.generateKeyPair();

        keyAgreement.init(kp1.getPrivate());
        keyAgreement.doPhase(kp2.getPublic(), true);
        byte[] sec1 = keyAgreement.generateSecret();

        keyAgreement.init(kp2.getPrivate());
        keyAgreement.doPhase(kp1.getPublic(), true);
        byte[] sec2 = keyAgreement.generateSecret();

        assertTrue(Arrays.areEqual(sec1, sec2));

        if (kp1.getPrivate() instanceof XDHPrivateKey)
        {
            keyAgreement.init(kp2.getPrivate());
            keyAgreement.doPhase(((XDHPrivateKey)kp1.getPrivate()).getPublicKey(), true);
            byte[] sec3 = keyAgreement.generateSecret();

            assertTrue(Arrays.areEqual(sec1, sec3));
        }
    }

    public void testRawEncodedKeySpec()
        throws Exception
    {
        KeyPair xd1 = generateKP("X448", new XDHParameterSpec(XDHParameterSpec.X448));

        checkRaw(xd1.getPublic(), "X448");

        KeyPair xd2 = generateKP("X25519", new XDHParameterSpec(XDHParameterSpec.X25519));

        checkRaw(xd2.getPublic(), "X25519");
    }

    private KeyPair generateKP(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");

        kpGen.initialize(spec);

        return kpGen.generateKeyPair();
    }

    private void checkRaw(PublicKey key, String algorithm)
        throws Exception
    {
        KeyFactory kf = KeyFactory.getInstance(algorithm, "BC");

        RawEncodedKeySpec rawSpec = (RawEncodedKeySpec)kf.getKeySpec(key, RawEncodedKeySpec.class);

        PublicKey pub = kf.generatePublic(rawSpec);

        assertEquals(key, pub);
    }

    private void checkNamedParamSpecXECKey(Key key, String name)
    {
        assertTrue(key instanceof XECKey);
        AlgorithmParameterSpec params = ((XECKey)key).getParams();
        assertTrue(params instanceof NamedParameterSpec);
        NamedParameterSpec spec = (NamedParameterSpec)params;
        assertEquals(name, spec.getName());
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(XDHKeyTest.class);
    }

    public static Test suite()
        throws Exception
    {
        return new TestSuite(XDHKeyTest.class);
    }
}
