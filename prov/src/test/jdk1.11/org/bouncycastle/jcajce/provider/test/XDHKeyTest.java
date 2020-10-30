package org.bouncycastle.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jcajce.interfaces.XDHPrivateKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;


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

    public void testBCAgreement()
        throws Exception
    {
        KeyPairGenerator kpGen1 = KeyPairGenerator.getInstance("X25519", "SunEC");
        KeyPairGenerator kpGen2 = KeyPairGenerator.getInstance("X25519", "BC");

        KeyAgreement keyAgreement = KeyAgreement.getInstance("XDH", "BC");

        KeyPair kp1 = kpGen1.generateKeyPair();
        KeyPair kp2 = kpGen2.generateKeyPair();

        keyAgreement.init(kp1.getPrivate());

        keyAgreement.doPhase(kp2.getPublic(), true);

        byte[] sec1 = keyAgreement.generateSecret();

        keyAgreement.init(kp2.getPrivate());

        keyAgreement.doPhase(kp1.getPublic(), true);

        byte[] sec2 = keyAgreement.generateSecret();

        assertTrue(Arrays.areEqual(sec1, sec2));
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
