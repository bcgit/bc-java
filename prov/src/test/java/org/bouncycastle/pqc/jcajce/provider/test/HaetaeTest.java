package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.HaetaeKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.HaetaeParameterSpec;
import org.bouncycastle.util.Strings;

public class HaetaeTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        HaetaeTest test = new HaetaeTest();
        test.setUp();
        test.testPrivateKeyRecovery();
        test.testPublicKeyRecovery();
        test.testRestrictedKeyPairGen();
        test.testHaetaeRandomSig();
        test.testHaetaeSign();
        test.testBcProviderKeyInfoConverter();
    }

    byte[] msg = Strings.toByteArray("Hello World!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testPrivateKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Haetae", "BCPQC");

        kpg.initialize(HaetaeParameterSpec.haetae2, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("Haetae", "BCPQC");

        HaetaeKey privKey = (HaetaeKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);
        assertEquals(kp.getPrivate().getAlgorithm(), privKey.getAlgorithm());
        assertEquals(kp.getPrivate().hashCode(), privKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        HaetaeKey privKey2 = (HaetaeKey)oIn.readObject();

        assertEquals(privKey, privKey2);
        assertEquals(privKey.getAlgorithm(), privKey2.getAlgorithm());
        assertEquals(privKey.hashCode(), privKey2.hashCode());
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Haetae", "BCPQC");

        kpg.initialize(HaetaeParameterSpec.haetae3, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance(HaetaeParameterSpec.haetae3.getName(), "BCPQC");

        HaetaeKey pubKey = (HaetaeKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);
        assertEquals(kp.getPublic().getAlgorithm(), pubKey.getAlgorithm());
        assertEquals(kp.getPublic().hashCode(), pubKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        HaetaeKey pubKey2 = (HaetaeKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
        assertEquals(pubKey.getAlgorithm(), pubKey2.getAlgorithm());
        assertEquals(pubKey.hashCode(), pubKey2.hashCode());
    }

    public void testHaetaeSign()
        throws Exception
    {
        testHaetae(HaetaeParameterSpec.haetae2, HaetaeParameterSpec.haetae3);
        testHaetae(HaetaeParameterSpec.haetae3, HaetaeParameterSpec.haetae5);
        testHaetae(HaetaeParameterSpec.haetae5, HaetaeParameterSpec.haetae2);
    }

    private void testHaetae(HaetaeParameterSpec spec, HaetaeParameterSpec wrongSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Haetae", "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance(spec.getName(), "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance(spec.getName(), "BCPQC");

        assertEquals(Strings.toUpperCase(spec.getName()), Strings.toUpperCase(sig.getAlgorithm()));

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        kpg = KeyPairGenerator.getInstance("Haetae", "BCPQC");

        kpg.initialize(wrongSpec, new SecureRandom());

        kp = kpg.generateKeyPair();

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("signature configured for " + Strings.toUpperCase(spec.getName()), e.getMessage());
        }
    }

    public void testRestrictedKeyPairGen()
        throws Exception
    {
        doTestRestrictedKeyPairGen(HaetaeParameterSpec.haetae2);
        doTestRestrictedKeyPairGen(HaetaeParameterSpec.haetae3);
        doTestRestrictedKeyPairGen(HaetaeParameterSpec.haetae5);
    }

    private void doTestRestrictedKeyPairGen(HaetaeParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(Strings.toUpperCase(spec.getName()), kp.getPublic().getAlgorithm());
        assertEquals(Strings.toUpperCase(spec.getName()), kp.getPrivate().getAlgorithm());
    }

    public void testHaetaeRandomSig()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Haetae", "BCPQC");

        kpg.initialize(HaetaeParameterSpec.haetae2, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Haetae", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("Haetae", "BCPQC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    /**
     * Verify that the BC provider's key-info-converter mechanism (populated by
     * {@code BouncyCastleProvider.loadPQCKeys()}) recognises every HAETAE OID
     * and decodes encoded key infos to HAETAE keys equal to the originals.
     */
    public void testBcProviderKeyInfoConverter()
        throws Exception
    {
        doBcKeyInfoRoundTrip(HaetaeParameterSpec.haetae2);
        doBcKeyInfoRoundTrip(HaetaeParameterSpec.haetae3);
        doBcKeyInfoRoundTrip(HaetaeParameterSpec.haetae5);
    }

    private void doBcKeyInfoRoundTrip(HaetaeParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Haetae", "BCPQC");
        kpg.initialize(spec, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        PublicKey decPub = BouncyCastleProvider.getPublicKey(pubInfo);
        PrivateKey decPriv = BouncyCastleProvider.getPrivateKey(privInfo);

        assertNotNull(spec.getName() + ": BC provider returned null for SubjectPublicKeyInfo", decPub);
        assertNotNull(spec.getName() + ": BC provider returned null for PrivateKeyInfo", decPriv);

        assertTrue(spec.getName() + ": decoded public key is not a HaetaeKey", decPub instanceof HaetaeKey);
        assertTrue(spec.getName() + ": decoded private key is not a HaetaeKey", decPriv instanceof HaetaeKey);

        assertEquals(spec.getName() + ": public key parameter spec mismatch",
            spec.getName(), ((HaetaeKey)decPub).getParameterSpec().getName());
        assertEquals(spec.getName() + ": private key parameter spec mismatch",
            spec.getName(), ((HaetaeKey)decPriv).getParameterSpec().getName());

        assertEquals(spec.getName() + ": public key equality", kp.getPublic(), decPub);
        assertEquals(spec.getName() + ": private key equality", kp.getPrivate(), decPriv);
    }

    private static class RiggedRandom
        extends SecureRandom
    {
        public void nextBytes(byte[] bytes)
        {
            for (int i = 0; i != bytes.length; i++)
            {
                bytes[i] = (byte)(i & 0xff);
            }
        }
    }
}
