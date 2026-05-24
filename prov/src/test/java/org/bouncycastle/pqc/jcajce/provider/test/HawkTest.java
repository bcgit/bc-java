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
import org.bouncycastle.pqc.jcajce.interfaces.HawkKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.HawkParameterSpec;
import org.bouncycastle.util.Strings;

public class HawkTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        HawkTest test = new HawkTest();
        test.setUp();
        test.testPrivateKeyRecovery();
        test.testPublicKeyRecovery();
        test.testRestrictedKeyPairGen();
        test.testHawkRandomSig();
        test.testHawkSign();
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Hawk", "BCPQC");

        kpg.initialize(HawkParameterSpec.hawk_256, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("Hawk", "BCPQC");

        HawkKey privKey = (HawkKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);
        assertEquals(kp.getPrivate().getAlgorithm(), privKey.getAlgorithm());
        assertEquals(kp.getPrivate().hashCode(), privKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        HawkKey privKey2 = (HawkKey)oIn.readObject();

        assertEquals(privKey, privKey2);
        assertEquals(privKey.getAlgorithm(), privKey2.getAlgorithm());
        assertEquals(privKey.hashCode(), privKey2.hashCode());
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Hawk", "BCPQC");

        kpg.initialize(HawkParameterSpec.hawk_512, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance(HawkParameterSpec.hawk_512.getName(), "BCPQC");

        HawkKey pubKey = (HawkKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);
        assertEquals(kp.getPublic().getAlgorithm(), pubKey.getAlgorithm());
        assertEquals(kp.getPublic().hashCode(), pubKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        HawkKey pubKey2 = (HawkKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
        assertEquals(pubKey.getAlgorithm(), pubKey2.getAlgorithm());
        assertEquals(pubKey.hashCode(), pubKey2.hashCode());
    }

    public void testHawkSign()
        throws Exception
    {
        testHawk(HawkParameterSpec.hawk_256, HawkParameterSpec.hawk_512);
        testHawk(HawkParameterSpec.hawk_512, HawkParameterSpec.hawk_256);
        testHawk(HawkParameterSpec.hawk_1024, HawkParameterSpec.hawk_256);
    }

    private void testHawk(HawkParameterSpec spec, HawkParameterSpec wrongSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Hawk", "BCPQC");

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

        kpg = KeyPairGenerator.getInstance("Hawk", "BCPQC");

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
        doTestRestrictedKeyPairGen(HawkParameterSpec.hawk_256);
        doTestRestrictedKeyPairGen(HawkParameterSpec.hawk_512);
        doTestRestrictedKeyPairGen(HawkParameterSpec.hawk_1024);
    }

    private void doTestRestrictedKeyPairGen(HawkParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(Strings.toUpperCase(spec.getName()), kp.getPublic().getAlgorithm());
        assertEquals(Strings.toUpperCase(spec.getName()), kp.getPrivate().getAlgorithm());
    }

    public void testHawkRandomSig()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Hawk", "BCPQC");

        kpg.initialize(HawkParameterSpec.hawk_256, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Hawk", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("Hawk", "BCPQC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    /**
     * Verify that the BC provider's key-info-converter mechanism (populated by
     * {@code BouncyCastleProvider.loadPQCKeys()}) recognises every Hawk OID
     * and decodes encoded key infos to Hawk keys equal to the originals.
     */
    public void testBcProviderKeyInfoConverter()
        throws Exception
    {
        doBcKeyInfoRoundTrip(HawkParameterSpec.hawk_256);
        doBcKeyInfoRoundTrip(HawkParameterSpec.hawk_512);
        doBcKeyInfoRoundTrip(HawkParameterSpec.hawk_1024);
    }

    private void doBcKeyInfoRoundTrip(HawkParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Hawk", "BCPQC");
        kpg.initialize(spec, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        PublicKey decPub = BouncyCastleProvider.getPublicKey(pubInfo);
        PrivateKey decPriv = BouncyCastleProvider.getPrivateKey(privInfo);

        assertNotNull(spec.getName() + ": BC provider returned null for SubjectPublicKeyInfo", decPub);
        assertNotNull(spec.getName() + ": BC provider returned null for PrivateKeyInfo", decPriv);

        assertTrue(spec.getName() + ": decoded public key is not a HawkKey", decPub instanceof HawkKey);
        assertTrue(spec.getName() + ": decoded private key is not a HawkKey", decPriv instanceof HawkKey);

        assertEquals(spec.getName() + ": public key parameter spec mismatch",
            spec.getName(), ((HawkKey)decPub).getParameterSpec().getName());
        assertEquals(spec.getName() + ": private key parameter spec mismatch",
            spec.getName(), ((HawkKey)decPriv).getParameterSpec().getName());

        assertEquals(spec.getName() + ": public key equality", kp.getPublic(), decPub);
        assertEquals(spec.getName() + ": private key equality", kp.getPrivate(), decPriv);
    }

    /**
     * Deterministic high-entropy PRNG, backed by {@link java.util.Random} so the
     * stream advances and is uniformly distributed. A constant-output rig
     * (the pattern used in other PQC provider tests) and a counter-modulo-256
     * rig both deadlock Hawk's keygen rejection-sample loop — the former
     * because every retry sees the same seed, the latter because the linear
     * byte pattern has a pathologically low keygen acceptance rate.
     */
    private static class RiggedRandom
        extends SecureRandom
    {
        private final java.util.Random delegate = new java.util.Random(0xCAFEBABEL);

        public void nextBytes(byte[] bytes)
        {
            delegate.nextBytes(bytes);
        }
    }
}
