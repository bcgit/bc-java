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
import org.bouncycastle.pqc.jcajce.interfaces.FaestKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FaestParameterSpec;
import org.bouncycastle.util.Strings;

public class FaestTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        FaestTest test = new FaestTest();
        test.setUp();
        test.testPrivateKeyRecovery();
        test.testPublicKeyRecovery();
        test.testRestrictedKeyPairGen();
        test.testFaestRandomSig();
        test.testFaestSign();
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Faest", "BCPQC");

        kpg.initialize(FaestParameterSpec.faest_128s, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("Faest", "BCPQC");

        FaestKey privKey = (FaestKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);
        assertEquals(kp.getPrivate().getAlgorithm(), privKey.getAlgorithm());
        assertEquals(kp.getPrivate().hashCode(), privKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        FaestKey privKey2 = (FaestKey)oIn.readObject();

        assertEquals(privKey, privKey2);
        assertEquals(privKey.getAlgorithm(), privKey2.getAlgorithm());
        assertEquals(privKey.hashCode(), privKey2.hashCode());
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Faest", "BCPQC");

        kpg.initialize(FaestParameterSpec.faest_em_128s, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance(FaestParameterSpec.faest_em_128s.getName(), "BCPQC");

        FaestKey pubKey = (FaestKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);
        assertEquals(kp.getPublic().getAlgorithm(), pubKey.getAlgorithm());
        assertEquals(kp.getPublic().hashCode(), pubKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        FaestKey pubKey2 = (FaestKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
        assertEquals(pubKey.getAlgorithm(), pubKey2.getAlgorithm());
        assertEquals(pubKey.hashCode(), pubKey2.hashCode());
    }

    public void testFaestSign()
        throws Exception
    {
        testFaest(FaestParameterSpec.faest_128s, FaestParameterSpec.faest_128f);
        testFaest(FaestParameterSpec.faest_128f, FaestParameterSpec.faest_128s);
        testFaest(FaestParameterSpec.faest_192s, FaestParameterSpec.faest_128s);
        testFaest(FaestParameterSpec.faest_192f, FaestParameterSpec.faest_128s);
        testFaest(FaestParameterSpec.faest_256s, FaestParameterSpec.faest_128s);
        testFaest(FaestParameterSpec.faest_256f, FaestParameterSpec.faest_128s);
        testFaest(FaestParameterSpec.faest_em_128s, FaestParameterSpec.faest_128s);
        testFaest(FaestParameterSpec.faest_em_128f, FaestParameterSpec.faest_128s);
        testFaest(FaestParameterSpec.faest_em_192s, FaestParameterSpec.faest_128s);
        testFaest(FaestParameterSpec.faest_em_192f, FaestParameterSpec.faest_128s);
        testFaest(FaestParameterSpec.faest_em_256s, FaestParameterSpec.faest_128s);
        testFaest(FaestParameterSpec.faest_em_256f, FaestParameterSpec.faest_128s);
    }

    private void testFaest(FaestParameterSpec spec, FaestParameterSpec wrongSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Faest", "BCPQC");

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

        kpg = KeyPairGenerator.getInstance("Faest", "BCPQC");

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
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_128s);
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_128f);
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_192s);
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_192f);
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_256s);
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_256f);
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_em_128s);
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_em_128f);
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_em_192s);
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_em_192f);
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_em_256s);
        doTestRestrictedKeyPairGen(FaestParameterSpec.faest_em_256f);
    }

    private void doTestRestrictedKeyPairGen(FaestParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(Strings.toUpperCase(spec.getName()), kp.getPublic().getAlgorithm());
        assertEquals(Strings.toUpperCase(spec.getName()), kp.getPrivate().getAlgorithm());
    }

    public void testFaestRandomSig()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Faest", "BCPQC");

        kpg.initialize(FaestParameterSpec.faest_128s, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Faest", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("Faest", "BCPQC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    /**
     * Verify that the BC provider's key-info-converter mechanism (populated by
     * {@code BouncyCastleProvider.loadPQCKeys()}) recognises every FAEST OID
     * and decodes encoded key infos to FAEST keys equal to the originals.
     */
    public void testBcProviderKeyInfoConverter()
        throws Exception
    {
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_128s);
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_128f);
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_192s);
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_192f);
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_256s);
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_256f);
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_em_128s);
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_em_128f);
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_em_192s);
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_em_192f);
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_em_256s);
        doBcKeyInfoRoundTrip(FaestParameterSpec.faest_em_256f);
    }

    private void doBcKeyInfoRoundTrip(FaestParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Faest", "BCPQC");
        kpg.initialize(spec, new RiggedRandom());
        KeyPair kp = kpg.generateKeyPair();

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        PublicKey decPub = BouncyCastleProvider.getPublicKey(pubInfo);
        PrivateKey decPriv = BouncyCastleProvider.getPrivateKey(privInfo);

        assertNotNull(spec.getName() + ": BC provider returned null for SubjectPublicKeyInfo", decPub);
        assertNotNull(spec.getName() + ": BC provider returned null for PrivateKeyInfo", decPriv);

        assertTrue(spec.getName() + ": decoded public key is not a FaestKey", decPub instanceof FaestKey);
        assertTrue(spec.getName() + ": decoded private key is not a FaestKey", decPriv instanceof FaestKey);

        assertEquals(spec.getName() + ": public key parameter spec mismatch",
            spec.getName(), ((FaestKey)decPub).getParameterSpec().getName());
        assertEquals(spec.getName() + ": private key parameter spec mismatch",
            spec.getName(), ((FaestKey)decPriv).getParameterSpec().getName());

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
