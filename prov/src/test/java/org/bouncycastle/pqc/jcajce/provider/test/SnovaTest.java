package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.pqc.jcajce.interfaces.SnovaKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SnovaParameterSpec;
import org.bouncycastle.util.Strings;

public class SnovaTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        SnovaTest test = new SnovaTest();
        test.setUp();
        test.testPrivateKeyRecovery();
        test.testPublicKeyRecovery();
        test.testRestrictedKeyPairGen();
        test.testSnovaRandomSig();
        test.testSnovaSign();
    }

    byte[] msg = Strings.toByteArray("Hello World!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testPrivateKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Snova", "BCPQC");

        kpg.initialize(SnovaParameterSpec.SNOVA_24_5_4_ESK, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("Snova", "BCPQC");

        SnovaKey privKey = (SnovaKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);
        assertEquals(kp.getPrivate().getAlgorithm(), privKey.getAlgorithm());
        assertEquals(kp.getPrivate().hashCode(), privKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        SnovaKey privKey2 = (SnovaKey)oIn.readObject();

        assertEquals(privKey, privKey2);
        assertEquals(privKey.getAlgorithm(), privKey2.getAlgorithm());
        assertEquals(privKey.hashCode(), privKey2.hashCode());
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Snova", "BCPQC");

        kpg.initialize(SnovaParameterSpec.SNOVA_25_8_3_ESK, new SnovaTest.RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance(SnovaParameterSpec.SNOVA_25_8_3_ESK.getName(), "BCPQC");

        SnovaKey pubKey = (SnovaKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);
        assertEquals(kp.getPublic().getAlgorithm(), pubKey.getAlgorithm());
        assertEquals(kp.getPublic().hashCode(), pubKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        SnovaKey pubKey2 = (SnovaKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
        assertEquals(pubKey.getAlgorithm(), pubKey2.getAlgorithm());
        assertEquals(pubKey.hashCode(), pubKey2.hashCode());
    }

    public void testSnovaSign()
        throws Exception
    {
        testSnova(SnovaParameterSpec.SNOVA_24_5_4_ESK, SnovaParameterSpec.SNOVA_24_5_4_SSK);
        testSnova(SnovaParameterSpec.SNOVA_24_5_4_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_24_5_4_SHAKE_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_24_5_4_SHAKE_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_24_5_5_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_24_5_5_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_24_5_5_SHAKE_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_24_5_5_SHAKE_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_25_8_3_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_25_8_3_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_25_8_3_SHAKE_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_25_8_3_SHAKE_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_29_6_5_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_29_6_5_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_29_6_5_SHAKE_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_29_6_5_SHAKE_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_37_8_4_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_37_8_4_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_37_8_4_SHAKE_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_37_8_4_SHAKE_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_37_17_2_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_37_17_2_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_37_17_2_SHAKE_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_37_17_2_SHAKE_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_49_11_3_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_49_11_3_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_49_11_3_SHAKE_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_49_11_3_SHAKE_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_56_25_2_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_56_25_2_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_56_25_2_SHAKE_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_56_25_2_SHAKE_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_60_10_4_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_60_10_4_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_60_10_4_SHAKE_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_60_10_4_SHAKE_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_66_15_3_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_66_15_3_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_66_15_3_SHAKE_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_66_15_3_SHAKE_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_75_33_2_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_75_33_2_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_75_33_2_SHAKE_ESK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
        testSnova(SnovaParameterSpec.SNOVA_75_33_2_SHAKE_SSK, SnovaParameterSpec.SNOVA_24_5_4_ESK);
    }

    private void testSnova(SnovaParameterSpec spec, SnovaParameterSpec wrongSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Snova", "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance(spec.getName(), "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance(spec.getName(), "BCPQC");

        assertEquals(spec.getName(), Strings.toUpperCase(sig.getAlgorithm()));

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        kpg = KeyPairGenerator.getInstance("Snova", "BCPQC");

        kpg.initialize(wrongSpec, new SecureRandom());

        kp = kpg.generateKeyPair();

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("signature configured for " + spec.getName(), e.getMessage());
        }
    }

    public void testRestrictedKeyPairGen()
        throws Exception
    {
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_24_5_4_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_24_5_4_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_24_5_4_SHAKE_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_24_5_4_SHAKE_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_24_5_5_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_24_5_5_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_24_5_5_SHAKE_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_24_5_5_SHAKE_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_25_8_3_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_25_8_3_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_25_8_3_SHAKE_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_25_8_3_SHAKE_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_29_6_5_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_29_6_5_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_29_6_5_SHAKE_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_29_6_5_SHAKE_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_37_8_4_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_37_8_4_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_37_8_4_SHAKE_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_37_8_4_SHAKE_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_37_17_2_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_37_17_2_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_37_17_2_SHAKE_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_37_17_2_SHAKE_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_49_11_3_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_49_11_3_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_49_11_3_SHAKE_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_49_11_3_SHAKE_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_56_25_2_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_56_25_2_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_56_25_2_SHAKE_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_56_25_2_SHAKE_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_60_10_4_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_60_10_4_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_60_10_4_SHAKE_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_60_10_4_SHAKE_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_66_15_3_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_66_15_3_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_66_15_3_SHAKE_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_66_15_3_SHAKE_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_75_33_2_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_75_33_2_SSK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_75_33_2_SHAKE_ESK);
        doTestRestrictedKeyPairGen(SnovaParameterSpec.SNOVA_75_33_2_SHAKE_SSK);
    }

    private void doTestRestrictedKeyPairGen(SnovaParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        //kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

//        try
//        {
//            kpg.initialize(altSpec, new SecureRandom());
//            fail("no exception");
//        }
//        catch (InvalidAlgorithmParameterException e)
//        {
//            assertEquals("key pair generator locked to " + spec.getName(), e.getMessage());
//        }
    }

    public void testSnovaRandomSig()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Snova", "BCPQC");

        kpg.initialize(SnovaParameterSpec.SNOVA_24_5_5_SHAKE_SSK, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Snova", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("Snova", "BCPQC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
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
