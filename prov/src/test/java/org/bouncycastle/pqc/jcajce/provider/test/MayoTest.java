package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.MayoKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.MayoParameterSpec;
import org.bouncycastle.util.Strings;

public class MayoTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        MayoTest test = new MayoTest();
        test.setUp();
        test.testMayo3();
        test.testMayo5();
        test.testMayoRandomSig();
        test.testReinitDiscardsBufferedMessage();
        test.testForeignPublicKeyKeepsCause();
        test.testPrivateKeyRecovery();
        test.testPublicKeyRecovery();
        test.testRestrictedKeyPairGen();
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Mayo", "BCPQC");

        kpg.initialize(MayoParameterSpec.mayo1, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("Mayo", "BCPQC");

        MayoKey privKey = (MayoKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);
        assertEquals(kp.getPrivate().getAlgorithm(), privKey.getAlgorithm());
        assertEquals(kp.getPrivate().hashCode(), privKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        MayoKey privKey2 = (MayoKey)oIn.readObject();

        assertEquals(privKey, privKey2);
        assertEquals(privKey.getAlgorithm(), privKey2.getAlgorithm());
        assertEquals(privKey.hashCode(), privKey2.hashCode());
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Mayo", "BCPQC");

        kpg.initialize(MayoParameterSpec.mayo2, new MayoTest.RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("MAYO-2", "BCPQC");

        MayoKey pubKey = (MayoKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);
        assertEquals(kp.getPublic().getAlgorithm(), pubKey.getAlgorithm());
        assertEquals(kp.getPublic().hashCode(), pubKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        MayoKey pubKey2 = (MayoKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
        assertEquals(pubKey.getAlgorithm(), pubKey2.getAlgorithm());
        assertEquals(pubKey.hashCode(), pubKey2.hashCode());
    }

    public void testMayo5()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Mayo", "BCPQC");

        kpg.initialize(MayoParameterSpec.mayo5, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("MAYO-5", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("MAYO-5", "BCPQC");

        assertEquals("MAYO-5", Strings.toUpperCase(sig.getAlgorithm()));

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        kpg = KeyPairGenerator.getInstance("Mayo", "BCPQC");

        kpg.initialize(MayoParameterSpec.mayo1, new SecureRandom());

        kp = kpg.generateKeyPair();

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("signature configured for MAYO-5", e.getMessage());
        }
    }

    public void testMayo3()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Mayo", "BCPQC");

        kpg.initialize(MayoParameterSpec.mayo3, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("MAYO-3", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("MAYO-3", "BCPQC");

        assertEquals("MAYO-3", Strings.toUpperCase(sig.getAlgorithm()));

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        kpg = KeyPairGenerator.getInstance("Mayo", "BCPQC");

        kpg.initialize(MayoParameterSpec.mayo5, new SecureRandom());

        kp = kpg.generateKeyPair();

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("signature configured for MAYO-3", e.getMessage());
        }
    }

    public void testRestrictedKeyPairGen()
        throws Exception
    {
        doTestRestrictedKeyPairGen(MayoParameterSpec.mayo1);
        doTestRestrictedKeyPairGen(MayoParameterSpec.mayo2);
        doTestRestrictedKeyPairGen(MayoParameterSpec.mayo3);
        doTestRestrictedKeyPairGen(MayoParameterSpec.mayo5);
    }

    private void doTestRestrictedKeyPairGen(MayoParameterSpec spec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        MayoParameterSpec altSpec = (spec == MayoParameterSpec.mayo1)
            ? MayoParameterSpec.mayo2
            : MayoParameterSpec.mayo1;

        kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

        try
        {
            kpg.initialize(altSpec, new SecureRandom());
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key pair generator locked to " + spec.getName(), e.getMessage());
        }
    }

    public void testMayoRandomSig()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Mayo", "BCPQC");

        kpg.initialize(MayoParameterSpec.mayo2, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Mayo", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("Mayo", "BCPQC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    /**
     * initSign / initVerify start a new message: bytes passed to update() before a re-initialisation,
     * or before switching between signing and verifying, must not reach the next signature.
     */
    public void testReinitDiscardsBufferedMessage()
        throws Exception
    {
        byte[] stale = Strings.toByteArray("stale");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Mayo", "BCPQC");

        kpg.initialize(MayoParameterSpec.mayo1, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("Mayo", "BCPQC");

        signer.initSign(kp.getPrivate(), new SecureRandom());

        signer.update(msg, 0, msg.length);

        byte[] s = signer.sign();

        // an abandoned sign, then a sign of msg: the result is a signature on msg alone
        Signature sig = Signature.getInstance("Mayo", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(stale, 0, stale.length);
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(msg, 0, msg.length);

        byte[] s2 = sig.sign();

        Signature verifier = Signature.getInstance("Mayo", "BCPQC");

        verifier.initVerify(kp.getPublic());
        verifier.update(msg, 0, msg.length);

        assertTrue("re-initSign kept the earlier update", verifier.verify(s2));

        // an abandoned verify, then a verify of msg
        sig.initVerify(kp.getPublic());
        sig.update(stale, 0, stale.length);
        sig.initVerify(kp.getPublic());
        sig.update(msg, 0, msg.length);

        assertTrue("re-initVerify kept the earlier update", sig.verify(s));

        // an abandoned sign, then a verify of msg on the same object
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(stale, 0, stale.length);
        sig.initVerify(kp.getPublic());
        sig.update(msg, 0, msg.length);

        assertTrue("initVerify after initSign kept the earlier update", sig.verify(s));
    }

    /**
     * A public key that is not a MAYO key is refused with an InvalidKeyException that keeps the
     * decoding failure as its cause.
     */
    public void testForeignPublicKeyKeepsCause()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");

        kpg.initialize(256, new SecureRandom());

        PublicKey ecKey = kpg.generateKeyPair().getPublic();

        Signature sig = Signature.getInstance("Mayo", "BCPQC");

        try
        {
            sig.initVerify(ecKey);
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertTrue(e.getMessage(), e.getMessage().startsWith("unknown public key passed to Mayo: "));
            assertNotNull("cause dropped", e.getCause());
        }
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

