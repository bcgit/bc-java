package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.pqc.jcajce.interfaces.SPHINCSPlusKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.bouncycastle.util.Strings;

/**
 * Test cases for the use of SPHINCS-256 with the BCPQC provider.
 */
public class SphincsPlusTest
    extends TestCase
{
    // test vector courtesy the "Yawning Angel" GO implementation and the SUPERCOP reference implementation.
    byte[] msg = Strings.toByteArray("Cthulhu Fthagn --What a wonderful phrase!Cthulhu Fthagn --Say it and you're crazed!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

//    public void testSphincsDefaultKeyGen()
//        throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
//
//        kpg.initialize(new SPHINCSPlusKeyGenParameterSpec(), new RiggedRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        SPHINCSPlusKey pub = (SPHINCSPlusKey)kp.getPublic();
//
//        assertTrue(Arrays.areEqual(expSha2Pub, pub.getKeyData()));
//
//        SPHINCSPlusKey priv = (SPHINCSPlusKey)kp.getPrivate();
//
//        assertTrue(Arrays.areEqual(expSha2Priv, priv.getKeyData()));
//
//        KeyFactory keyFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
//
//        SPHINCSPlusKey pub2 = (SPHINCSPlusKey)keyFact.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha2Pub, pub2.getKeyData()));
//
//        SPHINCSPlusKey priv2 = (SPHINCSPlusKey)keyFact.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha2Priv, priv2.getKeyData()));
//    }

    public void testPrivateKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");

        kpg.initialize(SPHINCSPlusParameterSpec.sha256_128f_simple, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");

        SPHINCSPlusKey privKey = (SPHINCSPlusKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        SPHINCSPlusKey privKey2 = (SPHINCSPlusKey)oIn.readObject();

        assertEquals(privKey, privKey2);
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");

        kpg.initialize(SPHINCSPlusParameterSpec.sha256_128f, new RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");

        SPHINCSPlusKey pubKey = (SPHINCSPlusKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        SPHINCSPlusKey pubKey2 = (SPHINCSPlusKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
    }

//    public void testSphincsDefaultSha2KeyGen()
//        throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
//
//        kpg.initialize(new SPHINCSPlusKeyGenParameterSpec(SPHINCSPlusKeyGenParameterSpec.SHA512_256), new RiggedRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        SPHINCSPlusKey pub = (SPHINCSPlusKey)kp.getPublic();
//
//        assertTrue(Arrays.areEqual(expSha2Pub, pub.getKeyData()));
//
//        SPHINCSPlusKey priv = (SPHINCSPlusKey)kp.getPrivate();
//
//        assertTrue(Arrays.areEqual(expSha2Priv, priv.getKeyData()));
//
//        KeyFactory keyFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
//
//        SPHINCSPlusKey pub2 = (SPHINCSPlusKey)keyFact.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha2Pub, pub2.getKeyData()));
//
//        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pub2.getEncoded());
//
//        assertEquals(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256), SPHINCSPlusKeyParams.getInstance(pkInfo.getAlgorithm().getParameters()).getTreeDigest());
//
//        SPHINCSPlusKey priv2 = (SPHINCSPlusKey)keyFact.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha2Priv, priv2.getKeyData()));
//    }
//
//    public void testSphincsDefaultSha3KeyGen()
//        throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
//
//        kpg.initialize(new SPHINCSPlusKeyGenParameterSpec(SPHINCSPlusKeyGenParameterSpec.SHA3_256), new RiggedRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        SPHINCSPlusKey pub = (SPHINCSPlusKey)kp.getPublic();
//
//        assertTrue(Arrays.areEqual(expSha3Pub, pub.getKeyData()));
//
//        SPHINCSPlusKey priv = (SPHINCSPlusKey)kp.getPrivate();
//
//        assertTrue(Arrays.areEqual(expSha3Priv, priv.getKeyData()));
//
//        KeyFactory keyFact = KeyFactory.getInstance("SPHINCSPlus", "BCPQC");
//
//        SPHINCSPlusKey pub2 = (SPHINCSPlusKey)keyFact.generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha3Pub, pub2.getKeyData()));
//
//        SubjectPublicKeyInfo pkInfo = SubjectPublicKeyInfo.getInstance(pub2.getEncoded());
//
//        assertEquals(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_256), SPHINCSPlusKeyParams.getInstance(pkInfo.getAlgorithm().getParameters()).getTreeDigest());
//
//        SPHINCSPlusKey priv2 = (SPHINCSPlusKey)keyFact.generatePrivate(new PKCS8EncodedKeySpec(priv.getEncoded()));
//
//        assertTrue(Arrays.areEqual(expSha3Priv, priv2.getKeyData()));
//    }
//
//    public void testSphincsSha2Signature()
//        throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
//
//        kpg.initialize(new SPHINCSPlusKeyGenParameterSpec(SPHINCSPlusKeyGenParameterSpec.SHA512_256), new RiggedRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        Signature sig = Signature.getInstance("SHA512withSPHINCSPlus", "BCPQC");
//
//        sig.initSign(kp.getPrivate());
//
//        sig.update(msg, 0, msg.length);
//
//        byte[] s = sig.sign();
//
//        assertTrue(Arrays.areEqual(expSha2Sig, s));
//    }
//
//    public void testSphincsSha3Signature()
//        throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
//
//        kpg.initialize(new SPHINCSPlusKeyGenParameterSpec(SPHINCSPlusKeyGenParameterSpec.SHA3_256), new RiggedRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        Signature sig = Signature.getInstance("SHA3-512withSPHINCSPlus", "BCPQC");
//
//        sig.initSign(kp.getPrivate());
//
//        sig.update(msg, 0, msg.length);
//
//        byte[] s = sig.sign();
//
//        assertTrue(Arrays.areEqual(expSha3Sig, s));
//    }
//
//    public void testSphincsRandomSigSHA3()
//        throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");
//
//        kpg.initialize(new SPHINCSPlusKeyGenParameterSpec(SPHINCSPlusKeyGenParameterSpec.SHA3_256), new SecureRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        Signature sig = Signature.getInstance("SHA3-512withSPHINCSPlus", "BCPQC");
//
//        // random should be ignored...
//        sig.initSign(kp.getPrivate(), new SecureRandom());
//
//        sig.update(msg, 0, msg.length);
//
//        byte[] s = sig.sign();
//
//        sig = Signature.getInstance("SHA3-512withSPHINCSPlus", "BCPQC");
//
//        sig.initVerify(kp.getPublic());
//
//        sig.update(msg, 0, msg.length);
//
//        assertTrue(sig.verify(s));
//
//        sig = Signature.getInstance("SHA512withSPHINCSPlus", "BCPQC");
//        try
//        {
//            sig.initVerify(kp.getPublic());
//            fail("no message");
//        }
//        catch (InvalidKeyException e)
//        {
//            assertEquals("SPHINCS-256 signature for tree digest: 2.16.840.1.101.3.4.2.8", e.getMessage());
//        }
//
//        try
//        {
//            sig.initSign(kp.getPrivate());
//            fail("no message");
//        }
//        catch (InvalidKeyException e)
//        {
//            assertEquals("SPHINCS-256 signature for tree digest: 2.16.840.1.101.3.4.2.8", e.getMessage());
//        }
//    }

    public void testSphincsRandomSigSHA2()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");

        kpg.initialize(SPHINCSPlusParameterSpec.sha256_256f, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SPHINCSPlus", "BCPQC");

        // random should be ignored...
        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("SPHINCSPlus", "BCPQC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    public void testSphincsRandomSigSHAKE()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");

        kpg.initialize(SPHINCSPlusParameterSpec.shake256_256f, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SPHINCSPlus", "BCPQC");

        // random should be ignored...
        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("SPHINCSPlus", "BCPQC");

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

