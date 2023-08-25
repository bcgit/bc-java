package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * KEM tests for Kyber with the BCPQC provider.
 */
public class KyberTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testBasicKEMAES()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber512, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "Kyber", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "Kyber", new KEMParameterSpec("AES-KWP"));

        kpg.initialize(KyberParameterSpec.kyber768, new SecureRandom());
        performKEMScipher(kpg.generateKeyPair(), "Kyber", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "Kyber", new KEMParameterSpec("AES-KWP"));
    }

    public void testBasicKEMCamellia()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber512, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "Kyber", new KTSParameterSpec.Builder("Camellia", 128).withNoKdf().build());
        performKEMScipher(kpg.generateKeyPair(), "Kyber", new KTSParameterSpec.Builder("Camellia-KWP", 128).withNoKdf().build());
    }

    public void testBasicKEMSEED()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber512, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "Kyber", new KTSParameterSpec.Builder("SEED", 128).build());
    }

    public void testBasicKEMARIA()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber512, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "Kyber", new KTSParameterSpec.Builder("ARIA", 256).build());
        performKEMScipher(kpg.generateKeyPair(), "Kyber", new KTSParameterSpec.Builder("ARIA-KWP", 256).build());
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KTSParameterSpec ktsParameterSpec)
            throws Exception
    {
        Cipher w1 = Cipher.getInstance(algorithm, "BCPQC");

        byte[] keyBytes;
        if (algorithm.endsWith("KWP"))
        {
            keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0faa");
        }
        else
        {
            keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
        }
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        w1.init(Cipher.WRAP_MODE, kp.getPublic(), ktsParameterSpec);

        byte[] data = w1.wrap(key);

        Cipher w2 = Cipher.getInstance(algorithm, "BCPQC");

        w2.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsParameterSpec);

        Key k = w2.unwrap(data, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, k.getEncoded()));
    }

    public void testGenerateAES()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber512, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES", 128), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(16, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES", 128));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    public void testGenerateAES256()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kpg.initialize(KyberParameterSpec.kyber1024, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    public void testRestrictedKeyPairGen()
        throws Exception
    {
        doTestRestrictedKeyPairGen(KyberParameterSpec.kyber512, KyberParameterSpec.kyber1024);
        doTestRestrictedKeyPairGen(KyberParameterSpec.kyber768, KyberParameterSpec.kyber1024);
        doTestRestrictedKeyPairGen(KyberParameterSpec.kyber1024, KyberParameterSpec.kyber512);
    }

    private void doTestRestrictedKeyPairGen(KyberParameterSpec spec, KyberParameterSpec altSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kpg.getAlgorithm());
        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

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

    public void testRestrictedKeyGen()
        throws Exception
    {
        doTestRestrictedKeyGen(KyberParameterSpec.kyber512, KyberParameterSpec.kyber1024);
        doTestRestrictedKeyGen(KyberParameterSpec.kyber768, KyberParameterSpec.kyber1024);
        doTestRestrictedKeyGen(KyberParameterSpec.kyber1024, KyberParameterSpec.kyber512);
    }

    private void doTestRestrictedKeyGen(KyberParameterSpec spec, KyberParameterSpec altSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kpg.getAlgorithm());
        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        KeyGenerator keyGen = KeyGenerator.getInstance(spec.getName(), "BCPQC");

        assertEquals(spec.getName(), keyGen.getAlgorithm());

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));

        kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");

        kpg.initialize(altSpec, new SecureRandom());

        kp = kpg.generateKeyPair();

        try
        {
            keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key generator locked to " + spec.getName(), e.getMessage());
        }

        try
        {
            keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key generator locked to " + spec.getName(), e.getMessage());
        }
    }

    public void testRestrictedCipher()
        throws Exception
    {
        doTestRestrictedCipher(KyberParameterSpec.kyber512, KyberParameterSpec.kyber1024, new byte[16]);
        doTestRestrictedCipher(KyberParameterSpec.kyber768, KyberParameterSpec.kyber1024, new byte[24]);
        doTestRestrictedCipher(KyberParameterSpec.kyber1024, KyberParameterSpec.kyber512, new byte[32]);
    }

    private void doTestRestrictedCipher(KyberParameterSpec spec, KyberParameterSpec altSpec, byte[] keyBytes)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kpg.getAlgorithm());
        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        Cipher cipher = Cipher.getInstance(spec.getName(), "BCPQC");

        assertEquals(spec.getName(), cipher.getAlgorithm());

        cipher.init(Cipher.WRAP_MODE, kp.getPublic(), new SecureRandom());

        byte[] wrapBytes = cipher.wrap(new SecretKeySpec(keyBytes, "AES"));

        cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());

        Key unwrapKey = cipher.unwrap(wrapBytes, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, unwrapKey.getEncoded()));

        kpg = KeyPairGenerator.getInstance("Kyber", "BCPQC");

        kpg.initialize(altSpec, new SecureRandom());

        kp = kpg.generateKeyPair();

        try
        {
            cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("cipher locked to " + spec.getName(), e.getMessage());
        }

        try
        {
            cipher.init(Cipher.WRAP_MODE, kp.getPublic(), new SecureRandom());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("cipher locked to " + spec.getName(), e.getMessage());
        }
    }
}
