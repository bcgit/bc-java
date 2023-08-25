package org.bouncycastle.pqc.jcajce.provider.test;

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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * KEM tests for NTRU with the BC provider.
 */
public class NTRUTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testBasicKEMAES()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", "BC");
        kpg.initialize(NTRUParameterSpec.ntruhps2048509, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("AES-KWP"));

        kpg.initialize(NTRUParameterSpec.ntruhps4096821, new SecureRandom());
        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("AES-KWP"));
    }

    public void testBasicKEMCamellia()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", "BC");
        kpg.initialize(NTRUParameterSpec.ntruhps2048509, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("Camellia"));
        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("Camellia-KWP"));
    }

    public void testBasicKEMSEED()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", "BC");
        kpg.initialize(NTRUParameterSpec.ntruhps2048509, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("SEED", 128));
    }

    public void testBasicKEMARIA()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", "BC");
        kpg.initialize(NTRUParameterSpec.ntruhps2048677, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("ARIA"));
        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("ARIA-KWP"));
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KEMParameterSpec ktsParameterSpec)
            throws Exception
    {
        Cipher w1 = Cipher.getInstance(algorithm, "BC");

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

        Cipher w2 = Cipher.getInstance(algorithm, "BC");

        w2.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsParameterSpec);

        Key k = w2.unwrap(data, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, k.getEncoded()));
    }

    public void testGenerateAES()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", "BC");
        kpg.initialize(NTRUParameterSpec.ntruhps2048509, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("NTRU", "BC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES", 128), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(16, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES", 128), new SecureRandom());

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    public void testGenerateAES256()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", "BC");
        kpg.initialize(NTRUParameterSpec.ntruhps4096821, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("NTRU", "BC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }
}
