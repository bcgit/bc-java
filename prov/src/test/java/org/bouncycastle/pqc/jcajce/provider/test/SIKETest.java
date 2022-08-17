package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * KEM tests for SIKE with the BCPQC provider.
 */
public class SIKETest
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
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SIKE", "BCPQC");
//        kpg.initialize(SIKEParameterSpec.sikep434, new SecureRandom());
//
//        performKEMScipher(kpg.generateKeyPair(), "SIKE", new KEMParameterSpec("AES"));
//        performKEMScipher(kpg.generateKeyPair(), "SIKE", new KEMParameterSpec("AES-KWP"));
//
//        kpg.initialize(SIKEParameterSpec.sikep610, new SecureRandom());
//        performKEMScipher(kpg.generateKeyPair(), "SIKE", new KEMParameterSpec("AES"));
//        performKEMScipher(kpg.generateKeyPair(), "SIKE", new KEMParameterSpec("AES-KWP"));
    }
//
//    public void testBasicKEMCamellia()
//            throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SIKE", "BCPQC");
//        kpg.initialize(SIKEParameterSpec.sikep610, new SecureRandom());
//
//        performKEMScipher(kpg.generateKeyPair(), "SIKE", new KEMParameterSpec("Camellia"));
//        performKEMScipher(kpg.generateKeyPair(), "SIKE", new KEMParameterSpec("Camellia-KWP"));
//    }
//
//    public void testBasicKEMSEED()
//            throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SIKE", "BCPQC");
//        kpg.initialize(SIKEParameterSpec.sikep434, new SecureRandom());
//
//        performKEMScipher(kpg.generateKeyPair(), "SIKE", new KEMParameterSpec("SEED"));
//    }
//
//    public void testBasicKEMARIA()
//            throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SIKE", "BCPQC");
//        kpg.initialize(SIKEParameterSpec.sikep503_compressed, new SecureRandom());
//
//        performKEMScipher(kpg.generateKeyPair(), "SIKE", new KEMParameterSpec("ARIA"));
//        performKEMScipher(kpg.generateKeyPair(), "SIKE", new KEMParameterSpec("ARIA-KWP"));
//    }
//
//    private void performKEMScipher(KeyPair kp, String algorithm, KEMParameterSpec ktsParameterSpec)
//            throws Exception
//    {
//        Cipher w1 = Cipher.getInstance(algorithm, "BCPQC");
//
//        byte[] keyBytes;
//        if (algorithm.endsWith("KWP"))
//        {
//            keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0faa");
//        }
//        else
//        {
//            keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
//        }
//        SecretKey key = new SecretKeySpec(keyBytes, "AES");
//
//        w1.init(Cipher.WRAP_MODE, kp.getPublic(), ktsParameterSpec);
//
//        byte[] data = w1.wrap(key);
//
//        Cipher w2 = Cipher.getInstance(algorithm, "BCPQC");
//
//        w2.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsParameterSpec);
//
//        Key k = w2.unwrap(data, "AES", Cipher.SECRET_KEY);
//
//        assertTrue(Arrays.areEqual(keyBytes, k.getEncoded()));
//    }
//
//    public void testGenerateAES()
//            throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SIKE", "BCPQC");
//        kpg.initialize(SIKEParameterSpec.sikep434_compressed, new SecureRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        KeyGenerator keyGen = KeyGenerator.getInstance("SIKE", "BCPQC");
//
//        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());
//
//        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();
//
//        assertEquals("AES", secEnc1.getAlgorithm());
//        assertEquals(16, secEnc1.getEncoded().length);
//
//        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"), new SecureRandom());
//
//        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();
//
//        assertEquals("AES", secEnc2.getAlgorithm());
//
//        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
//    }
//
//    public void testGenerateAES256()
//            throws Exception
//    {
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SIKE", "BCPQC");
//        kpg.initialize(SIKEParameterSpec.sikep751, new SecureRandom());
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        KeyGenerator keyGen = KeyGenerator.getInstance("SIKE", "BCPQC");
//
//        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());
//
//        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();
//
//        assertEquals("AES", secEnc1.getAlgorithm());
//        assertEquals(32, secEnc1.getEncoded().length);
//
//        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"), new SecureRandom());
//
//        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();
//
//        assertEquals("AES", secEnc2.getAlgorithm());
//
//        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
//    }
}
