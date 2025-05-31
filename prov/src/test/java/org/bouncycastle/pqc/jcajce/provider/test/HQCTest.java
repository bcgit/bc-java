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
import org.bouncycastle.pqc.crypto.hqc.HQCKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * KEM tests for HQC with the BCPQC provider.
 */
public class HQCTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        HQCTest test = new HQCTest();
        test.setUp();
        test.testGenerateAES();
    }

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
//        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
//        {
//            Security.addProvider(new BouncyCastleProvider());
//        }
    }

    public void testBasicKEMAES()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("HQC", "BCPQC");
        kpg.initialize(HQCParameterSpec.hqc128, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "HQC", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "HQC", new KEMParameterSpec("AES-KWP"));

        kpg.initialize(HQCParameterSpec.hqc256, new SecureRandom());
        KeyPair hqcKp = kpg.generateKeyPair();
        performKEMScipher(hqcKp, "HQC", new KEMParameterSpec("AES"));
        performKEMScipher(hqcKp, "HQC", new KEMParameterSpec("AES-KWP"));
    }

    public void testBasicKEMCamellia()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("HQC", "BCPQC");
        kpg.initialize(HQCParameterSpec.hqc128, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "HQC", new KEMParameterSpec("Camellia"));
        performKEMScipher(kpg.generateKeyPair(), "HQC", new KEMParameterSpec("Camellia-KWP"));
    }

    public void testBasicKEMSEED()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("HQC", "BCPQC");
        kpg.initialize(HQCParameterSpec.hqc128, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "HQC", new KEMParameterSpec("SEED"));
    }

    public void testBasicKEMARIA()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("HQC", "BCPQC");
        kpg.initialize(HQCParameterSpec.hqc128, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "HQC", new KEMParameterSpec("ARIA"));
        performKEMScipher(kpg.generateKeyPair(), "HQC", new KEMParameterSpec("ARIA-KWP"));
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KEMParameterSpec ktsParameterSpec)
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("HQC", "BCPQC");
        kpg.initialize(HQCParameterSpec.hqc128, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("HQC", "BCPQC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    public void testGenerateAES256()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("HQC", "BCPQC");
        kpg.initialize(HQCParameterSpec.hqc256, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("HQC", "BCPQC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    public void testReedSolomon()
        throws Exception
    {
        byte[] seed = Hex.decode("416a32ada1c7a569c34d5334273a781c340aac25eb7614271aa6930d0358fb30fd87e111336a29e165dc60d9643a3e9b");//b
        byte[] kemSeed = Hex.decode("13f36c0636ff93af6d702f7774097c185bf67cddc9b09f9b584d736c4faf40e073b0499efa0c926e9a44fec1e45ee4cf");
        //HQCKeyPairGenerator kpg = new HQCKeyPairGenerator();
        //kpg.init(new HQCKeyGenerationParameters();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("HQC", "BCPQC");
        SecureRandom random = new FixedSecureRandom(new FixedSecureRandom.Source[]{new FixedSecureRandom.Data(seed)});
        SecureRandom kemRandom = new FixedSecureRandom(new FixedSecureRandom.Source[]{new FixedSecureRandom.Data(kemSeed)});
        kpg.initialize(HQCParameterSpec.hqc128, random);
        KeyPair kp = kpg.generateKeyPair();
        String algorithm = "HQC";
        KEMParameterSpec ktsParameterSpec = new KEMParameterSpec("ARIA-KWP");
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

        w1.init(Cipher.WRAP_MODE, kp.getPublic(), ktsParameterSpec, kemRandom);

        byte[] data = w1.wrap(key);

        Cipher w2 = Cipher.getInstance(algorithm, "BCPQC");

        w2.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsParameterSpec);

        Key k = w2.unwrap(data, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, k.getEncoded()));
    }

}
