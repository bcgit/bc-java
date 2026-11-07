package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import junit.framework.TestCase;

/**
 * KEM tests for NTRU with the BC provider.
 */
public class NTRUTest
    extends TestCase
{
    private static final String NTRU_PROV_NAME = BouncyCastleProvider.PROVIDER_NAME;

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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", NTRU_PROV_NAME);
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", NTRU_PROV_NAME);
        kpg.initialize(NTRUParameterSpec.ntruhps2048509, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("Camellia"));
        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("Camellia-KWP"));
    }

    public void testBasicKEMSEED()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", NTRU_PROV_NAME);
        kpg.initialize(NTRUParameterSpec.ntruhps2048509, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("SEED", 128));
    }

    public void testBasicKEMARIA()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", NTRU_PROV_NAME);
        kpg.initialize(NTRUParameterSpec.ntruhps2048677, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("ARIA"));
        performKEMScipher(kpg.generateKeyPair(), "NTRU", new KEMParameterSpec("ARIA-KWP"));
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KEMParameterSpec ktsParameterSpec)
            throws Exception
    {
        Cipher w1 = Cipher.getInstance(algorithm, NTRU_PROV_NAME);

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

        Cipher w2 = Cipher.getInstance(algorithm, NTRU_PROV_NAME);

        w2.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsParameterSpec);

        Key k = w2.unwrap(data, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, k.getEncoded()));
    }

    public void testGenerateAES()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", NTRU_PROV_NAME);
        kpg.initialize(NTRUParameterSpec.ntruhps2048509, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("NTRU", NTRU_PROV_NAME);

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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", NTRU_PROV_NAME);
        kpg.initialize(NTRUParameterSpec.ntruhps4096821, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("NTRU", NTRU_PROV_NAME);

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    /*
     * With no KDF the key is taken from the front of the 256-bit shared secret, so a larger key size used to be padded
     * with zero bytes; it is now refused, as is a key of the wrong type. KEMKdfTest covers the KDF path.
     */
    public void testGenerateKeySizeBound()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", NTRU_PROV_NAME);
        kpg.initialize(NTRUParameterSpec.ntruhps2048509, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("NTRU", NTRU_PROV_NAME);

        try
        {
            keyGen.init(new KEMGenerateSpec.Builder(kp.getPublic(), "AES", 384).withNoKdf().build(), new SecureRandom());
            fail("oversize key accepted for generation");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("no KDF specified and ntruhps2048509 produces a 256 bit secret, 384 requested", e.getMessage());
        }

        try
        {
            keyGen.init(new KEMExtractSpec.Builder(kp.getPrivate(), new byte[699], "AES", 512).withNoKdf().build(), new SecureRandom());
            fail("oversize key accepted for extraction");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("no KDF specified and ntruhps2048509 produces a 256 bit secret, 512 requested", e.getMessage());
        }

        KeyPairGenerator mlkemKpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        KeyPair mlkemKp = mlkemKpg.generateKeyPair();
        try
        {
            keyGen.init(new KEMGenerateSpec(mlkemKp.getPublic(), "AES", 256), new SecureRandom());
            fail("non-NTRU key accepted");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("unsupported public key: NTRU public key required", e.getMessage());
        }

        // the full 256 bits are still available
        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES", 256), new SecureRandom());
        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES", 256), new SecureRandom());
        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), keyGen.generateKey().getEncoded()));
    }
}
