package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * KEM tests for the standardised FrodoKEM (ISO/IEC 18033-2) with the BC provider.
 */
public class FrodoKEMTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKeyPairGenAndFactory()
        throws Exception
    {
        FrodoKEMParameterSpec[] specs = new FrodoKEMParameterSpec[]{
            FrodoKEMParameterSpec.frodokem976shake,
            FrodoKEMParameterSpec.frodokem1344shake,
            FrodoKEMParameterSpec.efrodokem976shake,
            FrodoKEMParameterSpec.efrodokem1344shake,
            FrodoKEMParameterSpec.frodokem976aes,
            FrodoKEMParameterSpec.frodokem1344aes,
            FrodoKEMParameterSpec.efrodokem976aes,
            FrodoKEMParameterSpec.efrodokem1344aes
        };

        for (int i = 0; i != specs.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
            kpg.initialize(specs[i], new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("FRODOKEM", "BC");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

            assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(), pub.getEncoded()));
            assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), priv.getEncoded()));
            assertEquals(specs[i].getName(), kp.getPublic().getAlgorithm());
        }
    }

    public void testBasicKEM()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "FRODOKEM", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "FRODOKEM", new KEMParameterSpec("AES-KWP"));

        kpg.initialize(FrodoKEMParameterSpec.efrodokem1344shake, new SecureRandom());
        performKEMScipher(kpg.generateKeyPair(), "FRODOKEM", new KEMParameterSpec("AES"));
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("FRODOKEM", "BC");
        kpg.initialize(FrodoKEMParameterSpec.frodokem976shake, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("FRODOKEM", "BC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        // KEMGenerateSpec(pub, "AES") applies the default KDF (X9.44 KDF-3 / SHA-256) at 256 bits,
        // so the derived AES key is 32 bytes regardless of frodokem976shake's 192-bit raw secret.
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }
}
