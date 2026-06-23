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
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * KEM tests for the standardised Classic McEliece KEM (ISO/IEC 18033-2:2006/Amd 2:2026, Clause 13)
 * with the BC provider. (The legacy BCPQC implementation is covered separately by CMCETest.)
 */
public class CMCEKEMTest
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
        CMCEParameterSpec[] specs = new CMCEParameterSpec[]{
            CMCEParameterSpec.mceliece460896, CMCEParameterSpec.mceliece460896f,
            CMCEParameterSpec.mceliece460896pc, CMCEParameterSpec.mceliece460896pcf,
            CMCEParameterSpec.mceliece6688128, CMCEParameterSpec.mceliece6688128f,
            CMCEParameterSpec.mceliece6688128pc, CMCEParameterSpec.mceliece6688128pcf,
            CMCEParameterSpec.mceliece6960119, CMCEParameterSpec.mceliece6960119f,
            CMCEParameterSpec.mceliece6960119pc, CMCEParameterSpec.mceliece6960119pcf,
            CMCEParameterSpec.mceliece8192128, CMCEParameterSpec.mceliece8192128f,
            CMCEParameterSpec.mceliece8192128pc, CMCEParameterSpec.mceliece8192128pcf
        };

        for (int i = 0; i != specs.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
            kpg.initialize(specs[i], new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kf = KeyFactory.getInstance("CMCE", "BC");
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");

        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("AES-KWP"));

        kpg.initialize(CMCEParameterSpec.mceliece460896pc, new SecureRandom());
        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("AES"));
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KEMParameterSpec ktsParameterSpec)
        throws Exception
    {
        Cipher w1 = Cipher.getInstance(algorithm, "BC");
        byte[] keyBytes = Hex.decode("000102030405060708090a0b0c0d0e0f");
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BC");
        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("CMCE", "BC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());
        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        assertEquals("AES", secEnc1.getAlgorithm());

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));
        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();
        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }
}
