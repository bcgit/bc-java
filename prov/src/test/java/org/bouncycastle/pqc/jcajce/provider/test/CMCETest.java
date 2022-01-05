package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;


/**
 * KEM tests for CMCE with the BCPQC provider.
 */
public class CMCETest
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BCPQC");
        kpg.initialize(CMCEParameterSpec.mceliece348864, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("AES-KWP"));

        kpg.initialize(CMCEParameterSpec.mceliece460896, new SecureRandom());
        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("AES-KWP"));
    }

    public void testBasicKEMCamellia()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BCPQC");
        kpg.initialize(CMCEParameterSpec.mceliece348864, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("Camellia"));
        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("Camellia-KWP"));
    }

    public void testBasicKEMARIA()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("CMCE", "BCPQC");
        kpg.initialize(CMCEParameterSpec.mceliece348864, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("ARIA"));
        performKEMScipher(kpg.generateKeyPair(), "CMCE", new KEMParameterSpec("ARIA-KWP"));
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
}
