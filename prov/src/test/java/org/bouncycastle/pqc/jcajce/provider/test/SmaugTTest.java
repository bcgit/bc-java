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
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.SmaugTKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SmaugTParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SmaugTTest
    extends TestCase
{
    private static final SmaugTParameterSpec[] ALL_SPECS = new SmaugTParameterSpec[]
    {
        SmaugTParameterSpec.smaugt_mode1,
        SmaugTParameterSpec.smaugt_mode3,
        SmaugTParameterSpec.smaugt_mode5,
        SmaugTParameterSpec.smaugt_modet
    };

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

    public void testKeyPairGenerator()
        throws Exception
    {
        for (int i = 0; i != ALL_SPECS.length; i++)
        {
            SmaugTParameterSpec spec = ALL_SPECS[i];

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SMAUGT", "BCPQC");
            kpg.initialize(spec, new SecureRandom());

            KeyPair kp = kpg.generateKeyPair();

            assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
            assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

            assertTrue(kp.getPublic() instanceof SmaugTKey);
            assertTrue(kp.getPrivate() instanceof SmaugTKey);

            assertEquals(spec.getName(), ((SmaugTKey)kp.getPublic()).getParameterSpec().getName());
            assertEquals(spec.getName(), ((SmaugTKey)kp.getPrivate()).getParameterSpec().getName());
        }
    }

    public void testKeyFactoryRoundTrip()
        throws Exception
    {
        for (int i = 0; i != ALL_SPECS.length; i++)
        {
            SmaugTParameterSpec spec = ALL_SPECS[i];

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SMAUGT", "BCPQC");
            kpg.initialize(spec, new SecureRandom());

            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kFact = KeyFactory.getInstance("SMAUGT", "BCPQC");

            PublicKey pub = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey priv = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

            assertEquals(kp.getPublic(), pub);
            assertEquals(kp.getPrivate(), priv);
        }
    }

    public void testBasicKEMAES()
        throws Exception
    {
        for (int i = 0; i != ALL_SPECS.length; i++)
        {
            SmaugTParameterSpec spec = ALL_SPECS[i];

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SMAUGT", "BCPQC");
            kpg.initialize(spec, new SecureRandom());

            performKEMScipher(kpg.generateKeyPair(), "SMAUGT", new KEMParameterSpec("AES"));
            performKEMScipher(kpg.generateKeyPair(), "SMAUGT", new KEMParameterSpec("AES-KWP"));
        }
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KEMParameterSpec ktsParameterSpec)
        throws Exception
    {
        Cipher w1 = Cipher.getInstance(algorithm, "BCPQC");

        byte[] keyBytes;
        if (ktsParameterSpec.getKeyAlgorithmName().endsWith("KWP"))
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
        for (int i = 0; i != ALL_SPECS.length; i++)
        {
            SmaugTParameterSpec spec = ALL_SPECS[i];

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SMAUGT", "BCPQC");
            kpg.initialize(spec, new SecureRandom());

            KeyPair kp = kpg.generateKeyPair();

            KeyGenerator keyGen = KeyGenerator.getInstance("SMAUGT", "BCPQC");

            keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

            SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

            assertEquals("AES", secEnc1.getAlgorithm());
            assertEquals(32, secEnc1.getEncoded().length);

            keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

            SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

            assertEquals("AES", secEnc2.getAlgorithm());

            assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
        }
    }

    /**
     * The BC&lt;-&gt;BCPQC bridge regression test. For every parameter set, generate a keypair via
     * BCPQC, then call BouncyCastleProvider.getPublicKey/getPrivateKey against the encoded
     * SubjectPublicKeyInfo / PrivateKeyInfo and assert each returned key is a SmaugTKey with the
     * right algorithm and equals the original. If this passes, loadPQCKeys() is wired correctly.
     */
    public void testBcProviderKeyInfoConverter()
        throws Exception
    {
        for (int i = 0; i != ALL_SPECS.length; i++)
        {
            SmaugTParameterSpec spec = ALL_SPECS[i];

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SMAUGT", "BCPQC");
            kpg.initialize(spec, new SecureRandom());

            KeyPair kp = kpg.generateKeyPair();

            byte[] pubEnc = kp.getPublic().getEncoded();
            byte[] privEnc = kp.getPrivate().getEncoded();

            PublicKey pub = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(pubEnc));
            PrivateKey priv = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(privEnc));

            assertNotNull("BC provider returned null for " + spec.getName() + " public key", pub);
            assertNotNull("BC provider returned null for " + spec.getName() + " private key", priv);

            assertTrue(pub instanceof SmaugTKey);
            assertTrue(priv instanceof SmaugTKey);

            assertEquals(spec.getName(), ((SmaugTKey)pub).getParameterSpec().getName());
            assertEquals(spec.getName(), ((SmaugTKey)priv).getParameterSpec().getName());

            assertEquals(kp.getPublic(), pub);
            assertEquals(kp.getPrivate(), priv);
        }
    }
}
