package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

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
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.SNTRUPrimeKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * KEM tests for SNTRUPime with the BCPQC provider.
 */
public class SNTRUPrimeTest
    extends TestCase
{
    private static final SNTRUPrimeParameterSpec[] ALL_SPECS = new SNTRUPrimeParameterSpec[]
    {
        SNTRUPrimeParameterSpec.sntrup653,
        SNTRUPrimeParameterSpec.sntrup761,
        SNTRUPrimeParameterSpec.sntrup857,
        SNTRUPrimeParameterSpec.sntrup953,
        SNTRUPrimeParameterSpec.sntrup1013,
        SNTRUPrimeParameterSpec.sntrup1277
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

    /**
     * The BC&lt;-&gt;BCPQC bridge regression test: for every parameter set, generate a keypair via
     * BCPQC, then decode the encoded SubjectPublicKeyInfo / PrivateKeyInfo through
     * BouncyCastleProvider.getPublicKey / getPrivateKey - the path CertificateFactory("X.509", "BC")
     * and KeyFactory(..., "BC") use - and assert each key is recovered rather than returned as null,
     * which requires the Streamlined NTRU Prime OIDs to be registered in
     * BouncyCastleProvider.loadPQCKeys().
     */
    public void testBcProviderKeyInfoConverter()
        throws Exception
    {
        for (int i = 0; i != ALL_SPECS.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
            kpg.initialize(ALL_SPECS[i], new SecureRandom());

            KeyPair kp = kpg.generateKeyPair();

            PublicKey pub = BouncyCastleProvider.getPublicKey(
                SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));
            PrivateKey priv = BouncyCastleProvider.getPrivateKey(
                PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded()));

            assertNotNull("BC provider returned null for a SNTRUPrime public key", pub);
            assertNotNull("BC provider returned null for a SNTRUPrime private key", priv);

            assertTrue(pub instanceof SNTRUPrimeKey);
            assertTrue(priv instanceof SNTRUPrimeKey);

            assertEquals(kp.getPublic(), pub);
            assertEquals(kp.getPrivate(), priv);
        }
    }

    public void testBasicKEMAES()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup653, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("AES-KWP"));

        kpg.initialize(SNTRUPrimeParameterSpec.sntrup1013, new SecureRandom());
        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("AES"));
        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("AES-KWP"));
    }

    public void testBasicKEMCamellia()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup653, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KTSParameterSpec.Builder("Camellia", 256).build());
        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KTSParameterSpec.Builder("Camellia-KWP", 256).build());
    }

    public void testBasicKEMSEED()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup653, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KTSParameterSpec.Builder("SEED", 128).build());
    }

    public void testBasicKEMARIA()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup653, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("ARIA"));
        performKEMScipher(kpg.generateKeyPair(), "SNTRUPrime", new KEMParameterSpec("ARIA-KWP"));
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup653, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("SNTRUPrime", "BCPQC");

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc1.getAlgorithm());
        assertEquals(32, secEnc1.getEncoded().length);

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertEquals("AES", secEnc2.getAlgorithm());

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));
    }

    public void testGenerateAES256()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SNTRUPrime", "BCPQC");
        kpg.initialize(SNTRUPrimeParameterSpec.sntrup1277, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("SNTRUPrime", "BCPQC");

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
