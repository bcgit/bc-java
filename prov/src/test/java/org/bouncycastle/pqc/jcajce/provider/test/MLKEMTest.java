package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * KEM tests for MLKEM with the BC provider.
 */
public class MLKEMTest
    extends TestCase
{
    static private final String[] names = new String[]{
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024"
    };
    
    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testParametersAndParamSpecs()
        throws Exception
    {
        MLKEMParameters mlKemParameters[] = new MLKEMParameters[]
            {
                MLKEMParameters.ml_kem_512,
                MLKEMParameters.ml_kem_768,
                MLKEMParameters.ml_kem_1024
            };

        for (int i = 0; i != names.length; i++)
        {
            assertEquals(names[i], MLKEMParameterSpec.fromName(mlKemParameters[i].getName()).getName());
        }

        for (int i = 0; i != names.length; i++)
        {
            assertEquals(names[i], MLKEMParameterSpec.fromName(names[i]).getName());
        }
    }
    
    public void testKeyFactory()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("ML-KEM", "BC");
        KeyPairGenerator kpGen512 = KeyPairGenerator.getInstance("ML-KEM-512");
        KeyPair kp512 = kpGen512.generateKeyPair();
        KeyPairGenerator kpGen768 = KeyPairGenerator.getInstance("ML-KEM-768");
        KeyPair kp768 = kpGen768.generateKeyPair();
        KeyPairGenerator kpGen1024 = KeyPairGenerator.getInstance("ML-KEM-1024");
        KeyPair kp1024 = kpGen1024.generateKeyPair();

        tryKeyFact(KeyFactory.getInstance("ML-KEM-512", "BC"), kp512, kp768, "2.16.840.1.101.3.4.4.2");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_alg_ml_kem_512.toString(), "BC"), kp512, kp768, "2.16.840.1.101.3.4.4.2");
        tryKeyFact(KeyFactory.getInstance("ML-KEM-768", "BC"), kp768, kp512, "2.16.840.1.101.3.4.4.1");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_alg_ml_kem_768.toString(), "BC"), kp768, kp512, "2.16.840.1.101.3.4.4.1");
        tryKeyFact(KeyFactory.getInstance("ML-KEM-1024", "BC"), kp1024, kp768, "2.16.840.1.101.3.4.4.2");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_alg_ml_kem_1024.toString(), "BC"), kp1024, kp768, "2.16.840.1.101.3.4.4.2");
    }

    private void tryKeyFact(KeyFactory kFact, KeyPair kpValid, KeyPair kpInvalid, String oid)
        throws Exception
    {
        kFact.generatePrivate(new PKCS8EncodedKeySpec(kpValid.getPrivate().getEncoded()));
        kFact.generatePublic(new X509EncodedKeySpec(kpValid.getPublic().getEncoded()));

        try
        {
            kFact.generatePrivate(new PKCS8EncodedKeySpec(kpInvalid.getPrivate().getEncoded()));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("incorrect algorithm OID for key: " + oid, e.getMessage());
        }
        try
        {
            kFact.generatePublic(new X509EncodedKeySpec(kpInvalid.getPublic().getEncoded()));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("incorrect algorithm OID for key: " + oid, e.getMessage());
        }
    }

    public void testBasicKEMCamellia()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());

        kpg.generateKeyPair().getPrivate().getEncoded();
        performKEMScipher(kpg.generateKeyPair(), "ML-KEM", new KTSParameterSpec.Builder("Camellia", 128).withNoKdf().build());
        performKEMScipher(kpg.generateKeyPair(), "ML-KEM", new KTSParameterSpec.Builder("Camellia-KWP", 128).withNoKdf().build());
    }

    public void testBasicKEMSEED()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "ML-KEM", new KTSParameterSpec.Builder("SEED", 128).build());
    }

    public void testBasicKEMARIA()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());

        performKEMScipher(kpg.generateKeyPair(), "ML-KEM", new KTSParameterSpec.Builder("ARIA", 256).build());
        performKEMScipher(kpg.generateKeyPair(), "ML-KEM", new KTSParameterSpec.Builder("ARIA-KWP", 256).build());
    }

    private void performKEMScipher(KeyPair kp, String algorithm, KTSParameterSpec ktsParameterSpec)
        throws Exception
    {
        Cipher w1 = Cipher.getInstance(algorithm, "BC");

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

        Cipher w2 = Cipher.getInstance(algorithm, "BC");

        w2.init(Cipher.UNWRAP_MODE, kp.getPrivate(), ktsParameterSpec);

        Key k = w2.unwrap(data, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, k.getEncoded()));
    }

    public void testGenerateAES()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_512, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("ML-KEM", "BC");

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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kpg.initialize(MLKEMParameterSpec.ml_kem_1024, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyGenerator keyGen = KeyGenerator.getInstance("ML-KEM", "BC");

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
        doTestRestrictedKeyPairGen(MLKEMParameterSpec.ml_kem_512, MLKEMParameterSpec.ml_kem_1024);
        doTestRestrictedKeyPairGen(MLKEMParameterSpec.ml_kem_768, MLKEMParameterSpec.ml_kem_1024);
        doTestRestrictedKeyPairGen(MLKEMParameterSpec.ml_kem_1024, MLKEMParameterSpec.ml_kem_512);
    }

    private void doTestRestrictedKeyPairGen(MLKEMParameterSpec spec, MLKEMParameterSpec altSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kpg.getAlgorithm());
        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

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
        doTestRestrictedKeyGen(MLKEMParameterSpec.ml_kem_512, MLKEMParameterSpec.ml_kem_1024);
        doTestRestrictedKeyGen(MLKEMParameterSpec.ml_kem_768, MLKEMParameterSpec.ml_kem_1024);
        doTestRestrictedKeyGen(MLKEMParameterSpec.ml_kem_1024, MLKEMParameterSpec.ml_kem_512);
    }

    private void doTestRestrictedKeyGen(MLKEMParameterSpec spec, MLKEMParameterSpec altSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kpg.getAlgorithm());
        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        KeyGenerator keyGen = KeyGenerator.getInstance(spec.getName(), "BC");

        assertEquals(spec.getName(), keyGen.getAlgorithm());

        keyGen.init(new KEMGenerateSpec(kp.getPublic(), "AES"), new SecureRandom());

        SecretKeyWithEncapsulation secEnc1 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        keyGen.init(new KEMExtractSpec(kp.getPrivate(), secEnc1.getEncapsulation(), "AES"));

        SecretKeyWithEncapsulation secEnc2 = (SecretKeyWithEncapsulation)keyGen.generateKey();

        assertTrue(Arrays.areEqual(secEnc1.getEncoded(), secEnc2.getEncoded()));

        kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");

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
        doTestRestrictedCipher(MLKEMParameterSpec.ml_kem_512, MLKEMParameterSpec.ml_kem_1024, new byte[16]);
        doTestRestrictedCipher(MLKEMParameterSpec.ml_kem_768, MLKEMParameterSpec.ml_kem_1024, new byte[24]);
        doTestRestrictedCipher(MLKEMParameterSpec.ml_kem_1024, MLKEMParameterSpec.ml_kem_512, new byte[32]);
    }

    private void doTestRestrictedCipher(MLKEMParameterSpec spec, MLKEMParameterSpec altSpec, byte[] keyBytes)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kpg.getAlgorithm());
        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        Cipher cipher = Cipher.getInstance(spec.getName(), "BC");

        assertEquals(spec.getName(), cipher.getAlgorithm());

        cipher.init(Cipher.WRAP_MODE, kp.getPublic(), new SecureRandom());

        byte[] wrapBytes = cipher.wrap(new SecretKeySpec(keyBytes, "AES"));

        cipher.init(Cipher.UNWRAP_MODE, kp.getPrivate());

        Key unwrapKey = cipher.unwrap(wrapBytes, "AES", Cipher.SECRET_KEY);

        assertTrue(Arrays.areEqual(keyBytes, unwrapKey.getEncoded()));

        kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");

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
