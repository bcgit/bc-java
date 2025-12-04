package org.bouncycastle.jcajce.provider.test;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.internal.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeIndex;
import org.bouncycastle.jcajce.spec.CompositeSignatureSpec;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

public class CompositeSignaturesTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        CompositeSignaturesTest test = new CompositeSignaturesTest();
        test.setUp();
        List<Map<String, Object>> testVectors = test.readTestVectorsFromJson("pqc/crypto/composite", "testvectors.json");
        test.compositeSignaturesTest(testVectors);
        test.testSigningAndVerificationInternal();
    }

    private static String[] compositeSignaturesOIDs = {
        "1.3.6.1.5.5.7.6.37", // id_MLDSA44_RSA2048_PSS_SHA256
        "1.3.6.1.5.5.7.6.38", // id_MLDSA44_RSA2048_PKCS15_SHA256 
        "1.3.6.1.5.5.7.6.39", // id_MLDSA44_Ed25519_SHA512 
        "1.3.6.1.5.5.7.6.40", // id_MLDSA44_ECDSA_P256_SHA256 
        "1.3.6.1.5.5.7.6.41", // id_MLDSA65_RSA3072_PSS_SHA512 
        "1.3.6.1.5.5.7.6.42", // id_MLDSA65_RSA3072_PKCS15_SHA512 
        "1.3.6.1.5.5.7.6.43", // id_MLDSA65_RSA4096_PSS_SHA512 
        "1.3.6.1.5.5.7.6.44", // id_MLDSA65_RSA4096_PKCS15_SHA512 
        "1.3.6.1.5.5.7.6.45", // id_MLDSA65_ECDSA_P256_SHA512 
        "1.3.6.1.5.5.7.6.46", // id_MLDSA65_ECDSA_P384_SHA512 
        "1.3.6.1.5.5.7.6.47", // id_MLDSA65_ECDSA_brainpoolP256r1_SHA512 
        "1.3.6.1.5.5.7.6.48", // id_MLDSA65_Ed25519_SHA512 
        "1.3.6.1.5.5.7.6.49", // id_MLDSA87_ECDSA_P384_SHA512 
        "1.3.6.1.5.5.7.6.50", // id_MLDSA87_ECDSA_brainpoolP384r1_SHA512 
        "1.3.6.1.5.5.7.6.51", // id_MLDSA87_Ed448_SHAKE256 
        "1.3.6.1.5.5.7.6.52", // id_MLDSA87_RSA3072_PSS_SHA512 
        "1.3.6.1.5.5.7.6.53", // id_MLDSA87_RSA4096_PSS_SHA512 
        "1.3.6.1.5.5.7.6.54"  // id_MLDSA87_ECDSA_P521_SHA512
    };

    static final Map<String, String> oidMap = new HashMap<String, String>();

    static
    {
        oidMap.put("id-ML-DSA-44", "2.16.840.1.101.3.4.3.17");
        oidMap.put("id-ML-DSA-65", "2.16.840.1.101.3.4.3.18");
        oidMap.put("id-ML-DSA-87", "2.16.840.1.101.3.4.3.19");
        oidMap.put("id-MLDSA44-RSA2048-PSS-SHA256", IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256.getId());
        oidMap.put("id-MLDSA44-RSA2048-PKCS15-SHA256", IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256.getId());
        oidMap.put("id-MLDSA44-Ed25519-SHA512", IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512.getId());
        oidMap.put("id-MLDSA44-ECDSA-P256-SHA256", IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId());
        oidMap.put("id-MLDSA65-RSA3072-PSS-SHA512", IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512.getId());
        oidMap.put("id-MLDSA65-RSA3072-PKCS15-SHA512", IANAObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512.getId());
        oidMap.put("id-MLDSA65-RSA4096-PSS-SHA512",  IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512.getId());
        oidMap.put("id-MLDSA65-RSA4096-PKCS15-SHA512", IANAObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512.getId());
        oidMap.put("id-MLDSA65-ECDSA-P256-SHA512", IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512.getId());
        oidMap.put("id-MLDSA65-ECDSA-P384-SHA512", IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512.getId());
        oidMap.put("id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512.getId());
        oidMap.put("id-MLDSA65-Ed25519-SHA512", IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512.getId());
        oidMap.put("id-MLDSA87-ECDSA-P384-SHA512", IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512.getId());
        oidMap.put("id-MLDSA87-ECDSA-brainpoolP384r1-SHA512", IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512.getId());
        oidMap.put("id-MLDSA87-Ed448-SHAKE256", IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256.getId());
        oidMap.put("id-MLDSA87-RSA3072-PSS-SHA512", IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512.getId());
        oidMap.put("id-MLDSA87-RSA4096-PSS-SHA512", IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512.getId());
        oidMap.put("id-MLDSA87-ECDSA-P521-SHA512", IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512.getId());
    }


    public static final String messageToBeSigned = "Hello, how was your day?";

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testTestVectors()
        throws Exception
    {
        List<Map<String, Object>> testVectors = readTestVectorsFromJson("pqc/crypto/composite", "testvectors.json");
        compositeSignaturesTest(testVectors);
    }

    public void testKeyPairGeneration()
        throws Exception
    {
        for (ASN1ObjectIdentifier asnOid : CompositeIndex.getSupportedIdentifiers())
        {
            String oid = asnOid.getId();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(oid, "BC");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            CompositePublicKey compositePublicKey = (CompositePublicKey)keyPair.getPublic();
            CompositePrivateKey compositePrivateKey = (CompositePrivateKey)keyPair.getPrivate();

            ASN1ObjectIdentifier compAlg = compositePrivateKey.getAlgorithmIdentifier().getAlgorithm();
            if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256))
            {
                check_RSA_Composite("ML-DSA-44", 2048, compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512))
            {
                check_RSA_Composite("ML-DSA-65", 3072, compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512))
            {
                check_RSA_Composite("ML-DSA-87", 3072, compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512))
            {
                check_RSA_Composite("ML-DSA-87", 4096, compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512))
            {
                check_EdDSA_Composite("ML-DSA-44", "Ed25519", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512))
            {
                check_EdDSA_Composite("ML-DSA-65", "Ed25519", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256))
            {
                check_EdDSA_Composite("ML-DSA-87", "Ed448", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256))
            {
                check_ECDSA_Composite("ML-DSA-44", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512))
            {
                check_ECDSA_Composite("ML-DSA-65", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512))
            {
                check_ECDSA_Composite("ML-DSA-65", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512))
            {
                check_ECDSA_Composite("ML-DSA-87", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512))
            {
                check_ECDSA_Composite("ML-DSA-87", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512))
            {
                check_ECDSA_Composite("ML-DSA-87", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512))
            {
                check_ECDSA_Composite("ML-DSA-65", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256))
            {
                check_RSA_Composite("ML-DSA-44", 2048, compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512))
            {
                check_RSA_Composite("ML-DSA-65", 3072, compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512))
            {
                check_RSA_Composite("ML-DSA-65", 4096, compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(IANAObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512))
            {
                check_RSA_Composite("ML-DSA-65", 4096, compositePublicKey, compositePrivateKey);
            }
            else
            {
                throw new IllegalStateException("untested: " + CompositeIndex.getAlgorithmName(compAlg));
            }
        }
    }

    private void check_RSA_Composite(String firstAlg, int rsaKeySize, CompositePublicKey compPub, CompositePrivateKey compPriv)
    {
        TestCase.assertEquals(firstAlg, compPub.getPublicKeys().get(0).getAlgorithm());
        TestCase.assertEquals("RSA", compPub.getPublicKeys().get(1).getAlgorithm());
        RSAPublicKey rsaPublicKey = (RSAPublicKey)compPub.getPublicKeys().get(1);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)compPriv.getPrivateKeys().get(1);
        TestCase.assertEquals(rsaKeySize, rsaPublicKey.getModulus().bitLength());
        TestCase.assertEquals(rsaKeySize, rsaPrivateKey.getModulus().bitLength());
    }

    private void check_EdDSA_Composite(String firstAlg, String edDSAAlg, CompositePublicKey compPub, CompositePrivateKey compPriv)
    {
        TestCase.assertEquals(firstAlg, compPub.getPublicKeys().get(0).getAlgorithm());
        TestCase.assertEquals(edDSAAlg, compPub.getPublicKeys().get(1).getAlgorithm());
        TestCase.assertEquals(firstAlg, compPriv.getPrivateKeys().get(0).getAlgorithm());
        TestCase.assertEquals(edDSAAlg, compPriv.getPrivateKeys().get(1).getAlgorithm());
    }

    private void check_ECDSA_Composite(String firstAlg, CompositePublicKey compPub, CompositePrivateKey compPriv)
    {
        TestCase.assertEquals(firstAlg, compPub.getPublicKeys().get(0).getAlgorithm());
        TestCase.assertEquals("EC", compPub.getPublicKeys().get(1).getAlgorithm());
        TestCase.assertEquals(firstAlg, compPriv.getPrivateKeys().get(0).getAlgorithm());
        TestCase.assertEquals("EC", compPriv.getPrivateKeys().get(1).getAlgorithm());
    }

    public void testSelfComposition()
        throws Exception
    {
        KeyPairGenerator mldsaKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        mldsaKpGen.initialize(MLDSAParameterSpec.ml_dsa_44);

        KeyPair mldsaKp = mldsaKpGen.generateKeyPair();

        KeyPairGenerator ecKpGen = KeyPairGenerator.getInstance("EC", "BC");

        ecKpGen.initialize(new ECGenParameterSpec("P-256"));

        KeyPair ecKp = ecKpGen.generateKeyPair();

        CompositePublicKey compPublicKey = new CompositePublicKey(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, mldsaKp.getPublic(), ecKp.getPublic());
        CompositePrivateKey compPrivateKey = new CompositePrivateKey(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, mldsaKp.getPrivate(), ecKp.getPrivate());

        Signature signature = Signature.getInstance(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
        signature.initSign(compPrivateKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        byte[] signatureValue = signature.sign();

        signature.initVerify(compPublicKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));

        KeyFactory compFact = KeyFactory.getInstance(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
        PrivateKey compPriv = compFact.generatePrivate(new PKCS8EncodedKeySpec(compPrivateKey.getEncoded()));
        PublicKey compPub = compFact.generatePublic(new X509EncodedKeySpec(compPublicKey.getEncoded()));

        signature.initSign(compPriv);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        signatureValue = signature.sign();

        signature.initVerify(compPub);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));

    }

    public void testMixedComposition()
        throws Exception
    {
        if (Security.getProvider("SunEC") == null)
        {
            return;
        }
        KeyPairGenerator mldsaKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        mldsaKpGen.initialize(MLDSAParameterSpec.ml_dsa_44);

        KeyPair mldsaKp = mldsaKpGen.generateKeyPair();

        KeyPairGenerator ecKpGen = KeyPairGenerator.getInstance("EC", "SunEC");

        ecKpGen.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair ecKp = ecKpGen.generateKeyPair();

        CompositePublicKey compPublicKey = CompositePublicKey.builder(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
            .addPublicKey(mldsaKp.getPublic(), "BC")
            .addPublicKey(ecKp.getPublic(), "SunEC")
            .build();
        CompositePrivateKey compPrivateKey = CompositePrivateKey.builder(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
            .addPrivateKey(mldsaKp.getPrivate(), "BC")
            .addPrivateKey(ecKp.getPrivate(), "SunEC")
            .build();

        Signature signature = Signature.getInstance(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
        signature.initSign(compPrivateKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        byte[] signatureValue = signature.sign();

        signature.initVerify(compPublicKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));

        signature = Signature.getInstance("COMPOSITE", "BC");

        signature.initVerify(compPublicKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));

        KeyFactory compFact = KeyFactory.getInstance(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
        PrivateKey compPriv = compFact.generatePrivate(new PKCS8EncodedKeySpec(compPrivateKey.getEncoded()));
        PublicKey compPub = compFact.generatePublic(new X509EncodedKeySpec(compPublicKey.getEncoded()));
        signature = Signature.getInstance(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");

        signature.initSign(compPriv);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        signatureValue = signature.sign();

        signature.initVerify(compPub);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));

        //
        // as COMPOSITE on sig creation
        //
        compPublicKey = CompositePublicKey.builder(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
            .addPublicKey(mldsaKp.getPublic(), "BC")
            .addPublicKey(ecKp.getPublic(), "SunEC")
            .build();
        compPrivateKey = CompositePrivateKey.builder(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
            .addPrivateKey(mldsaKp.getPrivate(), "BC")
            .addPrivateKey(ecKp.getPrivate(), "SunEC")
            .build();

        signature = Signature.getInstance("COMPOSITE", "BC");

        signature.initSign(compPriv);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        signatureValue = signature.sign();

        signature = Signature.getInstance(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
        signature.initVerify(compPub);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));
    }

    public void testMixedCompositionHSMStyle()
        throws Exception
    {
        if (Security.getProvider("SunEC") == null)
        {
            return;
        }
        KeyPairGenerator mldsaKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        mldsaKpGen.initialize(MLDSAParameterSpec.ml_dsa_44);

        KeyPair mldsaKp = mldsaKpGen.generateKeyPair();

        KeyPairGenerator ecKpGen = KeyPairGenerator.getInstance("EC", "SunEC");

        ecKpGen.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair ecKp = ecKpGen.generateKeyPair();

        CompositePublicKey compPublicKey = CompositePublicKey.builder(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
            .addPublicKey(mldsaKp.getPublic(), "BC")
            .addPublicKey(ecKp.getPublic(), "SunEC")
            .build();
        CompositePrivateKey compPrivateKey = CompositePrivateKey.builder(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
            .addPrivateKey(new ProxyHSMPrivateKey((MLDSAPrivateKey)mldsaKp.getPrivate()), "BC")
            .addPrivateKey(ecKp.getPrivate(), "SunEC")
            .build();

        Signature signature = Signature.getInstance("COMPOSITE", "BC");
        
        try
        {
            signature.initSign(compPrivateKey);
            fail("proxy HSM key did not fail with BC");
        }
        catch (InvalidKeyException e)
        {
            // we want to make sure it got at least as far as passing key to ML-DSA implementation
            assertEquals("unknown private key passed to ML-DSA", e.getMessage());
        }
    }

    public void testMixedCompositionWithNull()
        throws Exception
    {
        if (Security.getProvider("SunEC") == null)
        {
            return;
        }
        KeyPairGenerator mldsaKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        mldsaKpGen.initialize(MLDSAParameterSpec.ml_dsa_44);

        KeyPair mldsaKp = mldsaKpGen.generateKeyPair();

        KeyPairGenerator ecKpGen = KeyPairGenerator.getInstance("EC", "SunEC");

        ecKpGen.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair ecKp = ecKpGen.generateKeyPair();

        CompositePublicKey compPublicKey = CompositePublicKey.builder(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
            .addPublicKey(mldsaKp.getPublic())
            .addPublicKey(ecKp.getPublic()).build();
        CompositePrivateKey compPrivateKey = CompositePrivateKey.builder(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
            .addPrivateKey(mldsaKp.getPrivate())
            .addPrivateKey(ecKp.getPrivate(), "SunEC")
            .build();

        Signature signature = Signature.getInstance(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
        signature.initSign(compPrivateKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        byte[] signatureValue = signature.sign();

        signature.initVerify(compPublicKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));

        KeyFactory compFact = KeyFactory.getInstance(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
        PrivateKey compPriv = compFact.generatePrivate(new PKCS8EncodedKeySpec(compPrivateKey.getEncoded()));
        PublicKey compPub = compFact.generatePublic(new X509EncodedKeySpec(compPublicKey.getEncoded()));

        signature.initSign(compPriv);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        signatureValue = signature.sign();

        signature.initVerify(compPub);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));

    }

    public void testPrehash()
        throws Exception
    {
        doTestPrehash("MLDSA44-ECDSA-P256-SHA256", "SHA256");
        doTestPrehash("MLDSA65-ECDSA-P256-SHA512", "SHA512");
    }

    public void testNamedPrehash()
        throws Exception
    {
        for (Iterator it = CompositeIndex.getSupportedIdentifiers().iterator(); it.hasNext(); )
        {
            String name = CompositeIndex.getAlgorithmName((ASN1ObjectIdentifier)it.next());
            doTestNamedPrehash(name, name.substring(name.lastIndexOf("-") + 1));
        }
    }

    public void testPrehashWithContext()
        throws Exception
    {
        doTestPrehash("MLDSA44-ECDSA-P256-SHA256", "SHA256", new ContextParameterSpec(Hex.decode("deadbeef")));
        doTestPrehash("MLDSA65-ECDSA-P256-SHA512", "SHA512", new ContextParameterSpec(Hex.decode("deadbeef")));
    }

    private void doTestPrehash(String sigName, String digestName)
        throws Exception
    {
        byte[] msg = Strings.toUTF8ByteArray(messageToBeSigned);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(sigName, "BC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // full msg sign, verify hash
        Signature signature = Signature.getInstance(sigName, "BC");
        signature.initSign(keyPair.getPrivate());
        signature.update(msg);

        byte[] signatureValue = signature.sign();

        signature.initVerify(keyPair.getPublic());
        signature.setParameter(new CompositeSignatureSpec(true));
        signature.update(MessageDigest.getInstance(digestName, "BC").digest(msg));
        assertTrue(signature.verify(signatureValue));

        // full msg sign, verify hash
        signature = Signature.getInstance(sigName, "BC");
        signature.initSign(keyPair.getPrivate());
        signature.setParameter(new CompositeSignatureSpec(true));
        signature.update(MessageDigest.getInstance(digestName, "BC").digest(msg));

        signatureValue = signature.sign();

        signature.initVerify(keyPair.getPublic());
        signature.setParameter(new CompositeSignatureSpec(false));
        signature.update(msg);
        assertTrue(signature.verify(signatureValue));

        // exceptions
        signature.initSign(keyPair.getPrivate());
        try
        {
            signature.setParameter(new CompositeSignatureSpec(true));
            signature.update(Hex.decode("beef"));
            signature.sign();
            fail("sign");
        }
        catch (SignatureException e)
        {
            assertEquals("provided pre-hash digest is the wrong length", e.getMessage());
        }

        // exceptions
        signature.initVerify(keyPair.getPublic());
        try
        {
            signature.setParameter(new CompositeSignatureSpec(true));
            signature.update(Hex.decode("beef"));
            signature.verify(signatureValue);
            fail("verify");
        }
        catch (SignatureException e)
        {
            assertEquals("provided pre-hash digest is the wrong length", e.getMessage());
        }
    }

    private void doTestNamedPrehash(String sigName, String digestName)
        throws Exception
    {
        byte[] msg = Strings.toUTF8ByteArray(messageToBeSigned);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(sigName, "BC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // full msg sign, verify hash
        Signature signature = Signature.getInstance(sigName, "BC");
        signature.initSign(keyPair.getPrivate());
        signature.update(msg);

        byte[] signatureValue = signature.sign();

        signature = Signature.getInstance(sigName + "-PREHASH", "BC");
        signature.initVerify(keyPair.getPublic());
        signature.update(MessageDigest.getInstance(digestName, "BC").digest(msg));
        assertTrue(signature.verify(signatureValue));

        // full msg sign, verify hash
        signature = Signature.getInstance(sigName + "-PREHASH", "BC");
        signature.initSign(keyPair.getPrivate());
        signature.update(MessageDigest.getInstance(digestName, "BC").digest(msg));

        signatureValue = signature.sign();

        signature = Signature.getInstance(sigName, "BC");
        signature.initVerify(keyPair.getPublic());
        signature.update(msg);
        assertTrue(signature.verify(signatureValue));

        // exceptions
        signature = Signature.getInstance(sigName + "-PREHASH", "BC");
        signature.initSign(keyPair.getPrivate());
        try
        {
            signature.update(Hex.decode("beef"));
            signature.sign();
            fail("sign");
        }
        catch (SignatureException e)
        {
            assertEquals("provided pre-hash digest is the wrong length", e.getMessage());
        }

        // exceptions
        signature.initVerify(keyPair.getPublic());
        try
        {
            signature.setParameter(new CompositeSignatureSpec(true));
            signature.update(Hex.decode("beef"));
            signature.verify(signatureValue);
            fail("verify");
        }
        catch (SignatureException e)
        {
            assertEquals("provided pre-hash digest is the wrong length", e.getMessage());
        }
    }

    private void doTestPrehash(String sigName, String digestName, ContextParameterSpec contextSpec)
        throws Exception
    {
        byte[] msg = Strings.toUTF8ByteArray(messageToBeSigned);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(sigName, "BC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // full msg sign, verify hash
        Signature signature = Signature.getInstance(sigName, "BC");
        signature.initSign(keyPair.getPrivate());
        signature.setParameter(contextSpec);
        signature.update(msg);

        byte[] signatureValue = signature.sign();

        signature.initVerify(keyPair.getPublic());
        signature.setParameter(new CompositeSignatureSpec(true, contextSpec));
        signature.update(MessageDigest.getInstance(digestName, "BC").digest(msg));
        assertTrue(signature.verify(signatureValue));

        // check reflection case
        signature.initVerify(keyPair.getPublic());
        signature.setParameter(new CompositeSignatureSpec(true, new MyContextSpec(contextSpec.getContext())));
        signature.update(MessageDigest.getInstance(digestName, "BC").digest(msg));
        assertTrue(signature.verify(signatureValue));

        // full msg sign, verify hash
        signature = Signature.getInstance(sigName, "BC");
        signature.initSign(keyPair.getPrivate());
        signature.setParameter(new CompositeSignatureSpec(true, contextSpec));
        signature.update(MessageDigest.getInstance(digestName, "BC").digest(msg));

        signatureValue = signature.sign();

        signature.initVerify(keyPair.getPublic());
        signature.setParameter(new CompositeSignatureSpec(false, contextSpec));
        signature.update(msg);
        assertTrue(signature.verify(signatureValue));

        signature.initVerify(keyPair.getPublic());
        signature.setParameter(new CompositeSignatureSpec(false));
        signature.update(msg);
        assertFalse(signature.verify(signatureValue));
    }

    public void testSigningAndVerificationInternal()
        throws Exception
    {
        byte[] msg = Strings.toUTF8ByteArray(messageToBeSigned);

        for (String oid : compositeSignaturesOIDs)
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(oid, "BC");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Signature signature = Signature.getInstance(oid, "BC");
            signature.initSign(keyPair.getPrivate());
            signature.update(msg);
            byte[] signatureValue = signature.sign();

            signature.initVerify(keyPair.getPublic());
            signature.update(msg);
            TestCase.assertTrue(signature.verify(signatureValue));

            Signature compSig = Signature.getInstance("COMPOSITE", "BC");

            compSig.initVerify(keyPair.getPublic());
            compSig.update(msg);

            TestCase.assertTrue(compSig.verify(signatureValue));

            compSig.initSign(keyPair.getPrivate());
            compSig.update(msg);
            signatureValue = compSig.sign();

            signature.initVerify(keyPair.getPublic());
            signature.update(msg);
            TestCase.assertTrue(signature.verify(signatureValue));
        }
    }

    public void testContextParameterSpec()
        throws Exception
    {
        String oid = IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(); // MLDSA44withECDSA_P256_SHA256

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(oid, "BC");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Signature signature = Signature.getInstance(oid, "BC");
        signature.initSign(keyPair.getPrivate());

        signature.setParameter(new ContextParameterSpec(Strings.toByteArray("Hello, world!")));

        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        byte[] signatureValue = signature.sign();

        signature = Signature.getInstance(oid, "BC");

        signature.initVerify(keyPair.getPublic());

        signature.setParameter(new ContextParameterSpec(Strings.toByteArray("Hello, world!")));

        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));
    }

    public void compositeSignaturesTest(List<Map<String, Object>> testVectors)
        throws Exception
    {
        for (int i = 0; i < testVectors.size(); i++)
        {

            Map<String, Object> map = testVectors.get(i);
            String tcId = (String)map.get("tcId");
            byte[] pk = (byte[])map.get("pk");
            byte[] x5c = (byte[])map.get("x5c");
            byte[] sk = (byte[])map.get("sk");
            byte[] sk_pkcs8 = (byte[])map.get("sk_pkcs8");
            byte[] s = (byte[])map.get("s");
            byte[] m = (byte[])map.get("m");
            byte[] x5cpk = null;
            PublicKey pubKey = null, certPubKey = null;
            PrivateKey privKey = null;
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate cert = null;
            try
            {
                cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(x5c));
            }
            catch (Exception e)
            {
                //Ignore IOException
            }

            if (tcId.contains("id-ML-DSA"))
            {
                KeyFactory kFact = KeyFactory.getInstance("ML-DSA", "BC");
                MLDSAParameterSpec parameterSpec = null;
                if (tcId.contains("44"))
                {
                    parameterSpec = MLDSAParameterSpec.ml_dsa_44;
                }
                else if (tcId.contains("65"))
                {
                    parameterSpec = MLDSAParameterSpec.ml_dsa_65;
                }
                else if (tcId.contains("87"))
                {
                    parameterSpec = MLDSAParameterSpec.ml_dsa_87;
                }
                MLDSAPrivateKeySpec privSpec = new MLDSAPrivateKeySpec(parameterSpec, sk);
                assertTrue(privSpec.isSeed());
                privKey = kFact.generatePrivate(privSpec);
                MLDSAPublicKeySpec pubSpec = new MLDSAPublicKeySpec(((MLDSAPrivateKey)privKey).getParameterSpec(),
                    ((MLDSAPrivateKey)privKey).getPublicKey().getPublicData());
                pubKey = kFact.generatePublic(pubSpec);
                x5cpk = ((MLDSAPublicKey)cert.getPublicKey()).getPublicData();
                certPubKey = kFact.generatePublic(new MLDSAPublicKeySpec(((MLDSAPrivateKey)privKey).getParameterSpec(),
                    x5cpk));
            }
            else
            {
                KeyFactory keyFactory = KeyFactory.getInstance(oidMap.get(tcId), "BC");
                pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(new ASN1ObjectIdentifier(oidMap.get(tcId))), pk).getEncoded()));
                privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(new PrivateKeyInfo(
                    new AlgorithmIdentifier(new ASN1ObjectIdentifier(oidMap.get(tcId))), new DEROctetString(sk)).getEncoded()));
                certPubKey = cert.getPublicKey();
                x5cpk = certPubKey.getEncoded();
                byte[] pkEncoded = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()).getPublicKeyData().getBytes();
                TestCase.assertTrue(Arrays.areEqual(pkEncoded, pk));
                byte[] skEncoded = PrivateKeyInfo.getInstance(privKey.getEncoded()).getPrivateKey().getOctets();
                privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(sk_pkcs8));
                TestCase.assertTrue(Arrays.areEqual(skEncoded, sk));
            }
            Signature signature = Signature.getInstance(oidMap.get(tcId), "BC");
            //1. Load the public key pk or certificate x5c and use it to verify the signature s over the message m.
            signature.initVerify(pubKey);
            signature.update(m);

            TestCase.assertTrue(signature.verify(s));
            // 2. Validate the self-signed certificate x5c.
            cert.verify(cert.getPublicKey(), "BC");
            signature.initVerify(certPubKey);
            signature.update(m);
            TestCase.assertTrue(signature.verify(s));
            // Compare public keys
            //TestCase.assertTrue(Arrays.areEqual(pk, x5cpk));

            // 3. Load the signing private key sk and use it to produce a new signature which can be verified using the provided pk or x5c.
            signature.initSign(privKey);
            signature.update(m);
            byte[] signatureValue = signature.sign();
            signature.initVerify(pubKey);
            signature.update(m);
            TestCase.assertTrue(signature.verify(signatureValue));
        }
    }


    public List<Map<String, Object>> readTestVectorsFromJson(String homeDire, String fileName)
        throws Exception
    {
        InputStream src = TestResourceFinder.findTestResource(homeDire, fileName);
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        String line;
        List<Map<String, Object>> testCases = new ArrayList<Map<String, Object>>();
        HashMap<String, Object> map = new HashMap<String, Object>();
        StringBuilder currentObject = null;
        byte[] m = null;
        while ((line = bin.readLine()) != null)
        {
            line = line.trim();

            if (line.startsWith("{"))
            {
                currentObject = new StringBuilder();
            }

            if (currentObject != null)
            {
                currentObject.append(line);
            }

            if ((line.endsWith("},") || line.endsWith("}")) && currentObject != null)
            {
                String jsonObj = currentObject.toString();
                Map<String, Object> testCase = parseJsonObject(jsonObj);
                testCase.put("m", m);
                testCases.add(testCase);
                currentObject = null;
            }

            if (currentObject != null && currentObject.toString().contains("\"m\":"))
            {
                m = Base64.decode(extractString(currentObject.toString(), "m"));
                currentObject = new StringBuilder();
            }
        }

        return testCases;
    }

    private static Map<String, Object> parseJsonObject(String json)
    {
        HashMap<String, Object> testCase = new HashMap<String, Object>();
        testCase.put("tcId", extractString(json, "tcId"));
        testCase.put("pk", Base64.decode(extractString(json, "pk")));
        testCase.put("x5c", Base64.decode(extractString(json, "x5c")));
        testCase.put("sk", Base64.decode(extractString(json, "sk")));
        testCase.put("sk_pkcs8", Base64.decode(extractString(json, "sk_pkcs8")));
        testCase.put("s", Base64.decode(extractString(json, "s")));
        return testCase;
    }

    private static String extractString(String json, String key)
    {
        String pattern = "\"" + key + "\"";
        int start = json.indexOf(pattern);
        if (start < 0)
        {
            return "";
        }

        start = json.indexOf(":", start) + 1;
        while (json.charAt(start) != '"')
        {
            start++;
        }
        start++;

        int end = start;
        while (json.charAt(end) != '"')
        {
            end++;
        }

        return json.substring(start, end).replace("\\\"", "\"");
    }

    public static class MyContextSpec
        implements AlgorithmParameterSpec
    {
        private final byte[] context;

        MyContextSpec(byte[] context)
        {
            this.context = context;
        }

        public byte[] getContext()
        {
            return context;
        }
    }

    private static class ProxyHSMPrivateKey
        implements MLDSAPrivateKey
    {
        private final MLDSAPrivateKey privateKey;

        ProxyHSMPrivateKey(MLDSAPrivateKey privateKey)
        {
            this.privateKey = privateKey;
        }

        @Override
        public String getAlgorithm()
        {
            return privateKey.getAlgorithm();
        }

        @Override
        public String getFormat()
        {
            throw new IllegalStateException("getFormat() called");
        }

        @Override
        public byte[] getEncoded()
        {
            throw new IllegalStateException("getEncoded() called");
        }

        @Override
        public MLDSAParameterSpec getParameterSpec()
        {
            return privateKey.getParameterSpec();
        }

        @Override
        public MLDSAPublicKey getPublicKey()
        {
            return privateKey.getPublicKey();
        }

        @Override
        public byte[] getPrivateData()
        {
            throw new IllegalStateException("getPrivateData() called");
        }

        @Override
        public byte[] getSeed()
        {
            throw new IllegalStateException("getSeed() called");
        }

        @Override
        public MLDSAPrivateKey getPrivateKey(boolean preferSeedOnly)
        {
            throw new IllegalStateException("getPrivateKey() called");
        }
    }
}
