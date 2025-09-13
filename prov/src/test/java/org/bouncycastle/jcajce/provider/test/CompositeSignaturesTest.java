package org.bouncycastle.jcajce.provider.test;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
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
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeIndex;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPublicKey;
import org.bouncycastle.jcajce.spec.CompositeSignatureSpec;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
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
        "2.16.840.1.114027.80.9.1.0", // id-MLDSA44-RSA2048-PSS-SHA256
        "2.16.840.1.114027.80.9.1.1", // id-MLDSA44-RSA2048-PKCS15-SHA256
        "2.16.840.1.114027.80.9.1.2", // id-MLDSA44-Ed25519-SHA512
        "2.16.840.1.114027.80.9.1.3", // id-MLDSA44-ECDSA-P256-SHA256
        "2.16.840.1.114027.80.9.1.4", // id-MLDSA65-RSA3072-PSS-SHA512
        "2.16.840.1.114027.80.9.1.5", // id-MLDSA65-RSA3072-PKCS15-SHA512
        "2.16.840.1.114027.80.9.1.6", // id-MLDSA65-RSA4096-PSS-SHA512
        "2.16.840.1.114027.80.9.1.7", // id-MLDSA65-RSA4096-PKCS15-SHA512
        "2.16.840.1.114027.80.9.1.8", // id-MLDSA65-ECDSA-P256-SHA512
        "2.16.840.1.114027.80.9.1.9", // id-MLDSA65-ECDSA-P384-SHA512
        "2.16.840.1.114027.80.9.1.10", // id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
        "2.16.840.1.114027.80.9.1.11", // id-MLDSA65-Ed25519-SHA512
        "2.16.840.1.114027.80.9.1.12", // id-MLDSA87-ECDSA-P384-SHA512
        "2.16.840.1.114027.80.9.1.13", // id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
        "2.16.840.1.114027.80.9.1.14", // id-MLDSA87-Ed448-SHAKE256
        "2.16.840.1.114027.80.9.1.15", // id-MLDSA87-RSA3072-PSS-SHA512
        "2.16.840.1.114027.80.9.1.16", // id-MLDSA87-RSA4096-PSS-SHA512
        "2.16.840.1.114027.80.9.1.17", // id-MLDSA87-ECDSA-P521-SHA512
    };

    static final Map<String, String> oidMap = new HashMap<String, String>();

    static
    {
        oidMap.put("id-ML-DSA-44", "2.16.840.1.101.3.4.3.17");
        oidMap.put("id-ML-DSA-65", "2.16.840.1.101.3.4.3.18");
        oidMap.put("id-ML-DSA-87", "2.16.840.1.101.3.4.3.19");
        oidMap.put("id-MLDSA44-RSA2048-PSS-SHA256", "2.16.840.1.114027.80.9.1.0");
        oidMap.put("id-MLDSA44-RSA2048-PKCS15-SHA256", "2.16.840.1.114027.80.9.1.1");
        oidMap.put("id-MLDSA44-Ed25519-SHA512", "2.16.840.1.114027.80.9.1.2");
        oidMap.put("id-MLDSA44-ECDSA-P256-SHA256", "2.16.840.1.114027.80.9.1.3");
        oidMap.put("id-MLDSA65-RSA3072-PSS-SHA512", "2.16.840.1.114027.80.9.1.4");
        oidMap.put("id-MLDSA65-RSA3072-PKCS15-SHA512", "2.16.840.1.114027.80.9.1.5");
        oidMap.put("id-MLDSA65-RSA4096-PSS-SHA512", "2.16.840.1.114027.80.9.1.6");
        oidMap.put("id-MLDSA65-RSA4096-PKCS15-SHA512", "2.16.840.1.114027.80.9.1.7");
        oidMap.put("id-MLDSA65-ECDSA-P256-SHA512", "2.16.840.1.114027.80.9.1.8");
        oidMap.put("id-MLDSA65-ECDSA-P384-SHA512", "2.16.840.1.114027.80.9.1.9");
        oidMap.put("id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", "2.16.840.1.114027.80.9.1.10");
        oidMap.put("id-MLDSA65-Ed25519-SHA512", "2.16.840.1.114027.80.9.1.11");
        oidMap.put("id-MLDSA87-ECDSA-P384-SHA512", "2.16.840.1.114027.80.9.1.12");
        oidMap.put("id-MLDSA87-ECDSA-brainpoolP384r1-SHA512", "2.16.840.1.114027.80.9.1.13");
        oidMap.put("id-MLDSA87-Ed448-SHAKE256", "2.16.840.1.114027.80.9.1.14");
        oidMap.put("id-MLDSA87-RSA3072-PSS-SHA512", "2.16.840.1.114027.80.9.1.15");
        oidMap.put("id-MLDSA87-RSA4096-PSS-SHA512", "2.16.840.1.114027.80.9.1.16");
        oidMap.put("id-MLDSA87-ECDSA-P521-SHA512", "2.16.840.1.114027.80.9.1.17");
    }


    public static final String messageToBeSigned = "Hello, how was your day?";

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
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
            if (compAlg.equals(BCObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256))
            {
                check_RSA_Composite("ML-DSA-44", 2048, compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512))
            {
                check_RSA_Composite("ML-DSA-65", 3072, compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512))
            {
                check_RSA_Composite("ML-DSA-87", 3072, compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512))
            {
                check_RSA_Composite("ML-DSA-87", 4096, compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA44_Ed25519_SHA512))
            {
                check_EdDSA_Composite("ML-DSA-44", "Ed25519", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA65_Ed25519_SHA512))
            {
                check_EdDSA_Composite("ML-DSA-65", "Ed25519", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256))
            {
                check_EdDSA_Composite("ML-DSA-87", "Ed448", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256))
            {
                check_ECDSA_Composite("ML-DSA-44", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512))
            {
                check_ECDSA_Composite("ML-DSA-65", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512))
            {
                check_ECDSA_Composite("ML-DSA-65", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA384))
            {
                check_ECDSA_Composite("ML-DSA-65", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512))
            {
                check_ECDSA_Composite("ML-DSA-87", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512))
            {
                check_ECDSA_Composite("ML-DSA-87", compositePublicKey, compositePrivateKey);
            }
            else if (compAlg.equals(BCObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512))
            {
                check_ECDSA_Composite("ML-DSA-87", compositePublicKey, compositePrivateKey);
            }
            else
            {
                System.out.println(CompositeIndex.getAlgorithmName(compAlg));
            }
//            switch (CompositeSignaturesConstants.ASN1IdentifierCompositeNameMap.get(new ASN1ObjectIdentifier(oid)))
//            {
//            case MLDSA44_RSA2048_PSS_SHA256:
//            case MLDSA44_RSA2048_PKCS15_SHA256:
//
//                break;
//            case MLDSA44_Ed25519_SHA512:
//                TestCase.assertEquals("ML-DSA-44", firstPublicKeyAlgorithm);
//                TestCase.assertEquals("ML-DSA-44", firstPrivateKeyAlgorithm);
//                TestCase.assertEquals("ED25519", secondPublicKeyAlgorithm);
//                TestCase.assertEquals("ED25519", secondPrivateKeyAlgorithm);
//                break;
//            case MLDSA44_ECDSA_P256_SHA256:
//            case MLDSA44_ECDSA_brainpoolP256r1_SHA256:
//                TestCase.assertEquals("ML-DSA-44", firstPublicKeyAlgorithm);
//                TestCase.assertEquals("ML-DSA-44", firstPrivateKeyAlgorithm);
//                TestCase.assertEquals("ECDSA", secondPublicKeyAlgorithm);
//                TestCase.assertEquals("ECDSA", secondPrivateKeyAlgorithm);
//                break;
//            case MLDSA65_RSA3072_PSS_SHA512:
//            case MLDSA65_RSA3072_PKCS15_SHA512:
//                TestCase.assertEquals("ML-DSA-65", firstPublicKeyAlgorithm);
//                TestCase.assertEquals("ML-DSA-65", firstPrivateKeyAlgorithm);
//                TestCase.assertEquals("RSA", secondPublicKeyAlgorithm);
//                TestCase.assertEquals("RSA", secondPrivateKeyAlgorithm);
//                rsaPublicKey = (BCRSAPublicKey)compositePublicKey.getPublicKeys().get(1);
//                rsaPrivateKey = (BCRSAPublicKey)compositePublicKey.getPublicKeys().get(1);
//                TestCase.assertEquals(3072, rsaPublicKey.getModulus().bitLength());
//                TestCase.assertEquals(3072, rsaPrivateKey.getModulus().bitLength());
//                break;
//            case MLDSA65_Ed25519_SHA512:
//                TestCase.assertEquals("ML-DSA-65", firstPublicKeyAlgorithm);
//                TestCase.assertEquals("ML-DSA-65", firstPrivateKeyAlgorithm);
//                TestCase.assertEquals("ED25519", secondPublicKeyAlgorithm);
//                TestCase.assertEquals("ED25519", secondPrivateKeyAlgorithm);
//                break;
//            case MLDSA65_ECDSA_P256_SHA512:
//            case MLDSA65_ECDSA_brainpoolP256r1_SHA512:
//                TestCase.assertEquals("ML-DSA-65", firstPublicKeyAlgorithm);
//                TestCase.assertEquals("ML-DSA-65", firstPrivateKeyAlgorithm);
//                TestCase.assertEquals("ECDSA", secondPublicKeyAlgorithm);
//                TestCase.assertEquals("ECDSA", secondPrivateKeyAlgorithm);
//                break;
//            case MLDSA87_Ed448_SHA512:
//                TestCase.assertEquals("ML-DSA-87", firstPublicKeyAlgorithm);
//                TestCase.assertEquals("ML-DSA-87", firstPrivateKeyAlgorithm);
//                TestCase.assertEquals("ED448", secondPublicKeyAlgorithm);
//                TestCase.assertEquals("ED448", secondPrivateKeyAlgorithm);
//                break;
//            case MLDSA87_ECDSA_P384_SHA512:
//            case MLDSA87_ECDSA_brainpoolP384r1_SHA512:
//                TestCase.assertEquals("ML-DSA-87", firstPublicKeyAlgorithm);
//                TestCase.assertEquals("ML-DSA-87", firstPrivateKeyAlgorithm);
//                TestCase.assertEquals("ECDSA", secondPublicKeyAlgorithm);
//                TestCase.assertEquals("ECDSA", secondPrivateKeyAlgorithm);
//                break;
//            default:
//                throw new IllegalStateException(
//                    "Unexpected key algorithm." + CompositeSignaturesConstants.ASN1IdentifierCompositeNameMap.get(new ASN1ObjectIdentifier(oid)));
//            }
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

        CompositePublicKey compPublicKey = new CompositePublicKey(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, mldsaKp.getPublic(), ecKp.getPublic());
        CompositePrivateKey compPrivateKey = new CompositePrivateKey(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, mldsaKp.getPrivate(), ecKp.getPrivate());

        Signature signature = Signature.getInstance(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
        signature.initSign(compPrivateKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        byte[] signatureValue = signature.sign();

        signature.initVerify(compPublicKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));

        KeyFactory compFact = KeyFactory.getInstance(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
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
        KeyPairGenerator mldsaKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        mldsaKpGen.initialize(MLDSAParameterSpec.ml_dsa_44);

        KeyPair mldsaKp = mldsaKpGen.generateKeyPair();

        KeyPairGenerator ecKpGen = KeyPairGenerator.getInstance("EC", "SunEC");

        ecKpGen.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair ecKp = ecKpGen.generateKeyPair();

        CompositePublicKey compPublicKey = CompositePublicKey.builder(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
                                                .addPublicKey(mldsaKp.getPublic(), "BC")
                                                .addPublicKey(ecKp.getPublic(), "SunEC")
                                                .build();
        CompositePrivateKey compPrivateKey = CompositePrivateKey.builder(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
                                                    .addPrivateKey(mldsaKp.getPrivate(), "BC")
                                                    .addPrivateKey(ecKp.getPrivate(), "SunEC")
                                                    .build();

        Signature signature = Signature.getInstance(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
        signature.initSign(compPrivateKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        byte[] signatureValue = signature.sign();

        signature.initVerify(compPublicKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));

        KeyFactory compFact = KeyFactory.getInstance(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
        PrivateKey compPriv = compFact.generatePrivate(new PKCS8EncodedKeySpec(compPrivateKey.getEncoded()));
        PublicKey compPub = compFact.generatePublic(new X509EncodedKeySpec(compPublicKey.getEncoded()));

        signature.initSign(compPriv);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        signatureValue = signature.sign();

        signature.initVerify(compPub);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));

    }

    public void testMixedCompositionWithNull()
        throws Exception
    {
        KeyPairGenerator mldsaKpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");

        mldsaKpGen.initialize(MLDSAParameterSpec.ml_dsa_44);

        KeyPair mldsaKp = mldsaKpGen.generateKeyPair();

        KeyPairGenerator ecKpGen = KeyPairGenerator.getInstance("EC", "SunEC");

        ecKpGen.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair ecKp = ecKpGen.generateKeyPair();

        CompositePublicKey compPublicKey = CompositePublicKey.builder(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
            .addPublicKey(mldsaKp.getPublic())
            .addPublicKey(ecKp.getPublic()).build();
        CompositePrivateKey compPrivateKey = CompositePrivateKey.builder(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256)
            .addPrivateKey(mldsaKp.getPrivate())
            .addPrivateKey(ecKp.getPrivate(), "SunEC")
            .build();

        Signature signature = Signature.getInstance(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
        signature.initSign(compPrivateKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        byte[] signatureValue = signature.sign();

        signature.initVerify(compPublicKey);
        signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
        TestCase.assertTrue(signature.verify(signatureValue));

        KeyFactory compFact = KeyFactory.getInstance(BCObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256.getId(), "BC");
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
        }
    }

    public void testContextParameterSpec()
        throws Exception
    {
        String oid = "2.16.840.1.114027.80.9.1.8"; // MLDSA44withECDSA_P256_SHA512

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
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
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
                x5cpk = ((BCMLDSAPublicKey)cert.getPublicKey()).getPublicData();
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
                byte[] pkEncoded = pubKey.getEncoded();
                TestCase.assertTrue(Arrays.areEqual(pkEncoded, pk));
                byte[] skEncoded = privKey.getEncoded();
                privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(sk_pkcs8));
                TestCase.assertTrue(Arrays.areEqual(skEncoded, sk));
                TestCase.assertTrue(Arrays.areEqual(skEncoded, privKey.getEncoded()));
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
            TestCase.assertTrue(Arrays.areEqual(pk, x5cpk));

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
                m = Base64.getDecoder().decode(extractString(currentObject.toString(), "m"));
                currentObject = new StringBuilder();
            }
        }

        return testCases;
    }

    private static Map<String, Object> parseJsonObject(String json)
    {
        HashMap<String, Object> testCase = new HashMap<>();
        testCase.put("tcId", extractString(json, "tcId"));
        testCase.put("pk", Base64.getDecoder().decode(extractString(json, "pk")));
        testCase.put("x5c", Base64.getDecoder().decode(extractString(json, "x5c")));
        testCase.put("sk", Base64.getDecoder().decode(extractString(json, "sk")));
        testCase.put("sk_pkcs8", Base64.getDecoder().decode(extractString(json, "sk_pkcs8")));
        testCase.put("s", Base64.getDecoder().decode(extractString(json, "s")));
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
}
