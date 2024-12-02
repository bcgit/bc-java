package org.bouncycastle.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeIndex;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

public class CompositeSignaturesTest
    extends TestCase
{

    private static String[] compositeSignaturesOIDs = {
        "2.16.840.1.114027.80.8.1.21", //id-MLDSA44-RSA2048-PSS-SHA256
        "2.16.840.1.114027.80.8.1.22", //id-MLDSA44-RSA2048-PKCS15-SHA256
        "2.16.840.1.114027.80.8.1.23", //id-MLDSA44-Ed25519-SHA512
        "2.16.840.1.114027.80.8.1.24", //id-MLDSA44-ECDSA-P256-SHA256
        "2.16.840.1.114027.80.8.1.26", //id-MLDSA65-RSA3072-PSS-SHA512
        "2.16.840.1.114027.80.8.1.27", //id-MLDSA65-RSA3072-PKCS15-SHA512
        "2.16.840.1.114027.80.8.1.28", //id-MLDSA65-ECDSA-P256-SHA512
        "2.16.840.1.114027.80.8.1.29", //id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
        "2.16.840.1.114027.80.8.1.30", //id-MLDSA65-Ed25519-SHA512
        "2.16.840.1.114027.80.8.1.31", //id-MLDSA87-ECDSA-P384-SHA512
        "2.16.840.1.114027.80.8.1.32", //id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
        "2.16.840.1.114027.80.8.1.33", //id-MLDSA87-Ed448-SHA512
    };

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

            String firstPublicKeyAlgorithm = Strings.toUpperCase(compositePublicKey.getPublicKeys().get(0).getAlgorithm());
            String secondPublicKeyAlgorithm = Strings.toUpperCase(compositePublicKey.getPublicKeys().get(1).getAlgorithm());
            String firstPrivateKeyAlgorithm = Strings.toUpperCase(compositePrivateKey.getPrivateKeys().get(0).getAlgorithm());
            String secondPrivateKeyAlgorithm = Strings.toUpperCase(compositePrivateKey.getPrivateKeys().get(1).getAlgorithm());

            BCRSAPublicKey rsaPublicKey = null;
            BCRSAPublicKey rsaPrivateKey = null;

//            switch (CompositeSignaturesConstants.ASN1IdentifierCompositeNameMap.get(new ASN1ObjectIdentifier(oid)))
//            {
//            case MLDSA44_RSA2048_PSS_SHA256:
//            case MLDSA44_RSA2048_PKCS15_SHA256:
//                TestCase.assertEquals("ML-DSA-44", firstPublicKeyAlgorithm);
//                TestCase.assertEquals("ML-DSA-44", firstPrivateKeyAlgorithm);
//                TestCase.assertEquals("RSA", secondPublicKeyAlgorithm);
//                TestCase.assertEquals("RSA", secondPrivateKeyAlgorithm);
//                rsaPublicKey = (BCRSAPublicKey)compositePublicKey.getPublicKeys().get(1);
//                rsaPrivateKey = (BCRSAPublicKey)compositePublicKey.getPublicKeys().get(1);
//                TestCase.assertEquals(2048, rsaPublicKey.getModulus().bitLength());
//                TestCase.assertEquals(2048, rsaPrivateKey.getModulus().bitLength());
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
//            case MLDSA65_ECDSA_brainpoolP256r1_SHA512:           ompositeK
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

    public void testSigningAndVerificationInternal()
        throws Exception
    {
        for (String oid : compositeSignaturesOIDs)
        {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(oid, "BC");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Signature signature = Signature.getInstance(oid, "BC");
            signature.initSign(keyPair.getPrivate());
            signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
            byte[] signatureValue = signature.sign();

            signature.initVerify(keyPair.getPublic());
            signature.update(Strings.toUTF8ByteArray(messageToBeSigned));
            TestCase.assertTrue(signature.verify(signatureValue));
        }
    }

    public void testContextParameterSpec()
        throws Exception
    {
        String oid = "2.16.840.1.114027.80.8.1.24"; // MLDSA44withECDSA_P256_SHA256

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
    
    /*
    //TODO: samples now out of date
    public void testDecodingAndVerificationExternal()
        throws Exception
    {
        InputStream is = TestResourceFinder.findTestResource("pqc/composite", "compositeSignatures.sample");
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        String line = null;
        int count = 0;
        while ((line = reader.readLine()) != null)
        {
            if (line.length() == 0)
            {
                continue;
            }

            String[] lineParts = line.split(";");

            if (lineParts.length != 4)
            {
                throw new IllegalStateException("Input file has unexpected format.");
            }
            String oid = lineParts[0];
            String signatureValueBase64 = lineParts[1];
            String publicKeyBase64 = lineParts[2];
            String messageBase64 = lineParts[3];

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.decode(publicKeyBase64));
            KeyFactory keyFactory = KeyFactory.getInstance(oid, "BC");
            CompositePublicKey compositePublicKey = (CompositePublicKey)keyFactory.generatePublic(pubKeySpec);
             
            Signature signature = Signature.getInstance(oid, "BC");
            signature.initVerify(compositePublicKey);
            signature.update(Base64.decode(messageBase64));
            assertTrue(oid.toString(), signature.verify(Base64.decode(signatureValueBase64)));
            count++;
        }

        assertEquals(compositeSignaturesOIDs.length, count);
    }
     */
}
