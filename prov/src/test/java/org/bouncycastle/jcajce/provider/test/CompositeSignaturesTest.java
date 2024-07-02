package org.bouncycastle.jcajce.provider.test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeSignaturesConstants;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

public class CompositeSignaturesTest
    extends TestCase
{

    private static String[] compositeSignaturesOIDs = {
        "2.16.840.1.114027.80.8.1.1", //id-MLDSA44-RSA2048-PSS-SHA256
        "2.16.840.1.114027.80.8.1.2", //id-MLDSA44-RSA2048-PKCS15-SHA256
        "2.16.840.1.114027.80.8.1.3", //id-MLDSA44-Ed25519-SHA512
        "2.16.840.1.114027.80.8.1.4", //id-MLDSA44-ECDSA-P256-SHA256
        "2.16.840.1.114027.80.8.1.5", //id-MLDSA44-ECDSA-brainpoolP256r1-SHA256
        "2.16.840.1.114027.80.8.1.6", //id-MLDSA65-RSA3072-PSS-SHA512
        "2.16.840.1.114027.80.8.1.7", //id-MLDSA65-RSA3072-PKCS15-SHA512
        "2.16.840.1.114027.80.8.1.8", //id-MLDSA65-ECDSA-P256-SHA512
        "2.16.840.1.114027.80.8.1.9", //id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
        "2.16.840.1.114027.80.8.1.10", //id-MLDSA65-Ed25519-SHA512
        "2.16.840.1.114027.80.8.1.11", //id-MLDSA87-ECDSA-P384-SHA512
        "2.16.840.1.114027.80.8.1.12", //id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
        "2.16.840.1.114027.80.8.1.13", //id-MLDSA87-Ed448-SHA512
        // Falcon composites below were excluded from the draft. See MiscObjectIdentifiers for details.
        "2.16.840.1.114027.80.8.1.14", //id-Falcon512-ECDSA-P256-SHA256
        "2.16.840.1.114027.80.8.1.15", //id-Falcon512-ECDSA-brainpoolP256r1-SHA256
        "2.16.840.1.114027.80.8.1.16", //id-Falcon512-Ed25519-SHA512
    };

    public static final String messageToBeSigned = "Hello, how was your day?";

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testKeyPairGeneration()
        throws Exception
    {
        for (String oid : compositeSignaturesOIDs)
        {
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

            switch (CompositeSignaturesConstants.ASN1IdentifierCompositeNameMap.get(new ASN1ObjectIdentifier(oid)))
            {
            case MLDSA44_RSA2048_PSS_SHA256:
            case MLDSA44_RSA2048_PKCS15_SHA256:
                TestCase.assertEquals("DILITHIUM2", firstPublicKeyAlgorithm);
                TestCase.assertEquals("DILITHIUM2", firstPrivateKeyAlgorithm);
                TestCase.assertEquals("RSA", secondPublicKeyAlgorithm);
                TestCase.assertEquals("RSA", secondPrivateKeyAlgorithm);
                rsaPublicKey = (BCRSAPublicKey)compositePublicKey.getPublicKeys().get(1);
                rsaPrivateKey = (BCRSAPublicKey)compositePublicKey.getPublicKeys().get(1);
                TestCase.assertEquals(2048, rsaPublicKey.getModulus().bitLength());
                TestCase.assertEquals(2048, rsaPrivateKey.getModulus().bitLength());
                break;
            case MLDSA44_Ed25519_SHA512:
                TestCase.assertEquals("DILITHIUM2", firstPublicKeyAlgorithm);
                TestCase.assertEquals("DILITHIUM2", firstPrivateKeyAlgorithm);
                TestCase.assertEquals("ED25519", secondPublicKeyAlgorithm);
                TestCase.assertEquals("ED25519", secondPrivateKeyAlgorithm);
                break;
            case MLDSA44_ECDSA_P256_SHA256:
            case MLDSA44_ECDSA_brainpoolP256r1_SHA256:
                TestCase.assertEquals("DILITHIUM2", firstPublicKeyAlgorithm);
                TestCase.assertEquals("DILITHIUM2", firstPrivateKeyAlgorithm);
                TestCase.assertEquals("ECDSA", secondPublicKeyAlgorithm);
                TestCase.assertEquals("ECDSA", secondPrivateKeyAlgorithm);
                break;
            case MLDSA65_RSA3072_PSS_SHA512:
            case MLDSA65_RSA3072_PKCS15_SHA512:
                TestCase.assertEquals("DILITHIUM3", firstPublicKeyAlgorithm);
                TestCase.assertEquals("DILITHIUM3", firstPrivateKeyAlgorithm);
                TestCase.assertEquals("RSA", secondPublicKeyAlgorithm);
                TestCase.assertEquals("RSA", secondPrivateKeyAlgorithm);
                rsaPublicKey = (BCRSAPublicKey)compositePublicKey.getPublicKeys().get(1);
                rsaPrivateKey = (BCRSAPublicKey)compositePublicKey.getPublicKeys().get(1);
                TestCase.assertEquals(3072, rsaPublicKey.getModulus().bitLength());
                TestCase.assertEquals(3072, rsaPrivateKey.getModulus().bitLength());
                break;
            case MLDSA65_Ed25519_SHA512:
                TestCase.assertEquals("DILITHIUM3", firstPublicKeyAlgorithm);
                TestCase.assertEquals("DILITHIUM3", firstPrivateKeyAlgorithm);
                TestCase.assertEquals("ED25519", secondPublicKeyAlgorithm);
                TestCase.assertEquals("ED25519", secondPrivateKeyAlgorithm);
                break;
            case MLDSA65_ECDSA_P256_SHA512:
            case MLDSA65_ECDSA_brainpoolP256r1_SHA512:
                TestCase.assertEquals("DILITHIUM3", firstPublicKeyAlgorithm);
                TestCase.assertEquals("DILITHIUM3", firstPrivateKeyAlgorithm);
                TestCase.assertEquals("ECDSA", secondPublicKeyAlgorithm);
                TestCase.assertEquals("ECDSA", secondPrivateKeyAlgorithm);
                break;
            case MLDSA87_Ed448_SHA512:
                TestCase.assertEquals("DILITHIUM5", firstPublicKeyAlgorithm);
                TestCase.assertEquals("DILITHIUM5", firstPrivateKeyAlgorithm);
                TestCase.assertEquals("ED448", secondPublicKeyAlgorithm);
                TestCase.assertEquals("ED448", secondPrivateKeyAlgorithm);
                break;
            case MLDSA87_ECDSA_P384_SHA512:
            case MLDSA87_ECDSA_brainpoolP384r1_SHA512:
                TestCase.assertEquals("DILITHIUM5", firstPublicKeyAlgorithm);
                TestCase.assertEquals("DILITHIUM5", firstPrivateKeyAlgorithm);
                TestCase.assertEquals("ECDSA", secondPublicKeyAlgorithm);
                TestCase.assertEquals("ECDSA", secondPrivateKeyAlgorithm);
                break;
            case Falcon512_Ed25519_SHA512:
                TestCase.assertEquals("FALCON-512", firstPublicKeyAlgorithm);
                TestCase.assertEquals("FALCON-512", firstPrivateKeyAlgorithm);
                TestCase.assertEquals("ED25519", secondPublicKeyAlgorithm);
                TestCase.assertEquals("ED25519", secondPrivateKeyAlgorithm);
                break;
            case Falcon512_ECDSA_P256_SHA256:
            case Falcon512_ECDSA_brainpoolP256r1_SHA256:
                TestCase.assertEquals("FALCON-512", firstPublicKeyAlgorithm);
                TestCase.assertEquals("FALCON-512", firstPrivateKeyAlgorithm);
                TestCase.assertEquals("ECDSA", secondPublicKeyAlgorithm);
                TestCase.assertEquals("ECDSA", secondPrivateKeyAlgorithm);
                break;
            default:
                throw new IllegalStateException(
                    "Unexpected key algorithm." + CompositeSignaturesConstants.ASN1IdentifierCompositeNameMap.get(new ASN1ObjectIdentifier(oid)));
            }
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
}
