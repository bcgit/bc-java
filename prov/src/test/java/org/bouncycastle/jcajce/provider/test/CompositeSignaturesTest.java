package org.bouncycastle.jcajce.provider.test;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
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
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
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

    /**
     * CompositePublicKey.getEncoded() now normalises an EC component to an uncompressed point, as
     * section 4 of the composite signature draft requires. That is a write-side change only: a
     * composite public key that an earlier release wrote with a compressed EC component - the
     * shorter body assembled by hand here - must still decode, and must still verify a signature
     * made by the matching private key. Re-encoding it yields the normalised (longer) form.
     */
    public void testCompressedECComponentStillDecodes()
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC").generateKeyPair();
        CompositePublicKey pub = (CompositePublicKey)kp.getPublic();

        byte[] mldsaPK = SubjectPublicKeyInfo.getInstance(pub.getPublicKeys().get(0).getEncoded()).getPublicKeyData().getOctets();

        PublicKey ecPub = pub.getPublicKeys().get(1);
        ((ECPointEncoder)ecPub).setPointFormat("COMPRESSED");
        byte[] compressedEC = SubjectPublicKeyInfo.getInstance(ecPub.getEncoded()).getPublicKeyData().getOctets();
        assertEquals("EC component should be a compressed point", 33, compressedEC.length);

        SubjectPublicKeyInfo legacy = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512),
            Arrays.concatenate(mldsaPK, compressedEC));

        PublicKey decoded = KeyFactory.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC")
            .generatePublic(new X509EncodedKeySpec(legacy.getEncoded()));

        Signature signer = Signature.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC");
        signer.initSign(kp.getPrivate());
        signer.update(Strings.toByteArray(messageToBeSigned));
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("MLDSA65-ECDSA-P256-SHA512", "BC");
        verifier.initVerify(decoded);
        verifier.update(Strings.toByteArray(messageToBeSigned));
        assertTrue("a key decoded from a compressed EC component must still verify", verifier.verify(signature));

        // and the key that comes back re-encodes in the normalised form
        assertTrue("re-encoding must produce the uncompressed form",
            Arrays.areEqual(pub.getEncoded(), decoded.getEncoded()));
    }

    /**
     * A truncated composite-signature public key whose body is the raw concatenation form (not a DER SEQUENCE)
     * and is shorter than the first component must surface as a checked IOException from
     * generatePublic(SubjectPublicKeyInfo), not an unchecked NegativeArraySizeException escaping the
     * KeyFactorySpi.split helper. Mirrors the compositekem sibling guard.
     */
    public void testMalformedTruncatedCompositePublicKey()
        throws Exception
    {
        org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi keyFactorySpi =
            new org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi();

        // id_MLDSA44_ECDSA_P256_SHA256 expects a first component of 1312 bytes; supply only 16 raw bytes
        // that do not parse as a DER SEQUENCE, forcing the raw-concatenation split path.
        byte[] truncatedBody = new byte[16];
        SubjectPublicKeyInfo malformed = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256), truncatedBody);

        try
        {
            keyFactorySpi.generatePublic(malformed);
            fail("expected IOException for truncated composite public key");
        }
        catch (java.io.IOException e)
        {
            TestCase.assertEquals("malformed composite public key: body shorter than the first component", e.getMessage());
        }
    }

    /**
     * A composite-signature public key whose body parses as a DER SEQUENCE but whose element count is
     * not exactly two must surface as a checked IOException from generatePublic(SubjectPublicKeyInfo),
     * not an unchecked ArrayIndexOutOfBoundsException (size 1) or IndexOutOfBoundsException (size 3)
     * escaping through the fixed two-element factory list and getKeysSpecs. Mirrors the split() guard
     * exercised by testMalformedTruncatedCompositePublicKey.
     */
    public void testMalformedCompositePublicKeyWrongComponentCount()
        throws Exception
    {
        org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi keyFactorySpi =
            new org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi();

        // A one-element SEQUENCE body: getKeysSpecs would read subjectPublicKeys[1] and previously
        // threw ArrayIndexOutOfBoundsException.
        ASN1EncodableVector oneElement = new ASN1EncodableVector();
        oneElement.add(new DEROctetString(new byte[8]));
        SubjectPublicKeyInfo oneComponent = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256),
            new DERSequence(oneElement).getEncoded());

        try
        {
            keyFactorySpi.generatePublic(oneComponent);
            fail("expected IOException for one-component composite public key");
        }
        catch (java.io.IOException e)
        {
            TestCase.assertEquals("malformed composite public key: expected exactly two components", e.getMessage());
        }

        // A three-element SEQUENCE body: the factories.get(i) loop would read factories.get(2) and
        // previously threw IndexOutOfBoundsException.
        ASN1EncodableVector threeElements = new ASN1EncodableVector();
        threeElements.add(new DEROctetString(new byte[8]));
        threeElements.add(new DEROctetString(new byte[8]));
        threeElements.add(new DEROctetString(new byte[8]));
        SubjectPublicKeyInfo threeComponents = new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256),
            new DERSequence(threeElements).getEncoded());

        try
        {
            keyFactorySpi.generatePublic(threeComponents);
            fail("expected IOException for three-component composite public key");
        }
        catch (java.io.IOException e)
        {
            TestCase.assertEquals("malformed composite public key: expected exactly two components", e.getMessage());
        }
    }

    /**
     * A truncated composite-signature private key whose body is shorter than the 32-byte ML-DSA seed
     * must surface as a checked IOException from generatePrivate(PrivateKeyInfo), not an unchecked
     * IllegalArgumentException ("32 &gt; N") escaping out of Arrays.copyOfRange. Mirrors the compositekem
     * sibling guard and the generatePublic-side split() guard exercised by
     * testMalformedTruncatedCompositePublicKey.
     */
    public void testMalformedTruncatedCompositePrivateKey()
        throws Exception
    {
        org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi keyFactorySpi =
            new org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi();

        // id_MLDSA44_ECDSA_P256_SHA256 expects a 32-byte ML-DSA seed followed by the traditional key;
        // supply only a 16-byte raw octet body, shorter than the seed.
        byte[] truncatedBody = new byte[16];
        PrivateKeyInfo malformed = new PrivateKeyInfo(
            new AlgorithmIdentifier(IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256), new DEROctetString(truncatedBody));

        try
        {
            keyFactorySpi.generatePrivate(malformed);
            fail("expected IOException for truncated composite private key");
        }
        catch (java.io.IOException e)
        {
            TestCase.assertEquals("malformed composite private key: body shorter than the ML-DSA seed", e.getMessage());
        }
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

    public void testKeyBuilders()
        throws Exception
    {
        String[] algorithms = new String[]{
            "MLDSA44-RSA2048-PSS-SHA256",
            "MLDSA44-RSA2048-PKCS15-SHA256",
            "MLDSA44-Ed25519-SHA512",
            "MLDSA44-ECDSA-P256-SHA256",
            "MLDSA65-RSA3072-PSS-SHA512",
            "MLDSA65-RSA3072-PKCS15-SHA512",
            "MLDSA65-RSA4096-PSS-SHA512",
            "MLDSA65-RSA4096-PKCS15-SHA512",
            "MLDSA65-ECDSA-P256-SHA512",
            "MLDSA65-ECDSA-P384-SHA512",
            "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
            "MLDSA65-Ed25519-SHA512",
            "MLDSA87-ECDSA-P384-SHA512",
            "MLDSA87-ECDSA-brainpoolP384R1-SHA512",
            "MLDSA87-Ed448-SHAKE256",
            "MLDSA87-RSA4096-PSS-SHA512",
            "MLDSA87-ECDSA-P521-SHA512",
            "MLDSA87-RSA3072-PSS-SHA512"
        };

        CompositePublicKey.Builder pubBuilder = null;
        CompositePrivateKey.Builder privBuilder = null;

        for (int i = 0; i != algorithms.length; i++)
        {
            pubBuilder = CompositePublicKey.builder(algorithms[i]);
            privBuilder = CompositePrivateKey.builder(algorithms[i]);
        }

        assertNotNull(pubBuilder);
        assertNotNull(privBuilder);
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

    /**
     * A spec that is not one of the composite provider's own but carries a context the way the
     * ML-DSA specs of other providers do, which SpecUtil.getContextFrom picks up reflectively.
     */
    public static class ForeignContextSpec
        implements AlgorithmParameterSpec
    {
        private final byte[] context;

        public ForeignContextSpec(byte[] context)
        {
            this.context = context;
        }

        public byte[] getContext()
        {
            return context;
        }
    }

    /**
     * The context may be set either side of initSign / initVerify, as it may be for the base
     * ML-DSA and SLH-DSA services (github #2396). Setting it first used to let a
     * NullPointerException out of engineSetParameter, which is declared to throw
     * InvalidAlgorithmParameterException, from dereferencing the key that was not there yet -
     * with no key the intent is unknowable, so the null key fell into the signing branch and every
     * one of the composite services failed identically (github #2412).
     */
    public void testSetParameterBeforeInit()
        throws Exception
    {
        String[] algorithms = new String[]
            {
                "MLDSA44-ECDSA-P256-SHA256",
                "MLDSA65-Ed25519-SHA512",
                "MLDSA44-ECDSA-P256-SHA256-PREHASH"
            };

        // the -PREHASH services are handed the digest of the message rather than the message
        String[] preHashDigests = new String[]{ null, null, "SHA256" };

        byte[] context = Strings.toByteArray("Hello, world!");

        for (int i = 0; i != algorithms.length; i++)
        {
            String algorithm = algorithms[i];

            byte[] msg = Strings.toUTF8ByteArray(messageToBeSigned);

            if (preHashDigests[i] != null)
            {
                msg = MessageDigest.getInstance(preHashDigests[i], "BC").digest(msg);
            }

            // only the plain names carry a KeyPairGenerator; the -PREHASH service takes the same key
            String keyAlgorithm = algorithm.endsWith("-PREHASH")
                ? algorithm.substring(0, algorithm.length() - "-PREHASH".length()) : algorithm;

            KeyPair kp = KeyPairGenerator.getInstance(keyAlgorithm, "BC").generateKeyPair();

            Signature before = Signature.getInstance(algorithm, "BC");

            before.setParameter(new ContextParameterSpec(context));
            before.initSign(kp.getPrivate());
            before.update(msg);

            byte[] sigBefore = before.sign();

            Signature verifier = Signature.getInstance(algorithm, "BC");

            verifier.setParameter(new ContextParameterSpec(context));
            verifier.initVerify(kp.getPublic());
            verifier.update(msg);

            assertTrue(algorithm, verifier.verify(sigBefore));

            // the context has to have reached the signer rather than been dropped on the way
            Signature noContext = Signature.getInstance(algorithm, "BC");

            noContext.initVerify(kp.getPublic());
            noContext.update(msg);

            assertFalse(algorithm + ": verified without the context", noContext.verify(sigBefore));

            // and a signature made with the context set afterwards has to verify against it
            Signature after = Signature.getInstance(algorithm, "BC");

            after.initSign(kp.getPrivate());
            after.setParameter(new ContextParameterSpec(context));
            after.update(msg);

            Signature check = Signature.getInstance(algorithm, "BC");

            check.setParameter(new ContextParameterSpec(context));
            check.initVerify(kp.getPublic());
            check.update(msg);

            assertTrue(algorithm + ": context set before init differs from after", check.verify(after.sign()));
        }
    }

    /**
     * The generic COMPOSITE service takes its algorithm from the key, so before initialisation it
     * has neither a key nor a digest - both of the parameter specs it accepts dereferenced one of
     * them.
     */
    public void testSetParameterBeforeInitOnGenericService()
        throws Exception
    {
        byte[] context = Strings.toByteArray("Hello, world!");
        byte[] msg = Strings.toUTF8ByteArray(messageToBeSigned);

        KeyPair kp = KeyPairGenerator.getInstance("MLDSA65-Ed25519-SHA512", "BC").generateKeyPair();

        Signature signer = Signature.getInstance("COMPOSITE", "BC");

        signer.setParameter(new ContextParameterSpec(context));
        signer.initSign(kp.getPrivate());
        signer.update(msg);

        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("COMPOSITE", "BC");

        verifier.setParameter(new ContextParameterSpec(context));
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);

        assertTrue(verifier.verify(sig));

        // the pre-hash choice likewise has to survive until the key names the algorithm
        Signature prehashSigner = Signature.getInstance("COMPOSITE", "BC");

        prehashSigner.setParameter(new CompositeSignatureSpec(true, new ContextParameterSpec(context)));
        prehashSigner.initSign(kp.getPrivate());

        MessageDigest digest = MessageDigest.getInstance("SHA512", "BC");

        prehashSigner.update(digest.digest(msg));

        byte[] prehashSig = prehashSigner.sign();

        Signature prehashVerifier = Signature.getInstance("MLDSA65-Ed25519-SHA512-PREHASH", "BC");

        prehashVerifier.setParameter(new ContextParameterSpec(context));
        prehashVerifier.initVerify(kp.getPublic());
        prehashVerifier.update(digest.digest(msg));

        assertTrue(prehashVerifier.verify(prehashSig));
    }

    /**
     * getParameters() caches the AlgorithmParameters it builds, so a context set after it has been
     * asked for once has to clear that cache rather than go on reporting the previous context.
     */
    public void testGetParametersNotStaleAfterReset()
        throws Exception
    {
        byte[] first = Strings.toByteArray("first context");
        byte[] second = Strings.toByteArray("second context");

        KeyPair kp = KeyPairGenerator.getInstance("MLDSA44-ECDSA-P256-SHA256", "BC").generateKeyPair();

        Signature sig = Signature.getInstance("MLDSA44-ECDSA-P256-SHA256", "BC");

        // init first, so this isolates the cache rather than tripping over the set-before-init path
        sig.initSign(kp.getPrivate());
        sig.setParameter(new ContextParameterSpec(first));

        assertTrue(Arrays.areEqual(first,
            sig.getParameters().getParameterSpec(ContextParameterSpec.class).getContext()));

        sig.setParameter(new ContextParameterSpec(second));

        assertTrue("getParameters() still reported the previous context", Arrays.areEqual(second,
            sig.getParameters().getParameterSpec(ContextParameterSpec.class).getContext()));
    }

    /**
     * A spec carrying a context that is not one of the provider's own is accepted, as it is by the
     * base ML-DSA services. It used to be applied and then reported as rejected by the same call,
     * so a caller that took the exception at its word went on to produce signatures bound to a
     * context it believed had not been set.
     */
    public void testForeignContextSpecAccepted()
        throws Exception
    {
        byte[] context = Strings.toByteArray("Hello, world!");
        byte[] msg = Strings.toUTF8ByteArray(messageToBeSigned);

        KeyPair kp = KeyPairGenerator.getInstance("MLDSA44-ECDSA-P256-SHA256", "BC").generateKeyPair();

        Signature signer = Signature.getInstance("MLDSA44-ECDSA-P256-SHA256", "BC");

        signer.initSign(kp.getPrivate());
        signer.setParameter(new ForeignContextSpec(context));
        signer.update(msg);

        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("MLDSA44-ECDSA-P256-SHA256", "BC");

        verifier.initVerify(kp.getPublic());
        verifier.setParameter(new ContextParameterSpec(context));
        verifier.update(msg);

        assertTrue(verifier.verify(sig));

        // a spec carrying no context at all is still rejected
        Signature unknown = Signature.getInstance("MLDSA44-ECDSA-P256-SHA256", "BC");

        unknown.initSign(kp.getPrivate());

        try
        {
            unknown.setParameter(new ECGenParameterSpec("P-256"));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("unknown parameterSpec passed to composite signature", e.getMessage());
        }
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


    public static List<Map<String, Object>> readTestVectorsFromJson(String homeDire, String fileName)
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
