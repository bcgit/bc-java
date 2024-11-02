package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

public class CompositeIndex
{
    private static Map<ASN1ObjectIdentifier, String[]> pairings = new HashMap<ASN1ObjectIdentifier, String[]>();
    private static Map<ASN1ObjectIdentifier, AlgorithmParameterSpec[]> kpgInitSpecs = new HashMap<ASN1ObjectIdentifier, AlgorithmParameterSpec[]>();
    private static Map<ASN1ObjectIdentifier, String> classNames = new HashMap<ASN1ObjectIdentifier, String>();
      
    static
    {
        pairings.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, new String[] { "ML-DSA-44", "SHA256withRSAandMGF1"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, new String[] { "ML-DSA-44", "SHA256withRSA"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, new String[] { "ML-DSA-44", "Ed25519"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, new String[] { "ML-DSA-44", "SHA256withECDSA"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256, new String[] { "ML-DSA-65", "SHA256withRSAandMGF1"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256, new String[] { "ML-DSA-65", "SHA256withRSA"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA384, new String[] { "ML-DSA-65", "SHA384withRSAandMGF1"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA384, new String[] { "ML-DSA-65", "SHA384withRSA"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA384, new String[] { "ML-DSA-65", "SHA384withECDSA"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256, new String[] { "ML-DSA-65", "SHA256withECDSA"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, new String[] { "ML-DSA-65", "Ed25519"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384, new String[] { "ML-DSA-87", "SHA384withECDSA"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384, new String[] { "ML-DSA-87", "SHA384withECDSA"});
        pairings.put(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512, new String[] { "ML-DSA-87", "Ed448"});
    
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PSS_SHA256, new String[] { "ML-DSA-44", "SHA256withRSAandMGF1"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PKCS15_SHA256, new String[] { "ML-DSA-44", "SHA256withRSA"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA44_Ed25519_SHA512, new String[] { "ML-DSA-44", "Ed25519"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA44_ECDSA_P256_SHA256, new String[] { "ML-DSA-44", "SHA256withECDSA"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PSS_SHA512, new String[] { "ML-DSA-65", "SHA256withRSAandMGF1"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PKCS15_SHA512, new String[] { "ML-DSA-65", "SHA256withRSA"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PSS_SHA512, new String[] { "ML-DSA-65", "SHA384withRSAandMGF1"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PKCS15_SHA512, new String[] { "ML-DSA-65", "SHA384withRSA"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_P384_SHA512, new String[] { "ML-DSA-65", "SHA384withECDSA"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512, new String[] { "ML-DSA-65", "SHA256withECDSA"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA65_Ed25519_SHA512, new String[] { "ML-DSA-65", "Ed25519"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_P384_SHA512, new String[] { "ML-DSA-87", "SHA384withECDSA"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512, new String[] { "ML-DSA-87", "SHA384withECDSA"});
        pairings.put(MiscObjectIdentifiers.id_HashMLDSA87_Ed448_SHA512, new String[] { "ML-DSA-87", "Ed448"});
        
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, new AlgorithmParameterSpec[] { null, null});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, new AlgorithmParameterSpec[] { null, new ECNamedCurveGenParameterSpec("P-256")});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA384, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA384, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA384, new AlgorithmParameterSpec[] { null, new ECNamedCurveGenParameterSpec("P-384")});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256, new AlgorithmParameterSpec[] { null, new ECNamedCurveGenParameterSpec("brainpoolP256r1")});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, new AlgorithmParameterSpec[] { null, null});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384, new AlgorithmParameterSpec[] { null, new ECNamedCurveGenParameterSpec("P-384")});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384, new AlgorithmParameterSpec[] { null, new ECNamedCurveGenParameterSpec("brainpoolP384r1")});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512, new AlgorithmParameterSpec[] { null, null});
    
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PSS_SHA256, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PKCS15_SHA256, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA44_Ed25519_SHA512, new AlgorithmParameterSpec[] { null, null});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA44_ECDSA_P256_SHA256, new AlgorithmParameterSpec[] { null, new ECNamedCurveGenParameterSpec("P-256")});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PSS_SHA512, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PKCS15_SHA512, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PSS_SHA512, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PKCS15_SHA512, new AlgorithmParameterSpec[] { null, new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_P384_SHA512, new AlgorithmParameterSpec[] { null, new ECNamedCurveGenParameterSpec("P-384")});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512, new AlgorithmParameterSpec[] { null, new ECNamedCurveGenParameterSpec("brainpoolP256r1")});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA65_Ed25519_SHA512, new AlgorithmParameterSpec[] { null, null});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_P384_SHA512, new AlgorithmParameterSpec[] { null, new ECNamedCurveGenParameterSpec("P-384")});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512, new AlgorithmParameterSpec[] { null, new ECNamedCurveGenParameterSpec("brainpoolP384r1")});
        kpgInitSpecs.put(MiscObjectIdentifiers.id_HashMLDSA87_Ed448_SHA512, new AlgorithmParameterSpec[] { null, null});
        
        classNames.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, "MLDSA44_RSA2048_PSS_SHA256");
        classNames.put(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, "MLDSA44_RSA2048_PKCS15_SHA256");
        classNames.put(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, "MLDSA44_Ed25519_SHA512");
        classNames.put(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, "MLDSA44_ECDSA_P256_SHA256");
        classNames.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256, "MLDSA65_RSA3072_PSS_SHA256");
        classNames.put(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256, "MLDSA65_RSA3072_PKCS15_SHA256");
        classNames.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA384, "MLDSA65_RSA4096_PSS_SHA384");
        classNames.put(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA384, "MLDSA65_RSA4096_PKCS15_SHA384");
        classNames.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA384, "MLDSA65_ECDSA_P384_SHA384");
        classNames.put(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256, "MLDSA65_ECDSA_brainpoolP256r1_SHA256");
        classNames.put(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, "MLDSA65_Ed25519_SHA512");
        classNames.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384, "MLDSA87_ECDSA_P384_SHA384");
        classNames.put(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384, "MLDSA87_ECDSA_brainpoolP384r1_SHA384");
        classNames.put(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512, "MLDSA87_Ed448_SHA512");
    
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PSS_SHA256, "HashMLDSA44_RSA2048_PSS_SHA256");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PKCS15_SHA256, "HashMLDSA44_RSA2048_PKCS15_SHA256");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA44_Ed25519_SHA512, "HashMLDSA44_Ed25519_SHA512");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA44_ECDSA_P256_SHA256, "HashMLDSA44_ECDSA_P256_SHA256");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PSS_SHA512, "HashMLDSA65_RSA3072_PSS_SHA512");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PKCS15_SHA512, "HashMLDSA65_RSA3072_PKCS15_SHA512");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PSS_SHA512, "HashMLDSA65_RSA4096_PSS_SHA512");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PKCS15_SHA512, "HashMLDSA65_RSA4096_PKCS15_SHA512");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_P384_SHA512, "HashMLDSA65_ECDSA_P384_SHA512");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512, "HashMLDSA65_ECDSA_brainpoolP256r1_SHA512");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA65_Ed25519_SHA512, "HashMLDSA65_Ed25519_SHA512");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_P384_SHA512, "HashMLDSA87_ECDSA_P384_SHA512");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512, "HashMLDSA87_ECDSA_brainpoolP384r1_SHA512");
        classNames.put(MiscObjectIdentifiers.id_HashMLDSA87_Ed448_SHA512, "HashMLDSA87_Ed448_SHA512");
    }

    public static boolean isAlgorithmSupported(ASN1ObjectIdentifier algorithm)
    {
        return pairings.containsKey(algorithm);
    }

    public static Set<ASN1ObjectIdentifier> getSupportedIdentifiers()
    {
        return pairings.keySet();
    }

    public static String getAlgorithmName(ASN1ObjectIdentifier algorithm)
    {
        return classNames.get(algorithm).replace('_', '-');
    }

    static String[] getPairing(ASN1ObjectIdentifier algorithm)
    {
        return pairings.get(algorithm);
    }

    static AlgorithmParameterSpec[] getKeyPairSpecs(ASN1ObjectIdentifier algorithm)
    {
        return kpgInitSpecs.get(algorithm);
    }

    static String getBaseName(String name)
    {
        if (name.indexOf("RSA") >= 0)
        {
            return "RSA";
        }
        if (name.indexOf("ECDSA") >= 0)
        {
            return "EC";
        }

        return name;
    }
}
