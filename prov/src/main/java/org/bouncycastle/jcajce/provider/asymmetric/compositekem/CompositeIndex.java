package org.bouncycastle.jcajce.provider.asymmetric.compositekem;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Registry of the Composite ML-KEM parameter sets from
 * <a href="https://lamps-wg.github.io/draft-composite-kem/draft-ietf-lamps-pq-composite-kem.html">
 *     Composite ML-KEM for use in X.509 Public Key Infrastructure</a>. For each composite OID it holds
 * the component algorithm pair, the human-readable algorithm name, and the KEM combiner domain
 * separator ("Label") used in section 3.4.
 */
public class CompositeIndex
{
    private static final Map<ASN1ObjectIdentifier, String[]> pairings = new HashMap<ASN1ObjectIdentifier, String[]>();
    private static final Map<ASN1ObjectIdentifier, String> algorithmNames = new HashMap<ASN1ObjectIdentifier, String>();
    private static final Map<ASN1ObjectIdentifier, byte[]> kemLabels = new HashMap<ASN1ObjectIdentifier, byte[]>();
    private static final Map<ASN1ObjectIdentifier, AlgorithmParameterSpec[]> kpgInitSpecs = new HashMap<ASN1ObjectIdentifier, AlgorithmParameterSpec[]>();

    static
    {
        // ML-KEM-768 + RSA-OAEP
        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256,
            "MLKEM768-RSA2048-SHA3-256",
            Strings.toByteArray("MLKEM768-RSAOAEP2048"),
            new String[]{"ML-KEM-768", "RSA"}
        );

        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM768_RSA3072_SHA3_256,
            "MLKEM768-RSA3072-SHA3-256",
            Strings.toByteArray("MLKEM768-RSAOAEP3072"),
            new String[]{"ML-KEM-768", "RSA"}
        );

        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM768_RSA4096_SHA3_256,
            "MLKEM768-RSA4096-SHA3-256",
            Strings.toByteArray("MLKEM768-RSAOAEP4096"),
            new String[]{"ML-KEM-768", "RSA"}
        );

        // ML-KEM-768 + X25519 - the label is the ASCII string "\.//^\" expressed as hex to avoid
        // escaping issues in the draft (section 6).
        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM768_X25519_SHA3_256,
            "MLKEM768-X25519-SHA3-256",
            Hex.decode("5c2e2f2f5e5c"),
            new String[]{"ML-KEM-768", "X25519"}
        );

        // ML-KEM-768 + ECDH
        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256,
            "MLKEM768-ECDH-P256-SHA3-256",
            Strings.toByteArray("MLKEM768-P256"),
            new String[]{"ML-KEM-768", "EC"}
        );

        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256,
            "MLKEM768-ECDH-P384-SHA3-256",
            Strings.toByteArray("MLKEM768-P384"),
            new String[]{"ML-KEM-768", "EC"}
        );

        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM768_ECDH_BP256_SHA3_256,
            "MLKEM768-ECDH-BP256-SHA3-256",
            Strings.toByteArray("MLKEM768-BP256"),
            new String[]{"ML-KEM-768", "EC"}
        );

        // ML-KEM-1024 + RSA-OAEP
        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM1024_RSA3072_SHA3_256,
            "MLKEM1024-RSA3072-SHA3-256",
            Strings.toByteArray("MLKEM1024-RSAOAEP3072"),
            new String[]{"ML-KEM-1024", "RSA"}
        );

        // ML-KEM-1024 + ECDH
        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256,
            "MLKEM1024-ECDH-P384-SHA3-256",
            Strings.toByteArray("MLKEM1024-P384"),
            new String[]{"ML-KEM-1024", "EC"}
        );

        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM1024_ECDH_BP384_SHA3_256,
            "MLKEM1024-ECDH-BP384-SHA3-256",
            Strings.toByteArray("MLKEM1024-BP384"),
            new String[]{"ML-KEM-1024", "EC"}
        );

        // ML-KEM-1024 + X448
        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM1024_X448_SHA3_256,
            "MLKEM1024-X448-SHA3-256",
            Strings.toByteArray("MLKEM1024-X448"),
            new String[]{"ML-KEM-1024", "X448"}
        );

        registerKEMAlgorithm(
            IANAObjectIdentifiers.id_MLKEM1024_ECDH_P521_SHA3_256,
            "MLKEM1024-ECDH-P521-SHA3-256",
            Strings.toByteArray("MLKEM1024-P521"),
            new String[]{"ML-KEM-1024", "EC"}
        );

        // Per-component KeyPairGenerator init specs (in pairing order: ML-KEM first, traditional
        // second). The ML-KEM component is generated through its parameter-set-specific
        // KeyPairGenerator name ("ML-KEM-768" / "ML-KEM-1024") so it needs no spec.
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256, new AlgorithmParameterSpec[]{null, new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_RSA3072_SHA3_256, new AlgorithmParameterSpec[]{null, new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_RSA4096_SHA3_256, new AlgorithmParameterSpec[]{null, new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_X25519_SHA3_256, new AlgorithmParameterSpec[]{null, null});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256, new AlgorithmParameterSpec[]{null, new ECNamedCurveGenParameterSpec("P-256")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256, new AlgorithmParameterSpec[]{null, new ECNamedCurveGenParameterSpec("P-384")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_BP256_SHA3_256, new AlgorithmParameterSpec[]{null, new ECNamedCurveGenParameterSpec("brainpoolP256r1")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM1024_RSA3072_SHA3_256, new AlgorithmParameterSpec[]{null, new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256, new AlgorithmParameterSpec[]{null, new ECNamedCurveGenParameterSpec("P-384")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_BP384_SHA3_256, new AlgorithmParameterSpec[]{null, new ECNamedCurveGenParameterSpec("brainpoolP384r1")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM1024_X448_SHA3_256, new AlgorithmParameterSpec[]{null, null});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P521_SHA3_256, new AlgorithmParameterSpec[]{null, new ECNamedCurveGenParameterSpec("P-521")});
    }

    /**
     * Per-component {@link AlgorithmParameterSpec}s used to initialise the component
     * KeyPairGenerators, in pairing order. An entry may be {@code null} when the component's
     * KeyPairGenerator name already fixes the parameter set (ML-KEM, X25519, X448).
     */
    public static AlgorithmParameterSpec[] getKeyPairSpecs(ASN1ObjectIdentifier algorithm)
    {
        return kpgInitSpecs.get(algorithm);
    }

    public static Set<ASN1ObjectIdentifier> getSupportedIdentifiers()
    {
        return pairings.keySet();
    }

    public static String getAlgorithmName(ASN1ObjectIdentifier algorithm)
    {
        return algorithmNames.get(algorithm);
    }

    public static String[] getPairing(ASN1ObjectIdentifier algorithm)
    {
        return pairings.get(algorithm);
    }

    private static void registerKEMAlgorithm(ASN1ObjectIdentifier oid, String algorithmName,
                                             byte[] label, String[] pairing)
    {
        pairings.put(oid, pairing);
        algorithmNames.put(oid, algorithmName);
        kemLabels.put(oid, label);
    }

    /**
     * Check if OID is a Composite KEM OID.
     */
    public static boolean isCompositeKEMOID(ASN1ObjectIdentifier oid)
    {
        return pairings.containsKey(oid);
    }

    /**
     * Get the KEM combiner domain separator ("Label") for a Composite KEM OID (section 3.4 / section 6).
     */
    public static byte[] getKEMLabel(ASN1ObjectIdentifier oid)
    {
        byte[] label = kemLabels.get(oid);
        if (label == null)
        {
            throw new IllegalArgumentException("Unknown Composite KEM OID: " + oid);
        }
        return label.clone(); // Return copy for safety
    }

    /**
     * Get the traditional algorithm component name for a Composite KEM OID.
     */
    public static String getTraditionalAlgorithmName(ASN1ObjectIdentifier oid)
    {
        String compositeName = getAlgorithmName(oid);
        if (compositeName == null)
        {
            return null;
        }

        if (compositeName.contains("RSA"))
        {
            return "RSA";
        }
        else if (compositeName.contains("ECDH"))
        {
            return "ECDH";
        }
        else if (compositeName.contains("X25519"))
        {
            return "X25519";
        }
        else if (compositeName.contains("X448"))
        {
            return "X448";
        }

        return null;
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
