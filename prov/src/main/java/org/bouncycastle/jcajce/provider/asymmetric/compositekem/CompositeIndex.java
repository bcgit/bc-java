package org.bouncycastle.jcajce.provider.asymmetric.compositekem;

import java.security.Key;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.util.Integers;
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
    private static final Map<ASN1ObjectIdentifier, String[]> algorithmAliases = new HashMap<ASN1ObjectIdentifier, String[]>();
    private static final Map<ASN1ObjectIdentifier, Integer> rsaKeySizes = new HashMap<ASN1ObjectIdentifier, Integer>();

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
            IANAObjectIdentifiers.id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256,
            "MLKEM768-ECDH-brainpoolP256r1-SHA3-256",
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
            IANAObjectIdentifiers.id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256,
            "MLKEM1024-ECDH-brainpoolP384r1-SHA3-256",
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

        // The two brainpool sets were originally registered with the curve abbreviated to BP256 /
        // BP384; those names are kept as aliases of the draft's spelling.
        algorithmAliases.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256, new String[]{"MLKEM768-ECDH-BP256-SHA3-256"});
        algorithmAliases.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256, new String[]{"MLKEM1024-ECDH-BP384-SHA3-256"});

        // The RSA modulus size, in bits, each RSA composite fixes (section 6.1).
        rsaKeySizes.put(IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256, Integers.valueOf(2048));
        rsaKeySizes.put(IANAObjectIdentifiers.id_MLKEM768_RSA3072_SHA3_256, Integers.valueOf(3072));
        rsaKeySizes.put(IANAObjectIdentifiers.id_MLKEM768_RSA4096_SHA3_256, Integers.valueOf(4096));
        rsaKeySizes.put(IANAObjectIdentifiers.id_MLKEM1024_RSA3072_SHA3_256, Integers.valueOf(3072));

        // Per-component KeyPairGenerator init specs, in pairing order: ML-KEM first, traditional
        // second. Every component carries one, including those whose parameter set the component's
        // KeyPairGenerator name already fixes (ML-KEM, X25519, X448), because initialize(null, random)
        // can only reach a component through a spec - a null slot silently drops the caller's random.
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_768, new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_RSA3072_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_768, new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_RSA4096_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_768, new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_X25519_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_768, new XDHParameterSpec(XDHParameterSpec.X25519)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_768, new ECNamedCurveGenParameterSpec("P-256")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_768, new ECNamedCurveGenParameterSpec("P-384")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM768_ECDH_brainpoolP256r1_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_768, new ECNamedCurveGenParameterSpec("brainpoolP256r1")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM1024_RSA3072_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_1024, new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_1024, new ECNamedCurveGenParameterSpec("P-384")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_brainpoolP384r1_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_1024, new ECNamedCurveGenParameterSpec("brainpoolP384r1")});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM1024_X448_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_1024, new XDHParameterSpec(XDHParameterSpec.X448)});
        kpgInitSpecs.put(IANAObjectIdentifiers.id_MLKEM1024_ECDH_P521_SHA3_256, new AlgorithmParameterSpec[]{MLKEMParameterSpec.ml_kem_1024, new ECNamedCurveGenParameterSpec("P-521")});
    }

    /**
     * Per-component {@link AlgorithmParameterSpec}s used to initialise the component
     * KeyPairGenerators, in pairing order. Every entry is non-null: the specs are also the only route
     * a caller-supplied SecureRandom has to a component generator.
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

    /**
     * Additional names a composite KEM algorithm is registered under, beyond the one
     * {@link #getAlgorithmName} returns. Empty for every parameter set that has only one name.
     */
    public static String[] getAlgorithmAliases(ASN1ObjectIdentifier algorithm)
    {
        String[] aliases = algorithmAliases.get(algorithm);

        return (aliases != null) ? aliases : new String[0];
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

        if (compositeName.indexOf("RSA") >= 0)
        {
            return "RSA";
        }
        else if (compositeName.indexOf("ECDH") >= 0)
        {
            return "ECDH";
        }
        else if (compositeName.indexOf("X25519") >= 0)
        {
            return "X25519";
        }
        else if (compositeName.indexOf("X448") >= 0)
        {
            return "X448";
        }

        return null;
    }

    /**
     * The RSA modulus size in bits that a Composite KEM OID fixes for its traditional component
     * (section 6.1 of draft-ietf-lamps-pq-composite-kem), or -1 if the traditional component is not RSA.
     */
    public static int getRSAKeySize(ASN1ObjectIdentifier oid)
    {
        Integer keySize = rsaKeySizes.get(oid);

        return (keySize != null) ? keySize.intValue() : -1;
    }

    /**
     * Checks that the traditional component of a composite key is acceptable for the Composite KEM
     * OID it is used under: section 6.1 of draft-ietf-lamps-pq-composite-kem fixes the modulus size
     * of an RSA component, and section 3.3 requires it to be checked.
     *
     * @return null if the component is acceptable, otherwise a message describing why it is not.
     */
    static String checkTraditionalKey(ASN1ObjectIdentifier oid, Key tradKey)
    {
        int keySize = getRSAKeySize(oid);

        if (keySize > 0)
        {
            if (!(tradKey instanceof RSAKey))
            {
                return "RSA component is not an RSA key";
            }
            if (((RSAKey)tradKey).getModulus().bitLength() != keySize)
            {
                return "RSA component must be a " + keySize + "-bit key";
            }
        }

        return null;
    }

    /**
     * Maps a component algorithm name to the KeyFactory / KeyPairGenerator name it is reached by.
     * Only the RSA components need translating; the pairings already name "EC", "X25519" and "X448"
     * as the provider registers them, and "ML-KEM-768" / "ML-KEM-1024" are service names in their
     * own right.
     */
    static String getBaseName(String name)
    {
        if (name.indexOf("RSA") >= 0)
        {
            return "RSA";
        }

        return name;
    }
}
