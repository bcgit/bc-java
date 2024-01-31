package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;

import java.util.HashMap;
import java.util.Map.Entry;


/**
 * Helper class containing constants/mappings for composite signatures.
 */
public abstract class CompositeSignaturesConstants
{

    /**
     * An array of supported identifiers of composite signature schemes.
     */
    public static final ASN1ObjectIdentifier[] supportedIdentifiers = {MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256, MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256, MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512, MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256, MiscObjectIdentifiers.id_MLDSA44_ECDSA_brainpoolP256r1_SHA256, MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256, MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256, MiscObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA256, MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256, MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512, MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384, MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384, MiscObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256, MiscObjectIdentifiers.id_Falcon512_ECDSA_P256_SHA256, MiscObjectIdentifiers.id_Falcon512_ECDSA_brainpoolP256r1_SHA256, MiscObjectIdentifiers.id_Falcon512_Ed25519_SHA512,};

    /**
     * Enum of supported composited signature schemes. Each one corresponds to a value from supportedIdentifiers.
     */
    public enum CompositeName
    {
        MLDSA44_RSA2048_PSS_SHA256, MLDSA44_RSA2048_PKCS15_SHA256, MLDSA44_ECDSA_P256_SHA256, MLDSA44_ECDSA_brainpoolP256r1_SHA256, MLDSA44_Ed25519_SHA512, MLDSA65_RSA3072_PSS_SHA256, MLDSA65_RSA3072_PKCS15_SHA256, MLDSA65_ECDSA_brainpoolP256r1_SHA256, MLDSA65_ECDSA_P256_SHA256, MLDSA65_Ed25519_SHA512, MLDSA87_ECDSA_P384_SHA384, MLDSA87_ECDSA_brainpoolP384r1_SHA384, MLDSA87_Ed448_SHAKE256, Falcon512_ECDSA_P256_SHA256, Falcon512_ECDSA_brainpoolP256r1_SHA256, Falcon512_Ed25519_SHA512,
    }

    /**
     * Map from CompositeName enum to ASN1 identifier.
     */
    public static final HashMap<CompositeName, ASN1ObjectIdentifier> compositeNameASN1IdentifierMap;

    static
    {
        compositeNameASN1IdentifierMap = new HashMap<>();
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA44_RSA2048_PSS_SHA256, MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA44_RSA2048_PKCS15_SHA256, MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA44_ECDSA_P256_SHA256, MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA44_ECDSA_brainpoolP256r1_SHA256, MiscObjectIdentifiers.id_MLDSA44_ECDSA_brainpoolP256r1_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA44_Ed25519_SHA512, MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA65_RSA3072_PSS_SHA256, MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA65_RSA3072_PKCS15_SHA256, MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA65_ECDSA_P256_SHA256, MiscObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA65_ECDSA_brainpoolP256r1_SHA256, MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA65_Ed25519_SHA512, MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA87_ECDSA_P384_SHA384, MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA87_ECDSA_brainpoolP384r1_SHA384, MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA87_Ed448_SHAKE256, MiscObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256);
        compositeNameASN1IdentifierMap.put(CompositeName.Falcon512_ECDSA_P256_SHA256, MiscObjectIdentifiers.id_Falcon512_ECDSA_P256_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.Falcon512_ECDSA_brainpoolP256r1_SHA256, MiscObjectIdentifiers.id_Falcon512_ECDSA_brainpoolP256r1_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.Falcon512_Ed25519_SHA512, MiscObjectIdentifiers.id_Falcon512_Ed25519_SHA512);
    }

    /**
     * Reverse map of compositeNameASN1IdentifierMap.
     */
    public static final HashMap<ASN1ObjectIdentifier, CompositeName> ASN1IdentifierCompositeNameMap;

    static
    {
        ASN1IdentifierCompositeNameMap = new HashMap<>();
        for (Entry<CompositeName, ASN1ObjectIdentifier> entry : compositeNameASN1IdentifierMap.entrySet())
        {
            ASN1IdentifierCompositeNameMap.put(entry.getValue(), entry.getKey());
        }
    }

    /**
     * Map from CompositeName to OID name from https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-sigs-10.html.
     * CompositeName enum value is converted to string, prefixed with "id-" and "_" replaced with "-".
     * These strings are used in the signing/verification process as a prefix for the message.
     */
    public static final HashMap<CompositeName, String> compositeNameOIDStringMap;

    static
    {
        compositeNameOIDStringMap = new HashMap<>();

        for (CompositeName algName : CompositeName.values())
        {
            compositeNameOIDStringMap.put(algName, "id-" + algName.name().replace("_", "-"));
        }
    }

    /**
     * Map from ASN1 identifier to a readable string used as the composite signature name for the JCA/JCE API.
     */
    public static final HashMap<ASN1ObjectIdentifier, String> ASN1IdentifierAlgorithmNameMap;

    static
    {
        ASN1IdentifierAlgorithmNameMap = new HashMap<>();
        for (ASN1ObjectIdentifier oid : supportedIdentifiers)
        {
            String algNameFromEnum = ASN1IdentifierCompositeNameMap.get(oid).name(); //Get enum so we can get name() value.
            String[] parts = algNameFromEnum.split("_");
            String algName = null;
            if (parts.length < 4)
            { //no 2nd "param", e.g., in the case of Ed25519, 3rd hash function is ignored
                algName = parts[0] + "and" + parts[1]; // e.g., MLDSA44_Ed25519_SHA512 => MLDSA44andEd25519
            }
            else
            {
                algName = parts[0] + "and" + parts[1] + parts[2]; // e.g., MLDSA44_RSA2048_PSS_SHA256 => MLDSA44andRSA2048PSS
            }
            ASN1IdentifierAlgorithmNameMap.put(oid, algName);
        }
    }

    private CompositeSignaturesConstants()
    {

    }
}
