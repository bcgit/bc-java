package org.bouncycastle.jcajce.provider.asymmetric.compositesignatures;

import java.util.HashMap;
import java.util.Map.Entry;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;


/**
 * Helper class containing constants/mappings for composite signatures.
 */
public abstract class CompositeSignaturesConstants
{

    /**
     * An array of supported identifiers of composite signature schemes.
     */
    public static final ASN1ObjectIdentifier[] supportedIdentifiers = {
        MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256,
        MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256,
        MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512,
        MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256,
        MiscObjectIdentifiers.id_MLDSA44_ECDSA_brainpoolP256r1_SHA256,
        MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512,
        MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512,
        MiscObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512,
        MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512,
        MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512,
        MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512,
        MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512,
        MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512,
        MiscObjectIdentifiers.id_Falcon512_ECDSA_P256_SHA256,
        MiscObjectIdentifiers.id_Falcon512_ECDSA_brainpoolP256r1_SHA256,
        MiscObjectIdentifiers.id_Falcon512_Ed25519_SHA512,
    };

    /**
     * Enum of supported composited signature schemes. Each one corresponds to a value from supportedIdentifiers.
     */
    public enum CompositeName
    {
        MLDSA44_RSA2048_PSS_SHA256("MLDSA44-RSA2048-PSS-SHA256"),
        MLDSA44_RSA2048_PKCS15_SHA256("MLDSA44-RSA2048-PKCS15-SHA256"),
        MLDSA44_Ed25519_SHA512("MLDSA44-Ed25519-SHA512"),
        MLDSA44_ECDSA_P256_SHA256("MLDSA44-ECDSA-P256-SHA256"),
        MLDSA44_ECDSA_brainpoolP256r1_SHA256("MLDSA44-ECDSA-brainpoolP256r1-SHA256"),
        MLDSA65_RSA3072_PSS_SHA512("MLDSA65-RSA3072-PSS-SHA512"),
        MLDSA65_RSA3072_PKCS15_SHA512("MLDSA65-RSA3072-PKCS15-SHA512"),
        MLDSA65_ECDSA_brainpoolP256r1_SHA512("MLDSA65-ECDSA-brainpoolP256r1-SHA512"),
        MLDSA65_ECDSA_P256_SHA512("MLDSA65-ECDSA-P256-SHA512"),
        MLDSA65_Ed25519_SHA512("MLDSA65-Ed25519-SHA512"),
        MLDSA87_ECDSA_P384_SHA512("MLDSA87-ECDSA-P384-SHA512"),
        MLDSA87_ECDSA_brainpoolP384r1_SHA512("MLDSA87-ECDSA-brainpoolP384r1-SHA512"),
        MLDSA87_Ed448_SHA512("MLDSA87-Ed448-SHA512"),
        Falcon512_ECDSA_P256_SHA256("Falcon512-ECDSA-P256-SHA256"),
        Falcon512_ECDSA_brainpoolP256r1_SHA256("Falcon512-ECDSA-brainpoolP256r1-SHA256"),
        Falcon512_Ed25519_SHA512("Falcon512-Ed25519-SHA512");

        private final String id;

        private CompositeName(String id)
        {
            this.id = id;
        }

        public String getId()
        {
            return id;
        }
    }

    /**
     * Map from CompositeName enum to ASN1 identifier.
     */
    public static final HashMap<CompositeName, ASN1ObjectIdentifier> compositeNameASN1IdentifierMap;

    static
    {
        compositeNameASN1IdentifierMap = new HashMap<CompositeName, ASN1ObjectIdentifier>();
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA44_RSA2048_PSS_SHA256, MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA44_RSA2048_PKCS15_SHA256, MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA44_ECDSA_P256_SHA256, MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA44_ECDSA_brainpoolP256r1_SHA256, MiscObjectIdentifiers.id_MLDSA44_ECDSA_brainpoolP256r1_SHA256);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA44_Ed25519_SHA512, MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA65_RSA3072_PSS_SHA512, MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA65_RSA3072_PKCS15_SHA512, MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA65_ECDSA_P256_SHA512, MiscObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA65_ECDSA_brainpoolP256r1_SHA512, MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA65_Ed25519_SHA512, MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA87_ECDSA_P384_SHA512, MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA87_ECDSA_brainpoolP384r1_SHA512, MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512);
        compositeNameASN1IdentifierMap.put(CompositeName.MLDSA87_Ed448_SHA512, MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512);
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
        ASN1IdentifierCompositeNameMap = new HashMap<ASN1ObjectIdentifier, CompositeName>();
        for (Entry<CompositeName, ASN1ObjectIdentifier> entry : compositeNameASN1IdentifierMap.entrySet())
        {
            ASN1IdentifierCompositeNameMap.put(entry.getValue(), entry.getKey());
        }
    }

    /**
     * Map from ASN1 identifier to a readable string used as the composite signature name for the JCA/JCE API.
     */
    public static final HashMap<ASN1ObjectIdentifier, CompositeName> ASN1IdentifierAlgorithmNameMap;

    static
    {
        ASN1IdentifierAlgorithmNameMap = new HashMap<ASN1ObjectIdentifier, CompositeName>();
        for (ASN1ObjectIdentifier oid : supportedIdentifiers)
        {
            CompositeName algName = ASN1IdentifierCompositeNameMap.get(oid); //Get enum so we can get name() value.
            ASN1IdentifierAlgorithmNameMap.put(oid, algName);
        }
    }

    private CompositeSignaturesConstants()
    {

    }
}
