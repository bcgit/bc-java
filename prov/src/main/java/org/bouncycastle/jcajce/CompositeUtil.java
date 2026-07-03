package org.bouncycastle.jcajce;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.util.Strings;

class CompositeUtil
{
    private static final Map<String, ASN1ObjectIdentifier> algorithmOids = new HashMap<String, ASN1ObjectIdentifier>();
    
    static
    {
        algorithmOids.put("MLDSA44-RSA2048-PSS-SHA256", IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256);
        algorithmOids.put("MLDSA44-RSA2048-PKCS15-SHA256", IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256);
        algorithmOids.put("MLDSA44-ED25519-SHA512", IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512);
        algorithmOids.put("MLDSA44-ECDSA-P256-SHA256", IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256);
        algorithmOids.put("MLDSA65-RSA3072-PSS-SHA512", IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512);
        algorithmOids.put("MLDSA65-RSA3072-PKCS15-SHA512", IANAObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512);
        algorithmOids.put("MLDSA65-RSA4096-PSS-SHA512", IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512);
        algorithmOids.put("MLDSA65-RSA4096-PKCS15-SHA512", IANAObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512);
        algorithmOids.put("MLDSA65-ECDSA-P256-SHA512", IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512);
        algorithmOids.put("MLDSA65-ECDSA-P384-SHA512", IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512);
        algorithmOids.put("MLDSA65-ECDSA-BRAINPOOLP256R1-SHA512", IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512);
        algorithmOids.put("MLDSA65-ED25519-SHA512", IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512);
        algorithmOids.put("MLDSA87-ECDSA-P384-SHA512", IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512);
        algorithmOids.put("MLDSA87-ECDSA-BRAINPOOLP384R1-SHA512", IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512);
        algorithmOids.put("MLDSA87-ED448-SHAKE256", IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256);
        algorithmOids.put("MLDSA87-RSA4096-PSS-SHA512", IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512);
        algorithmOids.put("MLDSA87-ECDSA-P521-SHA512", IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512);
        algorithmOids.put("MLDSA87-RSA3072-PSS-SHA512", IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512);

        // Composite ML-KEM (draft-ietf-lamps-pq-composite-kem) names, so builder(String) resolves
        // them the same way it does the composite signature names above.
        algorithmOids.put("MLKEM768-RSA2048-SHA3-256", IANAObjectIdentifiers.id_MLKEM768_RSA2048_SHA3_256);
        algorithmOids.put("MLKEM768-RSA3072-SHA3-256", IANAObjectIdentifiers.id_MLKEM768_RSA3072_SHA3_256);
        algorithmOids.put("MLKEM768-RSA4096-SHA3-256", IANAObjectIdentifiers.id_MLKEM768_RSA4096_SHA3_256);
        algorithmOids.put("MLKEM768-X25519-SHA3-256", IANAObjectIdentifiers.id_MLKEM768_X25519_SHA3_256);
        algorithmOids.put("MLKEM768-ECDH-P256-SHA3-256", IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256);
        algorithmOids.put("MLKEM768-ECDH-P384-SHA3-256", IANAObjectIdentifiers.id_MLKEM768_ECDH_P384_SHA3_256);
        algorithmOids.put("MLKEM768-ECDH-BP256-SHA3-256", IANAObjectIdentifiers.id_MLKEM768_ECDH_BP256_SHA3_256);
        algorithmOids.put("MLKEM1024-RSA3072-SHA3-256", IANAObjectIdentifiers.id_MLKEM1024_RSA3072_SHA3_256);
        algorithmOids.put("MLKEM1024-ECDH-P384-SHA3-256", IANAObjectIdentifiers.id_MLKEM1024_ECDH_P384_SHA3_256);
        algorithmOids.put("MLKEM1024-ECDH-BP384-SHA3-256", IANAObjectIdentifiers.id_MLKEM1024_ECDH_BP384_SHA3_256);
        algorithmOids.put("MLKEM1024-X448-SHA3-256", IANAObjectIdentifiers.id_MLKEM1024_X448_SHA3_256);
        algorithmOids.put("MLKEM1024-ECDH-P521-SHA3-256", IANAObjectIdentifiers.id_MLKEM1024_ECDH_P521_SHA3_256);
    }

    static ASN1ObjectIdentifier getOid(String name)
    {
        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)algorithmOids.get(Strings.toUpperCase(name));
        if (oid == null)
        {
            throw new IllegalArgumentException("name " + name + " not recognized");
        }

        return oid;
    }
}
