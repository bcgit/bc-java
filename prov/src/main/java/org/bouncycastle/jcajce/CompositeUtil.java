package org.bouncycastle.jcajce;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.internal.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.util.Strings;

class CompositeUtil
{
    private static final Map<String, ASN1ObjectIdentifier> algorithmOids = new HashMap<String, ASN1ObjectIdentifier>();
    
    static
    {
        algorithmOids.put("MLDSA44-RSA2048-PSS-SHA256", IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256);
        algorithmOids.put("MLDSA44-RSA2048-PKCS15-SHA256", IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256);
        algorithmOids.put("MLDSA44-Ed25519-SHA512", IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512);
        algorithmOids.put("MLDSA44-ECDSA-P256-SHA256", IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256);
        algorithmOids.put("MLDSA65-RSA3072-PSS-SHA512", IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512);
        algorithmOids.put("MLDSA65-RSA3072-PKCS15-SHA512", IANAObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512);
        algorithmOids.put("MLDSA65-RSA4096-PSS-SHA512", IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512);
        algorithmOids.put("MLDSA65-RSA4096-PKCS15-SHA512", IANAObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512);
        algorithmOids.put("MLDSA65-ECDSA-P256-SHA512", IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512);
        algorithmOids.put("MLDSA65-ECDSA-P384-SHA512", IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512);
        algorithmOids.put("MLDSA65-ECDSA-brainpoolP256r1-SHA512", IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512);
        algorithmOids.put("MLDSA65-Ed25519-SHA512", IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512);
        algorithmOids.put("MLDSA87-ECDSA-P384-SHA512", IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512);
        algorithmOids.put("MLDSA87-ECDSA-brainpoolP384r1-SHA512", IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512);
        algorithmOids.put("MLDSA87-Ed448-SHAKE256", IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256);
        algorithmOids.put("MLDSA87-RSA4096-PSS-SHA512", IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512);
        algorithmOids.put("MLDSA87-ECDSA-P521-SHA512", IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512);
        algorithmOids.put("MLDSA87-RSA3072-PSS-SHA512", IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512);
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
