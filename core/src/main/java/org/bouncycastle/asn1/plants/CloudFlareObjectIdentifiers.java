package org.bouncycastle.asn1.plants;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface CloudFlareObjectIdentifiers
{
    ASN1ObjectIdentifier cloudFlare = new ASN1ObjectIdentifier("1.3.6.1.4.1.44363");

    ASN1ObjectIdentifier id_alg_mtcProof =cloudFlare.branch("47.0");
}
