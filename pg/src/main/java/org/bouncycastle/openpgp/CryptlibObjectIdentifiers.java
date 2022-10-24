package org.bouncycastle.openpgp;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

// temporary fix for 172.1 due to module export lacking in provider.
class CryptlibObjectIdentifiers
{
    public static final ASN1ObjectIdentifier cryptlib = new ASN1ObjectIdentifier("1.3.6.1.4.1.3029");

    public static final ASN1ObjectIdentifier ecc = cryptlib.branch("1").branch("5");

    public static final ASN1ObjectIdentifier curvey25519 = ecc.branch("1");
}
