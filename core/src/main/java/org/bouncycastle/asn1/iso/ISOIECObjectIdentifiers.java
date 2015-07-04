package org.bouncycastle.asn1.iso;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * OIDS from  ISO/IEC 10118-3:2004
 */
public interface ISOIECObjectIdentifiers
{
    ASN1ObjectIdentifier iso_encryption_algorithms = new ASN1ObjectIdentifier("1.0.10118");

    ASN1ObjectIdentifier hash_algorithms = iso_encryption_algorithms.branch("3.0");

    ASN1ObjectIdentifier ripemd160 = hash_algorithms.branch("49");
    ASN1ObjectIdentifier ripemd128 = hash_algorithms.branch("50");
    ASN1ObjectIdentifier whirlpool = hash_algorithms.branch("55");
}
