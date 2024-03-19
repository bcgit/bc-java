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



    /**
     *   -- ISO/IEC 18033-2 arc

        is18033-2 OID ::= { iso(1) standard(0) is18033(18033) part2(2) }
     */
    ASN1ObjectIdentifier is18033_2 = new ASN1ObjectIdentifier("1.0.18033.2");

    ASN1ObjectIdentifier id_ac_generic_hybrid = is18033_2.branch("1.2");

    /**
    id-kem-rsa OID ::= {
       is18033-2 key-encapsulation-mechanism(2) rsa(4)
    }
     */
    ASN1ObjectIdentifier id_kem_rsa = is18033_2.branch("2.4");
}
