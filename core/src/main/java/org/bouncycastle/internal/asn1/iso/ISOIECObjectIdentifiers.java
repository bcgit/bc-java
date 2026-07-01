package org.bouncycastle.internal.asn1.iso;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * OIDS from  ISO/IEC 10118-3:2004 and ISO/IEC 18033-2:2006/Amd 2:2026
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
     *   id-kem OID ::= { is18033-2 key-encapsulation-mechanism(2) }
     *
     *   The other KEMs registered under the id-kem arc by ISO/IEC 18033-2 Annex A
     */
    ASN1ObjectIdentifier id_kem = is18033_2.branch("2");
    ASN1ObjectIdentifier id_kem_ecies = id_kem.branch("1");
    ASN1ObjectIdentifier id_kem_psec = id_kem.branch("2");
    ASN1ObjectIdentifier id_kem_ace = id_kem.branch("3");
    ASN1ObjectIdentifier id_kem_rsa = id_kem.branch("4");
    ASN1ObjectIdentifier id_kem_face = id_kem.branch("5");

    /**
     *   -- Classic McEliece (ISO/IEC 18033-2:2006/Amd 2:2026, Clause 13)
     *   id-kem-cm OID ::= { id-kem cm(6) }
     */
    ASN1ObjectIdentifier id_kem_cm = id_kem.branch("6");

    ASN1ObjectIdentifier mceliece460896 = id_kem_cm.branch("1");
    ASN1ObjectIdentifier mceliece460896f = id_kem_cm.branch("2");
    ASN1ObjectIdentifier mceliece460896pc = id_kem_cm.branch("3");
    ASN1ObjectIdentifier mceliece460896pcf = id_kem_cm.branch("4");
    ASN1ObjectIdentifier mceliece6688128 = id_kem_cm.branch("5");
    ASN1ObjectIdentifier mceliece6688128f = id_kem_cm.branch("6");
    ASN1ObjectIdentifier mceliece6688128pc = id_kem_cm.branch("7");
    ASN1ObjectIdentifier mceliece6688128pcf = id_kem_cm.branch("8");
    ASN1ObjectIdentifier mceliece6960119 = id_kem_cm.branch("9");
    ASN1ObjectIdentifier mceliece6960119f = id_kem_cm.branch("10");
    ASN1ObjectIdentifier mceliece6960119pc = id_kem_cm.branch("11");
    ASN1ObjectIdentifier mceliece6960119pcf = id_kem_cm.branch("12");
    ASN1ObjectIdentifier mceliece8192128 = id_kem_cm.branch("13");
    ASN1ObjectIdentifier mceliece8192128f = id_kem_cm.branch("14");
    ASN1ObjectIdentifier mceliece8192128pc = id_kem_cm.branch("15");
    ASN1ObjectIdentifier mceliece8192128pcf = id_kem_cm.branch("16");

    /**
     *   -- FrodoKEM (ISO/IEC 18033-2:2006/Amd 2:2026, Clause 14)
     *   id-kem-frodokem OID ::= { id-kem frodokem(7) }
     */
    ASN1ObjectIdentifier id_kem_frodokem = id_kem.branch("7");

    ASN1ObjectIdentifier frodokem976_shake = id_kem_frodokem.branch("1");
    ASN1ObjectIdentifier frodokem1344_shake = id_kem_frodokem.branch("2");
    ASN1ObjectIdentifier efrodokem976_shake = id_kem_frodokem.branch("3");
    ASN1ObjectIdentifier efrodokem1344_shake = id_kem_frodokem.branch("4");
    ASN1ObjectIdentifier frodokem976_aes = id_kem_frodokem.branch("5");
    ASN1ObjectIdentifier frodokem1344_aes = id_kem_frodokem.branch("6");
    ASN1ObjectIdentifier efrodokem976_aes = id_kem_frodokem.branch("7");
    ASN1ObjectIdentifier efrodokem1344_aes = id_kem_frodokem.branch("8");
}
