package org.bouncycastle.internal.asn1.iana;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * IANA:
 *  { iso(1) identifier-organization(3) dod(6) internet(1) } == IETF defined things
 */
public interface IANAObjectIdentifiers
{

    /** { iso(1) identifier-organization(3) dod(6) internet(1) } == IETF defined things */
    ASN1ObjectIdentifier   internet       = new ASN1ObjectIdentifier("1.3.6.1");
    /** 1.3.6.1.1: Internet directory: X.500 */
    ASN1ObjectIdentifier   directory      = internet.branch("1");
    /** 1.3.6.1.2: Internet management */
    ASN1ObjectIdentifier   mgmt           = internet.branch("2");
    /** 1.3.6.1.3: */
    ASN1ObjectIdentifier   experimental   = internet.branch("3");
    /** 1.3.6.1.4: */
    ASN1ObjectIdentifier   _private       = internet.branch("4");
    /** 1.3.6.1.5: Security services */
    ASN1ObjectIdentifier   security       = internet.branch("5");
    /** 1.3.6.1.6: SNMPv2 -- never really used */
    ASN1ObjectIdentifier   SNMPv2         = internet.branch("6");
    /** 1.3.6.1.7: mail -- never really used */
    ASN1ObjectIdentifier   mail           = internet.branch("7");


    // id-SHA1 OBJECT IDENTIFIER ::=
    // {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) ipsec(8) isakmpOakley(1)}
    //


    /** IANA security mechanisms; 1.3.6.1.5.5 */
    ASN1ObjectIdentifier    security_mechanisms  = security.branch("5");
    /** IANA security nametypes;  1.3.6.1.5.6 */
    ASN1ObjectIdentifier    security_nametypes   = security.branch("6");

    /** PKIX base OID:            1.3.6.1.5.5.7 */
    ASN1ObjectIdentifier    pkix                 = security_mechanisms.branch("7");


    /** IPSEC base OID:                        1.3.6.1.5.5.8 */
    ASN1ObjectIdentifier    ipsec                = security_mechanisms.branch("8");
    /** IPSEC ISAKMP-Oakley OID:               1.3.6.1.5.5.8.1 */
    ASN1ObjectIdentifier    isakmpOakley         = ipsec.branch("1");

    /** IPSEC ISAKMP-Oakley hmacMD5 OID:       1.3.6.1.5.5.8.1.1 */
    ASN1ObjectIdentifier    hmacMD5              = isakmpOakley.branch("1");
    /** IPSEC ISAKMP-Oakley hmacSHA1 OID:      1.3.6.1.5.5.8.1.2 */
    ASN1ObjectIdentifier    hmacSHA1             = isakmpOakley.branch("2");

    /** IPSEC ISAKMP-Oakley hmacTIGER OID:     1.3.6.1.5.5.8.1.3 */
    ASN1ObjectIdentifier    hmacTIGER            = isakmpOakley.branch("3");

    /** IPSEC ISAKMP-Oakley hmacRIPEMD160 OID: 1.3.6.1.5.5.8.1.4 */
    ASN1ObjectIdentifier    hmacRIPEMD160        = isakmpOakley.branch("4");

    /** 1.3.6.1.5.5.7.6 */
    ASN1ObjectIdentifier id_alg  = internet.branch("5.5.7.6");

    ASN1ObjectIdentifier id_RSASSA_PSS_SHAKE128 = id_alg.branch("30");

    ASN1ObjectIdentifier id_RSASSA_PSS_SHAKE256 = id_alg.branch("31");

    ASN1ObjectIdentifier id_ecdsa_with_shake128 = id_alg.branch("32");

    ASN1ObjectIdentifier id_ecdsa_with_shake256 = id_alg.branch("33");

    ASN1ObjectIdentifier id_alg_unsigned = id_alg.branch("36");

    /** 1.3.6.1.5.5.7.6.37 id-MLDSA44-RSA2048-PSS-SHA256 */
    ASN1ObjectIdentifier id_MLDSA44_RSA2048_PSS_SHA256 = id_alg.branch("37");
    /** 1.3.6.1.5.5.7.6.38 id-MLDSA44-RSA2048-PKCS15-SHA256 */
    ASN1ObjectIdentifier id_MLDSA44_RSA2048_PKCS15_SHA256 = id_alg.branch("38");
    /** 1.3.6.1.5.5.7.6.39 id-MLDSA44-Ed25519-SHA512 */
    ASN1ObjectIdentifier id_MLDSA44_Ed25519_SHA512 = id_alg.branch("39");
    /** 1.3.6.1.5.5.7.6.40 id-MLDSA44-ECDSA-P256-SHA256 */
    ASN1ObjectIdentifier id_MLDSA44_ECDSA_P256_SHA256 = id_alg.branch("40");
    /** 1.3.6.1.5.5.7.6.41 id-MLDSA65-RSA3072-PSS-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_RSA3072_PSS_SHA512 = id_alg.branch("41");
    /** 1.3.6.1.5.5.7.6.42 id-MLDSA65-RSA3072-PKCS15-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_RSA3072_PKCS15_SHA512 = id_alg.branch("42");
    /** 1.3.6.1.5.5.7.6.43 id-MLDSA65-RSA4096-PSS-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_RSA4096_PSS_SHA512 = id_alg.branch("43");
    /** 1.3.6.1.5.5.7.6.44 id-MLDSA65-RSA4096-PKCS15-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_RSA4096_PKCS15_SHA512 = id_alg.branch("44");
    /** 1.3.6.1.5.5.7.6.45 id-MLDSA65-ECDSA-P256-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_ECDSA_P256_SHA512 = id_alg.branch("45");
    /** 1.3.6.1.5.5.7.6.46 id-MLDSA65-ECDSA-P384-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_ECDSA_P384_SHA512 = id_alg.branch("46");
    /** 1.3.6.1.5.5.7.6.47 id-MLDSA65-ECDSA-brainpoolP256r1-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_ECDSA_brainpoolP256r1_SHA512 = id_alg.branch("47");
    /** 1.3.6.1.5.5.7.6.48 id-MLDSA65-Ed25519-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_Ed25519_SHA512 = id_alg.branch("48");
    /** 1.3.6.1.5.5.7.6.49 id-MLDSA87-ECDSA-P384-SHA512 */
    ASN1ObjectIdentifier id_MLDSA87_ECDSA_P384_SHA512 = id_alg.branch("49");
    /** 1.3.6.1.5.5.7.6.50 id-MLDSA87-ECDSA-brainpoolP384r1-SHA512 */
    ASN1ObjectIdentifier id_MLDSA87_ECDSA_brainpoolP384r1_SHA512 = id_alg.branch("50");
    /** 1.3.6.1.5.5.7.6.51 id-MLDSA87-Ed448-SHAKE256 */
    ASN1ObjectIdentifier id_MLDSA87_Ed448_SHAKE256 = id_alg.branch("51");
    /** 1.3.6.1.5.5.7.6.52 id-MLDSA87-RSA3072-PSS-SHA512 */
    ASN1ObjectIdentifier id_MLDSA87_RSA3072_PSS_SHA512 = id_alg.branch("52");
    /** 1.3.6.1.5.5.7.6.53 id-MLDSA87-RSA4096-PSS-SHA512 */
    ASN1ObjectIdentifier id_MLDSA87_RSA4096_PSS_SHA512 = id_alg.branch("53");
    /** 1.3.6.1.5.5.7.6.54 id-MLDSA87-ECDSA-P521-SHA512 */
    ASN1ObjectIdentifier id_MLDSA87_ECDSA_P521_SHA512 = id_alg.branch("54");

}
