package org.bouncycastle.asn1.nist;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 *
 * NIST:
 *     iso/itu(2) joint-assign(16) us(840) organization(1) gov(101) csor(3) 
 */
public interface NISTObjectIdentifiers
{
    //
    // nistalgorithms(4)
    //
    /** 2.16.840.1.101.3.4 -- algorithms */
    static final ASN1ObjectIdentifier    nistAlgorithm           = new ASN1ObjectIdentifier("2.16.840.1.101.3.4");

    /** 2.16.840.1.101.3.4.2 */
    static final ASN1ObjectIdentifier    hashAlgs                = nistAlgorithm.branch("2");

    /** 2.16.840.1.101.3.4.2.1 */
    static final ASN1ObjectIdentifier    id_sha256               = hashAlgs.branch("1");
    /** 2.16.840.1.101.3.4.2.2 */
    static final ASN1ObjectIdentifier    id_sha384               = hashAlgs.branch("2");
    /** 2.16.840.1.101.3.4.2.3 */
    static final ASN1ObjectIdentifier    id_sha512               = hashAlgs.branch("3");
    /** 2.16.840.1.101.3.4.2.4 */
    static final ASN1ObjectIdentifier    id_sha224               = hashAlgs.branch("4");
    /** 2.16.840.1.101.3.4.2.5 */
    static final ASN1ObjectIdentifier    id_sha512_224           = hashAlgs.branch("5");
    /** 2.16.840.1.101.3.4.2.6 */
    static final ASN1ObjectIdentifier    id_sha512_256           = hashAlgs.branch("6");

    /** 2.16.840.1.101.3.4.2.7 */
    static final ASN1ObjectIdentifier    id_sha3_224 = hashAlgs.branch("7");
    /** 2.16.840.1.101.3.4.2.8 */
    static final ASN1ObjectIdentifier    id_sha3_256 = hashAlgs.branch("8");
    /** 2.16.840.1.101.3.4.2.9 */
    static final ASN1ObjectIdentifier    id_sha3_384 = hashAlgs.branch("9");
    /** 2.16.840.1.101.3.4.2.10 */
    static final ASN1ObjectIdentifier    id_sha3_512 = hashAlgs.branch("10");
    /** 2.16.840.1.101.3.4.2.11 */
    static final ASN1ObjectIdentifier    id_shake128 = hashAlgs.branch("11");
    /** 2.16.840.1.101.3.4.2.12 */
    static final ASN1ObjectIdentifier    id_shake256 = hashAlgs.branch("12");
    /** 2.16.840.1.101.3.4.2.13 */
    static final ASN1ObjectIdentifier    id_hmacWithSHA3_224 = hashAlgs.branch("13");
    /** 2.16.840.1.101.3.4.2.14 */
    static final ASN1ObjectIdentifier    id_hmacWithSHA3_256 = hashAlgs.branch("14");
    /** 2.16.840.1.101.3.4.2.15 */
    static final ASN1ObjectIdentifier    id_hmacWithSHA3_384 = hashAlgs.branch("15");
    /** 2.16.840.1.101.3.4.2.16 */
    static final ASN1ObjectIdentifier    id_hmacWithSHA3_512 = hashAlgs.branch("16");
    /** 2.16.840.1.101.3.4.2.17 */
    static final ASN1ObjectIdentifier    id_shake128_len = hashAlgs.branch("17");
    /** 2.16.840.1.101.3.4.2.18 */
    static final ASN1ObjectIdentifier    id_shake256_len = hashAlgs.branch("18");
    /** 2.16.840.1.101.3.4.2.19 */
    static final ASN1ObjectIdentifier    id_KmacWithSHAKE128 = hashAlgs.branch("19");
    /** 2.16.840.1.101.3.4.2.20 */
    static final ASN1ObjectIdentifier    id_KmacWithSHAKE256 = hashAlgs.branch("20");

    /** 2.16.840.1.101.3.4.1 */
    static final ASN1ObjectIdentifier    aes                     = nistAlgorithm.branch("1");
    
    /** 2.16.840.1.101.3.4.1.1 */
    static final ASN1ObjectIdentifier    id_aes128_ECB           = aes.branch("1"); 
    /** 2.16.840.1.101.3.4.1.2 */
    static final ASN1ObjectIdentifier    id_aes128_CBC           = aes.branch("2");
    /** 2.16.840.1.101.3.4.1.3 */
    static final ASN1ObjectIdentifier    id_aes128_OFB           = aes.branch("3"); 
    /** 2.16.840.1.101.3.4.1.4 */
    static final ASN1ObjectIdentifier    id_aes128_CFB           = aes.branch("4"); 
    /** 2.16.840.1.101.3.4.1.5 */
    static final ASN1ObjectIdentifier    id_aes128_wrap          = aes.branch("5");
    /** 2.16.840.1.101.3.4.1.6 */
    static final ASN1ObjectIdentifier    id_aes128_GCM           = aes.branch("6");
    /** 2.16.840.1.101.3.4.1.7 */
    static final ASN1ObjectIdentifier    id_aes128_CCM           = aes.branch("7");
    /** 2.16.840.1.101.3.4.1.28 */
    static final ASN1ObjectIdentifier    id_aes128_wrap_pad      = aes.branch("8");

    /** 2.16.840.1.101.3.4.1.21 */
    static final ASN1ObjectIdentifier    id_aes192_ECB           = aes.branch("21"); 
    /** 2.16.840.1.101.3.4.1.22 */
    static final ASN1ObjectIdentifier    id_aes192_CBC           = aes.branch("22"); 
    /** 2.16.840.1.101.3.4.1.23 */
    static final ASN1ObjectIdentifier    id_aes192_OFB           = aes.branch("23"); 
    /** 2.16.840.1.101.3.4.1.24 */
    static final ASN1ObjectIdentifier    id_aes192_CFB           = aes.branch("24"); 
    /** 2.16.840.1.101.3.4.1.25 */
    static final ASN1ObjectIdentifier    id_aes192_wrap          = aes.branch("25");
    /** 2.16.840.1.101.3.4.1.26 */
    static final ASN1ObjectIdentifier    id_aes192_GCM           = aes.branch("26");
    /** 2.16.840.1.101.3.4.1.27 */
    static final ASN1ObjectIdentifier    id_aes192_CCM           = aes.branch("27");
    /** 2.16.840.1.101.3.4.1.28 */
    static final ASN1ObjectIdentifier    id_aes192_wrap_pad      = aes.branch("28");

    /** 2.16.840.1.101.3.4.1.41 */
    static final ASN1ObjectIdentifier    id_aes256_ECB           = aes.branch("41"); 
    /** 2.16.840.1.101.3.4.1.42 */
    static final ASN1ObjectIdentifier    id_aes256_CBC           = aes.branch("42");
    /** 2.16.840.1.101.3.4.1.43 */
    static final ASN1ObjectIdentifier    id_aes256_OFB           = aes.branch("43"); 
    /** 2.16.840.1.101.3.4.1.44 */
    static final ASN1ObjectIdentifier    id_aes256_CFB           = aes.branch("44"); 
    /** 2.16.840.1.101.3.4.1.45 */
    static final ASN1ObjectIdentifier    id_aes256_wrap          = aes.branch("45"); 
    /** 2.16.840.1.101.3.4.1.46 */
    static final ASN1ObjectIdentifier    id_aes256_GCM           = aes.branch("46");
    /** 2.16.840.1.101.3.4.1.47 */
    static final ASN1ObjectIdentifier    id_aes256_CCM           = aes.branch("47");
    /** 2.16.840.1.101.3.4.1.48 */
    static final ASN1ObjectIdentifier    id_aes256_wrap_pad      = aes.branch("48");

    //
    // signatures
    //
    /** 2.16.840.1.101.3.4.3 */
    static final ASN1ObjectIdentifier    sigAlgs        = nistAlgorithm.branch("3");

    static final ASN1ObjectIdentifier    id_dsa_with_sha2        = sigAlgs;

    /** 2.16.840.1.101.3.4.3.1 */
    static final ASN1ObjectIdentifier    dsa_with_sha224         = sigAlgs.branch("1");
    /** 2.16.840.1.101.3.4.3.2 */
    static final ASN1ObjectIdentifier    dsa_with_sha256         = sigAlgs.branch("2");
    /** 2.16.840.1.101.3.4.3.3 */
    static final ASN1ObjectIdentifier    dsa_with_sha384         = sigAlgs.branch("3");
    /** 2.16.840.1.101.3.4.3.4 */
    static final ASN1ObjectIdentifier    dsa_with_sha512         = sigAlgs.branch("4");
    /** 2.16.840.1.101.3.4.3.5 */
    static final ASN1ObjectIdentifier    id_dsa_with_sha3_224       = sigAlgs.branch("5");
    /** 2.16.840.1.101.3.4.3.6 */
    static final ASN1ObjectIdentifier    id_dsa_with_sha3_256       = sigAlgs.branch("6");
    /** 2.16.840.1.101.3.4.3.7 */
    static final ASN1ObjectIdentifier    id_dsa_with_sha3_384       = sigAlgs.branch("7");
    /** 2.16.840.1.101.3.4.3.8 */
    static final ASN1ObjectIdentifier    id_dsa_with_sha3_512       = sigAlgs.branch("8");

    // ECDSA with SHA-3
    /** 2.16.840.1.101.3.4.3.9 */
    static final ASN1ObjectIdentifier    id_ecdsa_with_sha3_224       = sigAlgs.branch("9");
    /** 2.16.840.1.101.3.4.3.10 */
    static final ASN1ObjectIdentifier    id_ecdsa_with_sha3_256       = sigAlgs.branch("10");
    /** 2.16.840.1.101.3.4.3.11 */
    static final ASN1ObjectIdentifier    id_ecdsa_with_sha3_384       = sigAlgs.branch("11");
    /** 2.16.840.1.101.3.4.3.12 */
    static final ASN1ObjectIdentifier    id_ecdsa_with_sha3_512       = sigAlgs.branch("12");

    // RSA PKCS #1 v1.5 Signature with SHA-3 family.
    /** 2.16.840.1.101.3.4.3.9 */
    static final ASN1ObjectIdentifier    id_rsassa_pkcs1_v1_5_with_sha3_224       = sigAlgs.branch("13");
    /** 2.16.840.1.101.3.4.3.10 */
    static final ASN1ObjectIdentifier    id_rsassa_pkcs1_v1_5_with_sha3_256       = sigAlgs.branch("14");
    /** 2.16.840.1.101.3.4.3.11 */
    static final ASN1ObjectIdentifier    id_rsassa_pkcs1_v1_5_with_sha3_384       = sigAlgs.branch("15");
    /** 2.16.840.1.101.3.4.3.12 */
    static final ASN1ObjectIdentifier    id_rsassa_pkcs1_v1_5_with_sha3_512       = sigAlgs.branch("16");
}
