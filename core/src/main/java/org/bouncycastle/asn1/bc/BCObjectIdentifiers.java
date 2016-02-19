package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 *  Object Identifiers belonging to iso.org.dod.internet.private.enterprise.legion-of-the-bouncy-castle (1.3.6.1.4.1.22554)
 */
public interface BCObjectIdentifiers
{
    /**
     *  iso.org.dod.internet.private.enterprise.legion-of-the-bouncy-castle
     *<p>
     *  1.3.6.1.4.1.22554
     */
    public static final ASN1ObjectIdentifier bc = new ASN1ObjectIdentifier("1.3.6.1.4.1.22554");

    /**
     * pbe(1) algorithms
     * <p>
     * 1.3.6.1.4.1.22554.1
     */
    public static final ASN1ObjectIdentifier bc_pbe        = bc.branch("1");

    /**
     * SHA-1(1)
     * <p>
     * 1.3.6.1.4.1.22554.1.1
     */
    public static final ASN1ObjectIdentifier bc_pbe_sha1   = bc_pbe.branch("1");

    /** SHA-2.SHA-256; 1.3.6.1.4.1.22554.1.2.1 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256 = bc_pbe.branch("2.1");
    /** SHA-2.SHA-384; 1.3.6.1.4.1.22554.1.2.2 */
    public static final ASN1ObjectIdentifier bc_pbe_sha384 = bc_pbe.branch("2.2");
    /** SHA-2.SHA-512; 1.3.6.1.4.1.22554.1.2.3 */
    public static final ASN1ObjectIdentifier bc_pbe_sha512 = bc_pbe.branch("2.3");
    /** SHA-2.SHA-224; 1.3.6.1.4.1.22554.1.2.4 */
    public static final ASN1ObjectIdentifier bc_pbe_sha224 = bc_pbe.branch("2.4");

    /**
     * PKCS-5(1)|PKCS-12(2)
     */
    /** SHA-1.PKCS5;  1.3.6.1.4.1.22554.1.1.1 */
    public static final ASN1ObjectIdentifier bc_pbe_sha1_pkcs5    = bc_pbe_sha1.branch("1");
    /** SHA-1.PKCS12; 1.3.6.1.4.1.22554.1.1.2 */
    public static final ASN1ObjectIdentifier bc_pbe_sha1_pkcs12   = bc_pbe_sha1.branch("2");

    /** SHA-256.PKCS12; 1.3.6.1.4.1.22554.1.2.1.1 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256_pkcs5  = bc_pbe_sha256.branch("1");
    /** SHA-256.PKCS12; 1.3.6.1.4.1.22554.1.2.1.2 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256_pkcs12 = bc_pbe_sha256.branch("2");

    /**
     * AES(1) . (CBC-128(2)|CBC-192(22)|CBC-256(42))
     */
    /** 1.3.6.1.4.1.22554.1.1.2.1.2 */
    public static final ASN1ObjectIdentifier bc_pbe_sha1_pkcs12_aes128_cbc   = bc_pbe_sha1_pkcs12.branch("1.2");
    /** 1.3.6.1.4.1.22554.1.1.2.1.22 */
    public static final ASN1ObjectIdentifier bc_pbe_sha1_pkcs12_aes192_cbc   = bc_pbe_sha1_pkcs12.branch("1.22");
    /** 1.3.6.1.4.1.22554.1.1.2.1.42 */
    public static final ASN1ObjectIdentifier bc_pbe_sha1_pkcs12_aes256_cbc   = bc_pbe_sha1_pkcs12.branch("1.42");

    /** 1.3.6.1.4.1.22554.1.1.2.2.2 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256_pkcs12_aes128_cbc = bc_pbe_sha256_pkcs12.branch("1.2");
    /** 1.3.6.1.4.1.22554.1.1.2.2.22 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256_pkcs12_aes192_cbc = bc_pbe_sha256_pkcs12.branch("1.22");
    /** 1.3.6.1.4.1.22554.1.1.2.2.42 */
    public static final ASN1ObjectIdentifier bc_pbe_sha256_pkcs12_aes256_cbc = bc_pbe_sha256_pkcs12.branch("1.42");

    /**
     * signature(2) algorithms
     */
    public static final ASN1ObjectIdentifier bc_sig        = bc.branch("2");

    /**
     * Sphincs-256
     */
    public static final ASN1ObjectIdentifier sphincs256                      = bc_sig.branch("1");
    public static final ASN1ObjectIdentifier sphincs256_with_BLAKE512        = sphincs256.branch("1");
    public static final ASN1ObjectIdentifier sphincs256_with_SHA512          = sphincs256.branch("2");
    public static final ASN1ObjectIdentifier sphincs256_with_SHA3_512        = sphincs256.branch("3");

    /**
     * key_exchange(3) algorithms
     */
    public static final ASN1ObjectIdentifier bc_exch = bc.branch("3");

    /**
     * NewHope
     */
    public static final ASN1ObjectIdentifier newHope = bc_exch.branch("1");
}
