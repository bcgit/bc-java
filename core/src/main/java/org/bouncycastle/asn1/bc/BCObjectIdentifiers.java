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
     * XMSS
     */
    public static final ASN1ObjectIdentifier xmss = bc_sig.branch("2");
    public static final ASN1ObjectIdentifier xmss_SHA256ph = xmss.branch("1");
    public static final ASN1ObjectIdentifier xmss_SHA512ph = xmss.branch("2");
    public static final ASN1ObjectIdentifier xmss_SHAKE128ph = xmss.branch("3");
    public static final ASN1ObjectIdentifier xmss_SHAKE256ph = xmss.branch("4");
    public static final ASN1ObjectIdentifier xmss_SHA256 = xmss.branch("5");
    public static final ASN1ObjectIdentifier xmss_SHA512 = xmss.branch("6");
    public static final ASN1ObjectIdentifier xmss_SHAKE128 = xmss.branch("7");
    public static final ASN1ObjectIdentifier xmss_SHAKE256 = xmss.branch("8");

    /**
     * XMSS^MT
     */
    public static final ASN1ObjectIdentifier xmss_mt = bc_sig.branch("3");
    public static final ASN1ObjectIdentifier xmss_mt_SHA256ph = xmss_mt.branch("1");
    public static final ASN1ObjectIdentifier xmss_mt_SHA512ph = xmss_mt.branch("2");
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE128ph = xmss_mt.branch("3");
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE256ph = xmss_mt.branch("4");
    public static final ASN1ObjectIdentifier xmss_mt_SHA256 = xmss_mt.branch("5");
    public static final ASN1ObjectIdentifier xmss_mt_SHA512 = xmss_mt.branch("6");
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE128 = xmss_mt.branch("7");
    public static final ASN1ObjectIdentifier xmss_mt_SHAKE256 = xmss_mt.branch("8");

    // old OIDs.
    /**
     * @deprecated use xmss_SHA256ph
     */
    public static final ASN1ObjectIdentifier xmss_with_SHA256          = xmss_SHA256ph;
    /**
     * @deprecated use xmss_SHA512ph
     */
    public static final ASN1ObjectIdentifier xmss_with_SHA512 = xmss_SHA512ph;
    /**
     * @deprecated use xmss_SHAKE128ph
     */
    public static final ASN1ObjectIdentifier xmss_with_SHAKE128 = xmss_SHAKE128ph;
    /**
     * @deprecated use xmss_SHAKE256ph
     */
    public static final ASN1ObjectIdentifier xmss_with_SHAKE256        = xmss_SHAKE256ph;

    /**
     * @deprecated use xmss_mt_SHA256ph
     */
    public static final ASN1ObjectIdentifier xmss_mt_with_SHA256          = xmss_mt_SHA256ph;
    /**
     * @deprecated use xmss_mt_SHA512ph
     */
    public static final ASN1ObjectIdentifier xmss_mt_with_SHA512          = xmss_mt_SHA512ph;
    /**
     * @deprecated use xmss_mt_SHAKE128ph
     */
    public static final ASN1ObjectIdentifier xmss_mt_with_SHAKE128        = xmss_mt_SHAKE128;
    /**
     * @deprecated use xmss_mt_SHAKE256ph
     */
    public static final ASN1ObjectIdentifier xmss_mt_with_SHAKE256        = xmss_mt_SHAKE256;

    /**
     * qTESLA
     */
    public static final ASN1ObjectIdentifier qTESLA = bc_sig.branch("4");

    public static final ASN1ObjectIdentifier qTESLA_Rnd1_I = qTESLA.branch("1");
    public static final ASN1ObjectIdentifier qTESLA_Rnd1_III_size = qTESLA.branch("2");
    public static final ASN1ObjectIdentifier qTESLA_Rnd1_III_speed = qTESLA.branch("3");
    public static final ASN1ObjectIdentifier qTESLA_Rnd1_p_I = qTESLA.branch("4");
    public static final ASN1ObjectIdentifier qTESLA_Rnd1_p_III = qTESLA.branch("5");


    public static final ASN1ObjectIdentifier qTESLA_p_I = qTESLA.branch("11");
    public static final ASN1ObjectIdentifier qTESLA_p_III = qTESLA.branch("12");

    /**
     * key_exchange(3) algorithms
     */
    public static final ASN1ObjectIdentifier bc_exch = bc.branch("3");

    /**
     * NewHope
     */
    public static final ASN1ObjectIdentifier newHope = bc_exch.branch("1");

    /**
     * X.509 extension(4) values
     * <p>
     * 1.3.6.1.4.1.22554.4
     */
    public static final ASN1ObjectIdentifier bc_ext        = bc.branch("4");

    public static final ASN1ObjectIdentifier linkedCertificate = bc_ext.branch("1");
}
