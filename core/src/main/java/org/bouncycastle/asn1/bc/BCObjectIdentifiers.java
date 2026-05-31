package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Object Identifiers belonging to iso.org.dod.internet.private.enterprise.legion-of-the-bouncy-castle (1.3.6.1.4.1.22554)
 */
public interface BCObjectIdentifiers
{
    /**
     * iso.org.dod.internet.private.enterprise.legion-of-the-bouncy-castle
     * <p>
     * 1.3.6.1.4.1.22554
     */
    ASN1ObjectIdentifier bc = new ASN1ObjectIdentifier("1.3.6.1.4.1.22554");

    /**
     * pbe(1) algorithms
     * <p>
     * 1.3.6.1.4.1.22554.1
     */
    ASN1ObjectIdentifier bc_pbe = bc.branch("1");

    /**
     * SHA-1(1)
     * <p>
     * 1.3.6.1.4.1.22554.1.1
     */
    ASN1ObjectIdentifier bc_pbe_sha1 = bc_pbe.branch("1");

    /**
     * SHA-2.SHA-256; 1.3.6.1.4.1.22554.1.2.1
     */
    ASN1ObjectIdentifier bc_pbe_sha256 = bc_pbe.branch("2.1");
    /**
     * SHA-2.SHA-384; 1.3.6.1.4.1.22554.1.2.2
     */
    ASN1ObjectIdentifier bc_pbe_sha384 = bc_pbe.branch("2.2");
    /**
     * SHA-2.SHA-512; 1.3.6.1.4.1.22554.1.2.3
     */
    ASN1ObjectIdentifier bc_pbe_sha512 = bc_pbe.branch("2.3");
    /**
     * SHA-2.SHA-224; 1.3.6.1.4.1.22554.1.2.4
     */
    ASN1ObjectIdentifier bc_pbe_sha224 = bc_pbe.branch("2.4");

    /**
     * PKCS-5(1)|PKCS-12(2)
     */
    /**
     * SHA-1.PKCS5;  1.3.6.1.4.1.22554.1.1.1
     */
    ASN1ObjectIdentifier bc_pbe_sha1_pkcs5 = bc_pbe_sha1.branch("1");
    /**
     * SHA-1.PKCS12; 1.3.6.1.4.1.22554.1.1.2
     */
    ASN1ObjectIdentifier bc_pbe_sha1_pkcs12 = bc_pbe_sha1.branch("2");

    /**
     * SHA-256.PKCS5; 1.3.6.1.4.1.22554.1.2.1.1
     */
    ASN1ObjectIdentifier bc_pbe_sha256_pkcs5 = bc_pbe_sha256.branch("1");
    /**
     * SHA-256.PKCS12; 1.3.6.1.4.1.22554.1.2.1.2
     */
    ASN1ObjectIdentifier bc_pbe_sha256_pkcs12 = bc_pbe_sha256.branch("2");

    /**
     * AES(1) . (CBC-128(2)|CBC-192(22)|CBC-256(42))
     */
    /**
     * 1.3.6.1.4.1.22554.1.1.2.1.2
     */
    ASN1ObjectIdentifier bc_pbe_sha1_pkcs12_aes128_cbc = bc_pbe_sha1_pkcs12.branch("1.2");
    /**
     * 1.3.6.1.4.1.22554.1.1.2.1.22
     */
    ASN1ObjectIdentifier bc_pbe_sha1_pkcs12_aes192_cbc = bc_pbe_sha1_pkcs12.branch("1.22");
    /**
     * 1.3.6.1.4.1.22554.1.1.2.1.42
     */
    ASN1ObjectIdentifier bc_pbe_sha1_pkcs12_aes256_cbc = bc_pbe_sha1_pkcs12.branch("1.42");

    /**
     * 1.3.6.1.4.1.22554.1.1.2.2.2
     */
    ASN1ObjectIdentifier bc_pbe_sha256_pkcs12_aes128_cbc = bc_pbe_sha256_pkcs12.branch("1.2");
    /**
     * 1.3.6.1.4.1.22554.1.1.2.2.22
     */
    ASN1ObjectIdentifier bc_pbe_sha256_pkcs12_aes192_cbc = bc_pbe_sha256_pkcs12.branch("1.22");
    /**
     * 1.3.6.1.4.1.22554.1.1.2.2.42
     */
    ASN1ObjectIdentifier bc_pbe_sha256_pkcs12_aes256_cbc = bc_pbe_sha256_pkcs12.branch("1.42");

    /**
     * signature(2) algorithms
     */
    ASN1ObjectIdentifier bc_sig = bc.branch("2");

    /**
     * Sphincs-256
     */
    ASN1ObjectIdentifier sphincs256 = bc_sig.branch("1");
    ASN1ObjectIdentifier sphincs256_with_BLAKE512 = sphincs256.branch("1");
    ASN1ObjectIdentifier sphincs256_with_SHA512 = sphincs256.branch("2");
    ASN1ObjectIdentifier sphincs256_with_SHA3_512 = sphincs256.branch("3");

    /**
     * XMSS
     */
    ASN1ObjectIdentifier xmss = bc_sig.branch("2");
    ASN1ObjectIdentifier xmss_SHA256ph = xmss.branch("1");
    ASN1ObjectIdentifier xmss_SHA512ph = xmss.branch("2");
    ASN1ObjectIdentifier xmss_SHAKE128_512ph = xmss.branch("3");
    ASN1ObjectIdentifier xmss_SHAKE256_1024ph = xmss.branch("4");
    ASN1ObjectIdentifier xmss_SHA256 = xmss.branch("5");
    ASN1ObjectIdentifier xmss_SHA512 = xmss.branch("6");
    ASN1ObjectIdentifier xmss_SHAKE128 = xmss.branch("7");
    ASN1ObjectIdentifier xmss_SHAKE256 = xmss.branch("8");
    ASN1ObjectIdentifier xmss_SHAKE128ph = xmss.branch("9");
    ASN1ObjectIdentifier xmss_SHAKE256ph = xmss.branch("10");

    /**
     * XMSS^MT
     */
    ASN1ObjectIdentifier xmss_mt = bc_sig.branch("3");
    ASN1ObjectIdentifier xmss_mt_SHA256ph = xmss_mt.branch("1");
    ASN1ObjectIdentifier xmss_mt_SHA512ph = xmss_mt.branch("2");
    ASN1ObjectIdentifier xmss_mt_SHAKE128_512ph = xmss_mt.branch("3");
    ASN1ObjectIdentifier xmss_mt_SHAKE256_1024ph = xmss_mt.branch("4");
    ASN1ObjectIdentifier xmss_mt_SHA256 = xmss_mt.branch("5");
    ASN1ObjectIdentifier xmss_mt_SHA512 = xmss_mt.branch("6");
    ASN1ObjectIdentifier xmss_mt_SHAKE128 = xmss_mt.branch("7");
    ASN1ObjectIdentifier xmss_mt_SHAKE256 = xmss_mt.branch("8");
    ASN1ObjectIdentifier xmss_mt_SHAKE128ph = xmss_mt.branch("9");
    ASN1ObjectIdentifier xmss_mt_SHAKE256ph = xmss_mt.branch("10");

    /**
     * qTESLA
     */
    ASN1ObjectIdentifier qTESLA = bc_sig.branch("4");

    ASN1ObjectIdentifier qTESLA_Rnd1_I = qTESLA.branch("1");
    ASN1ObjectIdentifier qTESLA_Rnd1_III_size = qTESLA.branch("2");
    ASN1ObjectIdentifier qTESLA_Rnd1_III_speed = qTESLA.branch("3");
    ASN1ObjectIdentifier qTESLA_Rnd1_p_I = qTESLA.branch("4");
    ASN1ObjectIdentifier qTESLA_Rnd1_p_III = qTESLA.branch("5");


    ASN1ObjectIdentifier qTESLA_p_I = qTESLA.branch("11");
    ASN1ObjectIdentifier qTESLA_p_III = qTESLA.branch("12");

    /**
     * SPHINCS+
     */
    ASN1ObjectIdentifier sphincsPlus = bc_sig.branch("5");
    ASN1ObjectIdentifier sphincsPlus_sha2_128s_r3 = sphincsPlus.branch("1");
    ASN1ObjectIdentifier sphincsPlus_sha2_128f_r3 = sphincsPlus.branch("2");
    ASN1ObjectIdentifier sphincsPlus_shake_128s_r3 = sphincsPlus.branch("3");
    ASN1ObjectIdentifier sphincsPlus_shake_128f_r3 = sphincsPlus.branch("4");
    ASN1ObjectIdentifier sphincsPlus_haraka_128s_r3 = sphincsPlus.branch("5");
    ASN1ObjectIdentifier sphincsPlus_haraka_128f_r3 = sphincsPlus.branch("6");

    ASN1ObjectIdentifier sphincsPlus_sha2_192s_r3 = sphincsPlus.branch("7");
    ASN1ObjectIdentifier sphincsPlus_sha2_192f_r3 = sphincsPlus.branch("8");
    ASN1ObjectIdentifier sphincsPlus_shake_192s_r3 = sphincsPlus.branch("9");
    ASN1ObjectIdentifier sphincsPlus_shake_192f_r3 = sphincsPlus.branch("10");
    ASN1ObjectIdentifier sphincsPlus_haraka_192s_r3 = sphincsPlus.branch("11");
    ASN1ObjectIdentifier sphincsPlus_haraka_192f_r3 = sphincsPlus.branch("12");

    ASN1ObjectIdentifier sphincsPlus_sha2_256s_r3 = sphincsPlus.branch("13");
    ASN1ObjectIdentifier sphincsPlus_sha2_256f_r3 = sphincsPlus.branch("14");
    ASN1ObjectIdentifier sphincsPlus_shake_256s_r3 = sphincsPlus.branch("15");
    ASN1ObjectIdentifier sphincsPlus_shake_256f_r3 = sphincsPlus.branch("16");
    ASN1ObjectIdentifier sphincsPlus_haraka_256s_r3 = sphincsPlus.branch("17");
    ASN1ObjectIdentifier sphincsPlus_haraka_256f_r3 = sphincsPlus.branch("18");

    ASN1ObjectIdentifier sphincsPlus_sha2_128s_r3_simple = sphincsPlus.branch("19");
    ASN1ObjectIdentifier sphincsPlus_sha2_128f_r3_simple = sphincsPlus.branch("20");
    ASN1ObjectIdentifier sphincsPlus_shake_128s_r3_simple = sphincsPlus.branch("21");
    ASN1ObjectIdentifier sphincsPlus_shake_128f_r3_simple = sphincsPlus.branch("22");
    ASN1ObjectIdentifier sphincsPlus_haraka_128s_r3_simple = sphincsPlus.branch("23");
    ASN1ObjectIdentifier sphincsPlus_haraka_128f_r3_simple = sphincsPlus.branch("24");

    ASN1ObjectIdentifier sphincsPlus_sha2_192s_r3_simple = sphincsPlus.branch("25");
    ASN1ObjectIdentifier sphincsPlus_sha2_192f_r3_simple = sphincsPlus.branch("26");
    ASN1ObjectIdentifier sphincsPlus_shake_192s_r3_simple = sphincsPlus.branch("27");
    ASN1ObjectIdentifier sphincsPlus_shake_192f_r3_simple = sphincsPlus.branch("28");
    ASN1ObjectIdentifier sphincsPlus_haraka_192s_r3_simple = sphincsPlus.branch("29");
    ASN1ObjectIdentifier sphincsPlus_haraka_192f_r3_simple = sphincsPlus.branch("30");

    ASN1ObjectIdentifier sphincsPlus_sha2_256s_r3_simple = sphincsPlus.branch("31");
    ASN1ObjectIdentifier sphincsPlus_sha2_256f_r3_simple = sphincsPlus.branch("32");
    ASN1ObjectIdentifier sphincsPlus_shake_256s_r3_simple = sphincsPlus.branch("33");
    ASN1ObjectIdentifier sphincsPlus_shake_256f_r3_simple = sphincsPlus.branch("34");
    ASN1ObjectIdentifier sphincsPlus_haraka_256s_r3_simple = sphincsPlus.branch("35");
    ASN1ObjectIdentifier sphincsPlus_haraka_256f_r3_simple = sphincsPlus.branch("36");


    ASN1ObjectIdentifier sphincsPlus_interop = new ASN1ObjectIdentifier("1.3.9999.6");

    /** 1.3.9999.6.4.13 OQS_OID_SPHINCSSHA2128FSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_sha2_128f = new ASN1ObjectIdentifier("1.3.9999.6.4.13");
    /** 1.3.9999.6.4.16 OQS_OID_SPHINCSSHA2128SSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_sha2_128s = new ASN1ObjectIdentifier("1.3.9999.6.4.16");
    /** 1.3.9999.6.5.10 OQS_OID_SPHINCSSHA2192FSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_sha2_192f = new ASN1ObjectIdentifier("1.3.9999.6.5.10");
    /** 1.3.9999.6.5.12 OQS_OID_SPHINCSSHA2192SSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_sha2_192s = new ASN1ObjectIdentifier("1.3.9999.6.5.12");
    /** 1.3.9999.6.6.10 OQS_OID_SPHINCSSHA2256FSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_sha2_256f = new ASN1ObjectIdentifier("1.3.9999.6.6.10");
    /** 1.3.9999.6.6.12 OQS_OID_SPHINCSSHA2256SSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_sha2_256s = new ASN1ObjectIdentifier("1.3.9999.6.6.12");

    /** 1.3.9999.6.7.13 OQS_OID_SPHINCSSHAKE128FSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_shake_128f = new ASN1ObjectIdentifier("1.3.9999.6.7.13");
    /** 1.3.9999.6.7.16 OQS_OID_SPHINCSSHAKE128SSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_shake_128s = new ASN1ObjectIdentifier("1.3.9999.6.7.16");
    /** 1.3.9999.6.8.10 OQS_OID_SPHINCSSHAKE192FSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_shake_192f = new ASN1ObjectIdentifier("1.3.9999.6.8.10");
    /** 1.3.9999.6.8.12 OQS_OID_SPHINCSSHAKE192SSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_shake_192s = new ASN1ObjectIdentifier("1.3.9999.6.8.12");
    /** 1.3.9999.6.9.10 OQS_OID_SPHINCSSHAKE256FSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_shake_256f = new ASN1ObjectIdentifier("1.3.9999.6.9.10");
    /** 1.3.9999.6.9.12 OQS_OID_SPHINCSSHAKE256SSIMPLE */
    ASN1ObjectIdentifier sphincsPlus_shake_256s = new ASN1ObjectIdentifier("1.3.9999.6.9.12");
    /** 1.3.9999.6.4.14 OQS_OID_P256_SPHINCSSHA2128FSIMPLE */
    ASN1ObjectIdentifier p256_sphincs_sha2_128f_simple = new ASN1ObjectIdentifier("1.3.9999.6.4.14");
    /** 1.3.9999.6.4.15 OQS_OID_RSA3072_SPHINCSSHA2128FSIMPLE */
    ASN1ObjectIdentifier rsa_3072_sphincs_sha2_128f_simple = new ASN1ObjectIdentifier("1.3.9999.6.4.15");
    /** 1.3.9999.6.4.17 OQS_OID_P256_SPHINCSSHA2128SSIMPLE */
    ASN1ObjectIdentifier p256_sphincs_sha2_128s_simple = new ASN1ObjectIdentifier("1.3.9999.6.4.17");
    /** 1.3.9999.6.4.18 OQS_OID_RSA3072_SPHINCSSHA2128SSIMPLE */
    ASN1ObjectIdentifier rsa_3072_sphincs_sha2_128s_simple = new ASN1ObjectIdentifier("1.3.9999.6.4.18");
    /** 1.3.9999.6.5.11 OQS_OID_P384_SPHINCSSHA2192FSIMPLE */
    ASN1ObjectIdentifier p384_sphincs_sha2_192f_simple = new ASN1ObjectIdentifier("1.3.9999.6.5.11");
    /** 1.3.9999.6.5.13 OQS_OID_P384_SPHINCSSHA2192SSIMPLE */
    ASN1ObjectIdentifier p384_sphincs_sha2192s_simple = new ASN1ObjectIdentifier("1.3.9999.6.5.13");
    /** 1.3.9999.6.6.11 OQS_OID_P521_SPHINCSSHA2256FSIMPLE */
    ASN1ObjectIdentifier p521_sphincs_sha2_256f_simple = new ASN1ObjectIdentifier("1.3.9999.6.6.11");
    /** 1.3.9999.6.6.13 OQS_OID_P521_SPHINCSSHA2256SSIMPLE */
    ASN1ObjectIdentifier p521_sphincs_sha2_256s_simple = new ASN1ObjectIdentifier("1.3.9999.6.6.13");
    /** 1.3.9999.6.7.14 OQS_OID_P256_SPHINCSSHAKE128FSIMPLE */
    ASN1ObjectIdentifier p256_sphincs_shake_128f_simple = new ASN1ObjectIdentifier("1.3.9999.6.7.14");
    /** 1.3.9999.6.7.15 OQS_OID_RSA3072_SPHINCSSHAKE128FSIMPLE */
    ASN1ObjectIdentifier rsa_3072_sphincs_shake_128f_simple = new ASN1ObjectIdentifier("1.3.9999.6.7.15");
    /** 1.3.9999.6.7.17 OQS_OID_P256_SPHINCSSHAKE128SSIMPLE */
    ASN1ObjectIdentifier p256_sphincs_shake_128s_simple = new ASN1ObjectIdentifier("1.3.9999.6.7.17");
    /** 1.3.9999.6.7.18 OQS_OID_RSA3072_SPHINCSSHAKE128SSIMPLE */
    ASN1ObjectIdentifier rsa_3072_sphincs_shake_128s_simple = new ASN1ObjectIdentifier("1.3.9999.6.7.18");
    /** 1.3.9999.6.8.11 OQS_OID_P384_SPHINCSSHAKE192FSIMPLE */
    ASN1ObjectIdentifier p384_sphincs_shake_192f_simple = new ASN1ObjectIdentifier("1.3.9999.6.8.11");
    /** 1.3.9999.6.8.13 OQS_OID_P384_SPHINCSSHAKE192SSIMPLE */
    ASN1ObjectIdentifier p384_sphincs_shake_192s_simple = new ASN1ObjectIdentifier("1.3.9999.6.8.13");
    /** 1.3.9999.6.9.11 OQS_OID_P521_SPHINCSSHAKE256FSIMPLE */
    ASN1ObjectIdentifier p521_sphincs_shake256f_simple = new ASN1ObjectIdentifier("1.3.9999.6.9.11");
    /** 1.3.9999.6.9.13 OQS_OID_P521_SPHINCSSHAKE256SSIMPLE */
    ASN1ObjectIdentifier p521_sphincs_shake256s_simple = new ASN1ObjectIdentifier("1.3.9999.6.9.13");

    /**
     * Picnic
     */
    ASN1ObjectIdentifier picnic = bc_sig.branch("6");

    ASN1ObjectIdentifier picnic_key = picnic.branch("1");

    ASN1ObjectIdentifier picnicl1fs = picnic_key.branch("1");
    ASN1ObjectIdentifier picnicl1ur = picnic_key.branch("2");
    ASN1ObjectIdentifier picnicl3fs = picnic_key.branch("3");
    ASN1ObjectIdentifier picnicl3ur = picnic_key.branch("4");
    ASN1ObjectIdentifier picnicl5fs = picnic_key.branch("5");
    ASN1ObjectIdentifier picnicl5ur = picnic_key.branch("6");
    ASN1ObjectIdentifier picnic3l1 = picnic_key.branch("7");
    ASN1ObjectIdentifier picnic3l3 = picnic_key.branch("8");
    ASN1ObjectIdentifier picnic3l5 = picnic_key.branch("9");
    ASN1ObjectIdentifier picnicl1full = picnic_key.branch("10");
    ASN1ObjectIdentifier picnicl3full = picnic_key.branch("11");
    ASN1ObjectIdentifier picnicl5full = picnic_key.branch("12");

    ASN1ObjectIdentifier picnic_signature = picnic.branch("2");

    ASN1ObjectIdentifier picnic_with_sha512 = picnic_signature.branch("1");
    ASN1ObjectIdentifier picnic_with_shake256 = picnic_signature.branch("2");
    ASN1ObjectIdentifier picnic_with_sha3_512 = picnic_signature.branch("3");

    /*
     * Falcon
     */
    ASN1ObjectIdentifier falcon = bc_sig.branch("7");

    ASN1ObjectIdentifier old_falcon_512 = new ASN1ObjectIdentifier("1.3.9999.3.6");  // falcon.branch("1");
    ASN1ObjectIdentifier old_falcon_1024 = new ASN1ObjectIdentifier("1.3.9999.3.9"); // falcon.branch("2");

    /** 1.3.9999.3.11 OQS_OID_FALCON512 */
    ASN1ObjectIdentifier falcon_512 = new ASN1ObjectIdentifier("1.3.9999.3.11");
    /** 1.3.9999.3.12 OQS_OID_P256_FALCON512 */
    ASN1ObjectIdentifier p256_falcon_512 = new ASN1ObjectIdentifier("1.3.9999.3.12");
    /** 1.3.9999.3.13 OQS_OID_RSA3072_FALCON512 */
    ASN1ObjectIdentifier rsa_3072_falcon_512 = new ASN1ObjectIdentifier("1.3.9999.3.13");
    /** 1.3.9999.3.14 OQS_OID_FALCON1024 */
    ASN1ObjectIdentifier falcon_1024 = new ASN1ObjectIdentifier("1.3.9999.3.14");
    /** 1.3.9999.3.15 OQS_OID_P521_FALCON1024 */
    ASN1ObjectIdentifier p521_falcon1024 = new ASN1ObjectIdentifier("1.3.9999.3.15");
    /** 1.3.9999.3.16 OQS_OID_FALCONPADDED512 */
    ASN1ObjectIdentifier falcon_padded_512 = new ASN1ObjectIdentifier("1.3.9999.3.16");
    /** 1.3.9999.3.17 OQS_OID_P256_FALCONPADDED512 */
    ASN1ObjectIdentifier p256_falcon_padded512 = new ASN1ObjectIdentifier("1.3.9999.3.17");
    /** 1.3.9999.3.18 OQS_OID_RSA3072_FALCONPADDED512 */
    ASN1ObjectIdentifier rsa_3072_falconpadded512 = new ASN1ObjectIdentifier("1.3.9999.3.18");
    /** 1.3.9999.3.19 OQS_OID_FALCONPADDED1024 */
    ASN1ObjectIdentifier falcon_padded_1024 = new ASN1ObjectIdentifier("1.3.9999.3.19");
    /** 1.3.9999.3.20 OQS_OID_P521_FALCONPADDED1024 */
    ASN1ObjectIdentifier p521_falcon_padded_1024 = new ASN1ObjectIdentifier("1.3.9999.3.20");

    /*
     * Dilithium
     */
    ASN1ObjectIdentifier dilithium = bc_sig.branch("8");

    // OpenSSL OIDs
    ASN1ObjectIdentifier dilithium2 = new ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.12.4.4"); // dilithium.branch("1");
    ASN1ObjectIdentifier dilithium3 = new ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.12.6.5"); // dilithium.branch("2");
    ASN1ObjectIdentifier dilithium5 = new ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.12.8.7"); // dilithium.branch("3");
    ASN1ObjectIdentifier dilithium2_aes = new ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.11.4.4"); // dilithium.branch("4");
    ASN1ObjectIdentifier dilithium3_aes = new ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.11.6.5"); // dilithium.branch("5");
    ASN1ObjectIdentifier dilithium5_aes = new ASN1ObjectIdentifier("1.3.6.1.4.1.2.267.11.8.7"); // dilithium.branch("6");

    /*
     * ML-DSA
     */
    ///** 2.16.840.1.101.3.4.3.17 OQS_OID_MLDSA44 */
    /** 1.3.9999.7.5 OQS_OID_P256_MLDSA44 */
    ASN1ObjectIdentifier p256_mldsa44 = new ASN1ObjectIdentifier("1.3.9999.7.5");
    /** 1.3.9999.7.6 OQS_OID_RSA3072_MLDSA44 */
    ASN1ObjectIdentifier rsa3072_mldsa44 = new ASN1ObjectIdentifier("1.3.9999.7.6");
    /** 2.16.840.1.114027.80.8.1.1 OQS_OID_MLDSA44_pss2048 */
    ASN1ObjectIdentifier mldsa44_pss2048 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.1");
    /** 2.16.840.1.114027.80.8.1.2 OQS_OID_MLDSA44_rsa2048 */
    ASN1ObjectIdentifier mldsa44_rsa2048 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.2");
    /** 2.16.840.1.114027.80.8.1.3 OQS_OID_MLDSA44_ed25519 */
    ASN1ObjectIdentifier mldsa44_ed25519 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.3");
    /** 2.16.840.1.114027.80.8.1.4 OQS_OID_MLDSA44_p256 */
    ASN1ObjectIdentifier mldsa44_p256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.4");
    /** 2.16.840.1.114027.80.8.1.5 OQS_OID_MLDSA44_bp256 */
    ASN1ObjectIdentifier mldsa44_bp256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.5");
    ///** 2.16.840.1.101.3.4.3.18 OQS_OID_MLDSA65 */
    /** 1.3.9999.7.7 OQS_OID_P384_MLDSA65 */
    ASN1ObjectIdentifier p384_mldsa65 = new ASN1ObjectIdentifier("1.3.9999.7.7");
    /** 2.16.840.1.114027.80.8.1.6 OQS_OID_MLDSA65_pss3072 */
    ASN1ObjectIdentifier mldsa65_pss3072 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.6");
    /** 2.16.840.1.114027.80.8.1.7 OQS_OID_MLDSA65_rsa3072 */
    ASN1ObjectIdentifier mldsa65_rsa3072 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.7");
    /** 2.16.840.1.114027.80.8.1.8 OQS_OID_MLDSA65_p256 */
    ASN1ObjectIdentifier mldsa65_p256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.8");
    /** 2.16.840.1.114027.80.8.1.9 OQS_OID_MLDSA65_bp256 */
    ASN1ObjectIdentifier mldsa65_bp256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.9");
    /** 2.16.840.1.114027.80.8.1.10 OQS_OID_MLDSA65_ed25519 */
    ASN1ObjectIdentifier mldsa65_ed25519 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.10");
    ///** 2.16.840.1.101.3.4.3.19 OQS_OID_MLDSA87 */
    /** 1.3.9999.7.8 OQS_OID_P521_MLDSA87 */
    ASN1ObjectIdentifier p521_mldsa87 = new ASN1ObjectIdentifier("1.3.9999.7.8");
    /** 2.16.840.1.114027.80.8.1.11 OQS_OID_MLDSA87_p384 */
    ASN1ObjectIdentifier mldsa87_p384 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.11");
    /** 2.16.840.1.114027.80.8.1.12 OQS_OID_MLDSA87_bp384 */
    ASN1ObjectIdentifier mldsa87_bp384 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.12");
    /** 2.16.840.1.114027.80.8.1.13 OQS_OID_MLDSA87_ed448 */
    ASN1ObjectIdentifier mldsa87_ed448 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.8.1.13");

    /** 2.16.840.1.114027.80.9.1.0 id-MLDSA44-RSA2048-PSS-SHA256 */
    ASN1ObjectIdentifier id_MLDSA44_RSA2048_PSS_SHA256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.0");
    /** 2.16.840.1.114027.80.9.1.1 id-MLDSA44-RSA2048-PKCS15-SHA256 */
    ASN1ObjectIdentifier id_MLDSA44_RSA2048_PKCS15_SHA256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.1");
    /** 2.16.840.1.114027.80.9.1.2 id-MLDSA44-Ed25519-SHA512 */
    ASN1ObjectIdentifier id_MLDSA44_Ed25519_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.2");
    /** 2.16.840.1.114027.80.9.1.3 id-MLDSA44-ECDSA-P256-SHA256 */
    ASN1ObjectIdentifier id_MLDSA44_ECDSA_P256_SHA256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.3");
    /** 2.16.840.1.114027.80.9.1.4 id-MLDSA65-RSA3072-PSS-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_RSA3072_PSS_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.4");
    /** 2.16.840.1.114027.80.9.1.5 id-MLDSA65-RSA3072-PKCS15-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_RSA3072_PKCS15_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.5");
    /** 2.16.840.1.114027.80.9.1.6 id-MLDSA65-RSA4096-PSS-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_RSA4096_PSS_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.6");
    /** 2.16.840.1.114027.80.9.1.7 id-MLDSA65-RSA4096-PKCS15-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_RSA4096_PKCS15_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.7");
    /** 2.16.840.1.114027.80.9.1.8 id-MLDSA65-ECDSA-P256-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_ECDSA_P256_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.8");
    /** 2.16.840.1.114027.80.9.1.9 id-MLDSA65-ECDSA-P384-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_ECDSA_P384_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.9");
    /** 2.16.840.1.114027.80.9.1.10 id-MLDSA65-ECDSA-brainpoolP256r1-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_ECDSA_brainpoolP256r1_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.10");
    /** 2.16.840.1.114027.80.9.1.11 id-MLDSA65-Ed25519-SHA512 */
    ASN1ObjectIdentifier id_MLDSA65_Ed25519_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.11");
    /** 2.16.840.1.114027.80.9.1.12 id-MLDSA87-ECDSA-P384-SHA512 */
    ASN1ObjectIdentifier id_MLDSA87_ECDSA_P384_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.12");
    /** 2.16.840.1.114027.80.9.1.13 id-MLDSA87-ECDSA-brainpoolP384r1-SHA512 */
    ASN1ObjectIdentifier id_MLDSA87_ECDSA_brainpoolP384r1_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.13");
    /** 2.16.840.1.114027.80.9.1.14 id-MLDSA87-Ed448-SHAKE256 */
    ASN1ObjectIdentifier id_MLDSA87_Ed448_SHAKE256 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.14");
    /** 2.16.840.1.114027.80.9.1.15 id-MLDSA87-RSA3072-PSS-SHA512 */
    ASN1ObjectIdentifier id_MLDSA87_RSA3072_PSS_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.15");
    /** 2.16.840.1.114027.80.9.1.16 id-MLDSA87-RSA4096-PSS-SHA512 */
    ASN1ObjectIdentifier id_MLDSA87_RSA4096_PSS_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.16");
    /** 2.16.840.1.114027.80.9.1.17 id-MLDSA87-ECDSA-P521-SHA512 */
    ASN1ObjectIdentifier id_MLDSA87_ECDSA_P521_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.114027.80.9.1.17");

    /*
     * Rainbow
     */
    ASN1ObjectIdentifier rainbow = bc_sig.branch("9");

    ASN1ObjectIdentifier rainbow_III_classic = rainbow.branch("1");
    ASN1ObjectIdentifier rainbow_III_circumzenithal = rainbow.branch("2");
    ASN1ObjectIdentifier rainbow_III_compressed = rainbow.branch("3");
    ASN1ObjectIdentifier rainbow_V_classic = rainbow.branch("4");
    ASN1ObjectIdentifier rainbow_V_circumzenithal = rainbow.branch("5");
    ASN1ObjectIdentifier rainbow_V_compressed = rainbow.branch("6");

    /**
     * key_exchange(3) algorithms
     */
    ASN1ObjectIdentifier bc_exch = bc.branch("3");

    /**
     * NewHope
     */
    ASN1ObjectIdentifier newHope = bc_exch.branch("1");

    /**
     * X.509 extension/certificate types
     * <p>
     * 1.3.6.1.4.1.22554.4
     */
    ASN1ObjectIdentifier bc_ext = bc.branch("4");

    ASN1ObjectIdentifier linkedCertificate = bc_ext.branch("1");
    ASN1ObjectIdentifier external_value = bc_ext.branch("2");

    /**
     * Placeholder for the id-ad-certDiscovery access method defined by
     * draft-ietf-lamps-certdiscovery-03 (registered as TBD2 against the SMI
     * Security for PKIX Access Descriptor registry). Used as the
     * AccessDescription.accessMethod inside a SubjectInfoAccess extension to
     * advertise that the accessLocation points at a related certificate.
     * <p>
     * 1.3.6.1.4.1.22554.4.3 (BC private placeholder; replace with the
     * IANA-assigned id-ad.N once the draft progresses to RFC)
     */
    ASN1ObjectIdentifier id_ad_certDiscovery = bc_ext.branch("3");

    /**
     * Placeholder for the id-on-relatedCertificateDescriptor otherName type
     * defined by draft-ietf-lamps-certdiscovery-03 (registered as TBD3
     * against the SMI Security for PKIX Other Name Forms registry). Used as
     * the OtherName.type-id wrapping the RelatedCertificateDescriptor
     * carried inside the SIA extension's accessLocation GeneralName.
     * <p>
     * 1.3.6.1.4.1.22554.4.4 (BC private placeholder; replace with the
     * IANA-assigned id-on.N once the draft progresses to RFC)
     */
    ASN1ObjectIdentifier id_on_relatedCertificateDescriptor = bc_ext.branch("4");

    /**
     * Placeholder for the id-rcd discovery-intent arc defined by
     * draft-ietf-lamps-certdiscovery-03 (registered as TBD4). Parent of the
     * five DiscoveryIntentId values below.
     * <p>
     * 1.3.6.1.4.1.22554.4.5 (BC private placeholder; replace with the
     * IANA-assigned id-rcd once the draft progresses to RFC)
     */
    ASN1ObjectIdentifier id_rcd = bc_ext.branch("5");

    /** id-rcd-agility: secondary certificate provides cryptographic agility. */
    ASN1ObjectIdentifier id_rcd_agility       = id_rcd.branch("1");
    /** id-rcd-redundancy: secondary certificate is a backup (different CA / validity). */
    ASN1ObjectIdentifier id_rcd_redundancy    = id_rcd.branch("2");
    /** id-rcd-dual: secondary certificate provides the complementary key usage (sign/encrypt split). */
    ASN1ObjectIdentifier id_rcd_dual          = id_rcd.branch("3");
    /** id-rcd-priv-key-stmt: secondary certificate carries a proof-of-possession statement signed for the primary. */
    ASN1ObjectIdentifier id_rcd_priv_key_stmt = id_rcd.branch("4");
    /** id-rcd-self: descriptor points at the location of the current certificate itself. */
    ASN1ObjectIdentifier id_rcd_self          = id_rcd.branch("5");

    /**
     * KEM(5) algorithms
     */
    ASN1ObjectIdentifier bc_kem = bc.branch("5");

    /**
     * Classic McEliece
     */
    ASN1ObjectIdentifier pqc_kem_mceliece = bc_kem.branch("1");

    ASN1ObjectIdentifier mceliece348864_r3 = pqc_kem_mceliece.branch("1");
    ASN1ObjectIdentifier mceliece348864f_r3 = pqc_kem_mceliece.branch("2");
    ASN1ObjectIdentifier mceliece460896_r3 = pqc_kem_mceliece.branch("3");
    ASN1ObjectIdentifier mceliece460896f_r3 = pqc_kem_mceliece.branch("4");
    ASN1ObjectIdentifier mceliece6688128_r3 = pqc_kem_mceliece.branch("5");
    ASN1ObjectIdentifier mceliece6688128f_r3 = pqc_kem_mceliece.branch("6");
    ASN1ObjectIdentifier mceliece6960119_r3 = pqc_kem_mceliece.branch("7");
    ASN1ObjectIdentifier mceliece6960119f_r3 = pqc_kem_mceliece.branch("8");
    ASN1ObjectIdentifier mceliece8192128_r3 = pqc_kem_mceliece.branch("9");
    ASN1ObjectIdentifier mceliece8192128f_r3 = pqc_kem_mceliece.branch("10");

    /**
     * Frodo
     */
    ASN1ObjectIdentifier pqc_kem_frodo = bc_kem.branch("2");

    ASN1ObjectIdentifier frodokem640aes = pqc_kem_frodo.branch("1");
    ASN1ObjectIdentifier frodokem640shake = pqc_kem_frodo.branch("2");
    ASN1ObjectIdentifier frodokem976aes = pqc_kem_frodo.branch("3");
    ASN1ObjectIdentifier frodokem976shake = pqc_kem_frodo.branch("4");
    ASN1ObjectIdentifier frodokem1344aes = pqc_kem_frodo.branch("5");
    ASN1ObjectIdentifier frodokem1344shake = pqc_kem_frodo.branch("6");

    /**
     * SABER
     */
    ASN1ObjectIdentifier pqc_kem_saber = bc_kem.branch("3");

    ASN1ObjectIdentifier lightsaberkem128r3 = pqc_kem_saber.branch("1");
    ASN1ObjectIdentifier saberkem128r3 = pqc_kem_saber.branch("2");
    ASN1ObjectIdentifier firesaberkem128r3 = pqc_kem_saber.branch("3");
    ASN1ObjectIdentifier lightsaberkem192r3 = pqc_kem_saber.branch("4");
    ASN1ObjectIdentifier saberkem192r3 = pqc_kem_saber.branch("5");
    ASN1ObjectIdentifier firesaberkem192r3 = pqc_kem_saber.branch("6");
    ASN1ObjectIdentifier lightsaberkem256r3 = pqc_kem_saber.branch("7");
    ASN1ObjectIdentifier saberkem256r3 = pqc_kem_saber.branch("8");
    ASN1ObjectIdentifier firesaberkem256r3 = pqc_kem_saber.branch("9");
    ASN1ObjectIdentifier ulightsaberkemr3 = pqc_kem_saber.branch("10");
    ASN1ObjectIdentifier usaberkemr3 = pqc_kem_saber.branch("11");
    ASN1ObjectIdentifier ufiresaberkemr3 = pqc_kem_saber.branch("12");
    ASN1ObjectIdentifier lightsaberkem90sr3 = pqc_kem_saber.branch("13");
    ASN1ObjectIdentifier saberkem90sr3 = pqc_kem_saber.branch("14");
    ASN1ObjectIdentifier firesaberkem90sr3 = pqc_kem_saber.branch("15");
    ASN1ObjectIdentifier ulightsaberkem90sr3 = pqc_kem_saber.branch("16");
    ASN1ObjectIdentifier usaberkem90sr3 = pqc_kem_saber.branch("17");
    ASN1ObjectIdentifier ufiresaberkem90sr3 = pqc_kem_saber.branch("18");

    /**
     * SIKE
     */
    ASN1ObjectIdentifier pqc_kem_sike = bc_kem.branch("4");

    ASN1ObjectIdentifier sikep434 = pqc_kem_sike.branch("1");
    ASN1ObjectIdentifier sikep503 = pqc_kem_sike.branch("2");
    ASN1ObjectIdentifier sikep610 = pqc_kem_sike.branch("3");
    ASN1ObjectIdentifier sikep751 = pqc_kem_sike.branch("4");
    ASN1ObjectIdentifier sikep434_compressed = pqc_kem_sike.branch("5");
    ASN1ObjectIdentifier sikep503_compressed = pqc_kem_sike.branch("6");
    ASN1ObjectIdentifier sikep610_compressed = pqc_kem_sike.branch("7");
    ASN1ObjectIdentifier sikep751_compressed = pqc_kem_sike.branch("8");

    /**
     * NTRU
     */
    ASN1ObjectIdentifier pqc_kem_ntru = bc_kem.branch("5");

    ASN1ObjectIdentifier ntruhps2048509 = pqc_kem_ntru.branch("1");
    ASN1ObjectIdentifier ntruhps2048677 = pqc_kem_ntru.branch("2");
    ASN1ObjectIdentifier ntruhps4096821 = pqc_kem_ntru.branch("3");
    ASN1ObjectIdentifier ntruhrss701 = pqc_kem_ntru.branch("4");
    ASN1ObjectIdentifier ntruhps40961229 = pqc_kem_ntru.branch("5");
    ASN1ObjectIdentifier ntruhrss1373 = pqc_kem_ntru.branch("6");

    /**
     * Kyber
     */
    ASN1ObjectIdentifier pqc_kem_kyber = bc_kem.branch("6");

    ASN1ObjectIdentifier kyber512 = pqc_kem_kyber.branch("1");
    ASN1ObjectIdentifier kyber768 = pqc_kem_kyber.branch("2");
    ASN1ObjectIdentifier kyber1024 = pqc_kem_kyber.branch("3");
    ASN1ObjectIdentifier kyber512_aes = pqc_kem_kyber.branch("4");
    ASN1ObjectIdentifier kyber768_aes = pqc_kem_kyber.branch("5");
    ASN1ObjectIdentifier kyber1024_aes = pqc_kem_kyber.branch("6");

    /**
     * NTRUPrime
     */
    ASN1ObjectIdentifier pqc_kem_ntruprime = bc_kem.branch("7");

    ASN1ObjectIdentifier pqc_kem_ntrulprime = pqc_kem_ntruprime.branch("1");
    ASN1ObjectIdentifier ntrulpr653 = pqc_kem_ntrulprime.branch("1");
    ASN1ObjectIdentifier ntrulpr761 = pqc_kem_ntrulprime.branch("2");
    ASN1ObjectIdentifier ntrulpr857 = pqc_kem_ntrulprime.branch("3");
    ASN1ObjectIdentifier ntrulpr953 = pqc_kem_ntrulprime.branch("4");
    ASN1ObjectIdentifier ntrulpr1013 = pqc_kem_ntrulprime.branch("5");
    ASN1ObjectIdentifier ntrulpr1277 = pqc_kem_ntrulprime.branch("6");

    ASN1ObjectIdentifier pqc_kem_sntruprime = pqc_kem_ntruprime.branch("2");
    ASN1ObjectIdentifier sntrup653 = pqc_kem_sntruprime.branch("1");
    ASN1ObjectIdentifier sntrup761 = pqc_kem_sntruprime.branch("2");
    ASN1ObjectIdentifier sntrup857 = pqc_kem_sntruprime.branch("3");
    ASN1ObjectIdentifier sntrup953 = pqc_kem_sntruprime.branch("4");
    ASN1ObjectIdentifier sntrup1013 = pqc_kem_sntruprime.branch("5");
    ASN1ObjectIdentifier sntrup1277 = pqc_kem_sntruprime.branch("6");

    /**
     * BIKE
     **/
    ASN1ObjectIdentifier pqc_kem_bike = bc_kem.branch("8");

    ASN1ObjectIdentifier bike128 = pqc_kem_bike.branch("1");
    ASN1ObjectIdentifier bike192 = pqc_kem_bike.branch("2");
    ASN1ObjectIdentifier bike256 = pqc_kem_bike.branch("3");

    /**
     * HQC
     **/
    ASN1ObjectIdentifier pqc_kem_hqc = bc_kem.branch("9");

    ASN1ObjectIdentifier hqc128 = pqc_kem_hqc.branch("1");
    ASN1ObjectIdentifier hqc192 = pqc_kem_hqc.branch("2");
    ASN1ObjectIdentifier hqc256 = pqc_kem_hqc.branch("3");
    
    /**
     * Mayo
     */
    ASN1ObjectIdentifier mayo = bc_sig.branch("10");

    /** 1.3.9999.8.1.3 OQS_OID_MAYO1 */
    ASN1ObjectIdentifier mayo_1 = new ASN1ObjectIdentifier("1.3.9999.8.1.3");
    /** 1.3.9999.8.1.4 OQS_OID_P256_MAYO1 */
    ASN1ObjectIdentifier p256_mayo1 = new ASN1ObjectIdentifier("1.3.9999.8.1.4");
    /** 1.3.9999.8.2.3 OQS_OID_MAYO2 */
    ASN1ObjectIdentifier mayo_2 = new ASN1ObjectIdentifier("1.3.9999.8.2.3");
    /** 1.3.9999.8.2.4 OQS_OID_P256_MAYO2 */
    ASN1ObjectIdentifier p256_mayo2 = new ASN1ObjectIdentifier("1.3.9999.8.2.4");
    /** 1.3.9999.8.3.3 OQS_OID_MAYO3 */
    ASN1ObjectIdentifier mayo_3 = new ASN1ObjectIdentifier("1.3.9999.8.3.3");
    /** 1.3.9999.8.3.4 OQS_OID_P384_MAYO3 */
    ASN1ObjectIdentifier p384_mayo3 = new ASN1ObjectIdentifier("1.3.9999.8.3.4");
    /** 1.3.9999.8.5.3 OQS_OID_MAYO5 */
    ASN1ObjectIdentifier mayo_5 = new ASN1ObjectIdentifier("1.3.9999.8.5.3");
    /** 1.3.9999.8.5.4 OQS_OID_P521_MAYO5 */
    ASN1ObjectIdentifier p521_mayo5 = new ASN1ObjectIdentifier("1.3.9999.8.5.4");

    ASN1ObjectIdentifier mayo1 = mayo_1;
    ASN1ObjectIdentifier mayo2 = mayo_2;
    ASN1ObjectIdentifier mayo3 = mayo_3;
    ASN1ObjectIdentifier mayo5 = mayo_5;

    /**
     * cross
     */
//    /** 1.3.6.1.4.1.62245.2.1.1.2 OQS_OID_CROSSRSDP128BALANCED */
//    ASN1ObjectIdentifier crossrsdp_128balanced = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.1.2");
//    /** 1.3.6.1.4.1.62245.2.1.2.2 OQS_OID_CROSSRSDP128FAST */
//    ASN1ObjectIdentifier crossrsdp_128fast = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.2.2");
//    /** 1.3.6.1.4.1.62245.2.1.3.2 OQS_OID_CROSSRSDP128SMALL */
//    ASN1ObjectIdentifier crossrsdp_128small = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.3.2");
//    /** 1.3.6.1.4.1.62245.2.1.4.2 OQS_OID_CROSSRSDP192BALANCED */
//    ASN1ObjectIdentifier crossrsdp_192balanced = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.4.2");
//    /** 1.3.6.1.4.1.62245.2.1.5.2 OQS_OID_CROSSRSDP192FAST */
//    ASN1ObjectIdentifier crossrsdp_192fast = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.5.2");
//    /** 1.3.6.1.4.1.62245.2.1.6.2 OQS_OID_CROSSRSDP192SMALL */
//    ASN1ObjectIdentifier crossrsdp_192small = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.6.2");
//    /** 1.3.6.1.4.1.62245.2.1.9.2 OQS_OID_CROSSRSDP256SMALL */
//    ASN1ObjectIdentifier crossrsdp256small = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.9.2");
//    /** 1.3.6.1.4.1.62245.2.1.10.2 OQS_OID_CROSSRSDPG128BALANCED */
//    ASN1ObjectIdentifier crossrsdpg_128balanced = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.10.2");
//    /** 1.3.6.1.4.1.62245.2.1.11.2 OQS_OID_CROSSRSDPG128FAST */
//    ASN1ObjectIdentifier crossrsdpg_128fast = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.11.2");
//    /** 1.3.6.1.4.1.62245.2.1.12.2 OQS_OID_CROSSRSDPG128SMALL */
//    ASN1ObjectIdentifier crossrsdpg_128small = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.12.2");
//    /** 1.3.6.1.4.1.62245.2.1.13.2 OQS_OID_CROSSRSDPG192BALANCED */
//    ASN1ObjectIdentifier crossrsdpg_192balanced = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.13.2");
//    /** 1.3.6.1.4.1.62245.2.1.14.2 OQS_OID_CROSSRSDPG192FAST */
//    ASN1ObjectIdentifier crossrsdpg_192fast = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.14.2");
//    /** 1.3.6.1.4.1.62245.2.1.15.2 OQS_OID_CROSSRSDPG192SMALL */
//    ASN1ObjectIdentifier crossrsdpg_192small = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.15.2");
//    /** 1.3.6.1.4.1.62245.2.1.16.2 OQS_OID_CROSSRSDPG256BALANCED */
//    ASN1ObjectIdentifier crossrsdpg_256balanced = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.16.2");
//    /** 1.3.6.1.4.1.62245.2.1.17.2 OQS_OID_CROSSRSDPG256FAST */
//    ASN1ObjectIdentifier crossrsdpg_256fast = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.17.2");
//    /** 1.3.6.1.4.1.62245.2.1.18.2 OQS_OID_CROSSRSDPG256SMALL */
//    ASN1ObjectIdentifier crossrsdpg_256small = new ASN1ObjectIdentifier("1.3.6.1.4.1.62245.2.1.18.2");

    /**
     * OV
     * */
//    /** 1.3.9999.9.1.1 OQS_OID_OV_IS */
//    ASN1ObjectIdentifier ov_is = new ASN1ObjectIdentifier("1.3.9999.9.1.1");
//    /** 1.3.9999.9.1.2 OQS_OID_P256_OV_IS */
//    ASN1ObjectIdentifier p256_ov_is = new ASN1ObjectIdentifier("1.3.9999.9.1.2");
//    /** 1.3.9999.9.2.1 OQS_OID_OV_IP */
//    ASN1ObjectIdentifier ov_ip = new ASN1ObjectIdentifier("1.3.9999.9.2.1");
//    /** 1.3.9999.9.2.2 OQS_OID_P256_OV_IP */
//    ASN1ObjectIdentifier p256_ov_ip = new ASN1ObjectIdentifier("1.3.9999.9.2.2");
//    /** 1.3.9999.9.3.1 OQS_OID_OV_III */
//    ASN1ObjectIdentifier ov_iii = new ASN1ObjectIdentifier("1.3.9999.9.3.1");
//    /** 1.3.9999.9.3.2 OQS_OID_P384_OV_III */
//    ASN1ObjectIdentifier p384_ov_iii = new ASN1ObjectIdentifier("1.3.9999.9.3.2");
//    /** 1.3.9999.9.4.1 OQS_OID_OV_V */
//    ASN1ObjectIdentifier ov_v = new ASN1ObjectIdentifier("1.3.9999.9.4.1");
//    /** 1.3.9999.9.4.2 OQS_OID_P521_OV_V */
//    ASN1ObjectIdentifier p521_ov_v = new ASN1ObjectIdentifier("1.3.9999.9.4.2");
//    /** 1.3.9999.9.5.1 OQS_OID_OV_IS_PKC */
//    ASN1ObjectIdentifier ov_is_pkc = new ASN1ObjectIdentifier("1.3.9999.9.5.1");
//    /** 1.3.9999.9.5.2 OQS_OID_P256_OV_IS_PKC */
//    ASN1ObjectIdentifier p256_ov_is_pkc = new ASN1ObjectIdentifier("1.3.9999.9.5.2");
//    /** 1.3.9999.9.6.1 OQS_OID_OV_IP_PKC */
//    ASN1ObjectIdentifier ov_ip_pkc = new ASN1ObjectIdentifier("1.3.9999.9.6.1");
//    /** 1.3.9999.9.6.2 OQS_OID_P256_OV_IP_PKC */
//    ASN1ObjectIdentifier p256_ov_ip_pkc = new ASN1ObjectIdentifier("1.3.9999.9.6.2");
//    /** 1.3.9999.9.7.1 OQS_OID_OV_III_PKC */
//    ASN1ObjectIdentifier ov_iii_pkc = new ASN1ObjectIdentifier("1.3.9999.9.7.1");
//    /** 1.3.9999.9.7.2 OQS_OID_P384_OV_III_PKC */
//    ASN1ObjectIdentifier p384_ov_iii_pkc = new ASN1ObjectIdentifier("1.3.9999.9.7.2");
//    /** 1.3.9999.9.8.1 OQS_OID_OV_V_PKC */
//    ASN1ObjectIdentifier ov_v_pkc = new ASN1ObjectIdentifier("1.3.9999.9.8.1");
//    /** 1.3.9999.9.8.2 OQS_OID_P521_OV_V_PKC */
//    ASN1ObjectIdentifier p521_ov_v_pkc = new ASN1ObjectIdentifier("1.3.9999.9.8.2");
//    /** 1.3.9999.9.9.1 OQS_OID_OV_IS_PKC_SKC */
//    ASN1ObjectIdentifier ov_is_pkc_skc = new ASN1ObjectIdentifier("1.3.9999.9.9.1");
//    /** 1.3.9999.9.9.2 OQS_OID_P256_OV_IS_PKC_SKC */
//    ASN1ObjectIdentifier p256_ov_is_pkc_skc = new ASN1ObjectIdentifier("1.3.9999.9.9.2");
//    /** 1.3.9999.9.10.1 OQS_OID_OV_IP_PKC_SKC */
//    ASN1ObjectIdentifier ov_ip_pkc_skc = new ASN1ObjectIdentifier("1.3.9999.9.10.1");
//    /** 1.3.9999.9.10.2 OQS_OID_P256_OV_IP_PKC_SKC */
//    ASN1ObjectIdentifier p256_ov_ip_pkc_skc = new ASN1ObjectIdentifier("1.3.9999.9.10.2");
//    /** 1.3.9999.9.11.1 OQS_OID_OV_III_PKC_SKC */
//    ASN1ObjectIdentifier ov_iii_pkc_skc = new ASN1ObjectIdentifier("1.3.9999.9.11.1");
//    /** 1.3.9999.9.11.2 OQS_OID_P384_OV_III_PKC_SKC */
//    ASN1ObjectIdentifier p384_ov_iii_pkc_skc = new ASN1ObjectIdentifier("1.3.9999.9.11.2");
//    /** 1.3.9999.9.12.1 OQS_OID_OV_V_PKC_SKC */
//    ASN1ObjectIdentifier ov_v_pkc_skc = new ASN1ObjectIdentifier("1.3.9999.9.12.1");
//    /** 1.3.9999.9.12.2 OQS_OID_P521_OV_V_PKC_SKC */
//    ASN1ObjectIdentifier p521_ov_v_pkc_skc = new ASN1ObjectIdentifier("1.3.9999.9.12.2");

    /**
     * Snova
     */
    ASN1ObjectIdentifier snova = bc_sig.branch("11");
    ASN1ObjectIdentifier snova_24_5_4_ssk = snova.branch("1");
    ASN1ObjectIdentifier snova_24_5_4_esk = snova.branch("2");
    ASN1ObjectIdentifier snova_24_5_4_shake_ssk = snova.branch("3");
    ASN1ObjectIdentifier snova_24_5_4_shake_esk = snova.branch("4");
    ASN1ObjectIdentifier snova_24_5_5_ssk = snova.branch("5");
    ASN1ObjectIdentifier snova_24_5_5_esk = snova.branch("6");
    ASN1ObjectIdentifier snova_24_5_5_shake_ssk = snova.branch("7");
    ASN1ObjectIdentifier snova_24_5_5_shake_esk = snova.branch("8");
    ASN1ObjectIdentifier snova_25_8_3_ssk = snova.branch("9");
    ASN1ObjectIdentifier snova_25_8_3_esk = snova.branch("10");
    ASN1ObjectIdentifier snova_25_8_3_shake_ssk = snova.branch("11");
    ASN1ObjectIdentifier snova_25_8_3_shake_esk = snova.branch("12");
    ASN1ObjectIdentifier snova_29_6_5_ssk = snova.branch("13");
    ASN1ObjectIdentifier snova_29_6_5_esk = snova.branch("14");
    ASN1ObjectIdentifier snova_29_6_5_shake_ssk = snova.branch("15");
    ASN1ObjectIdentifier snova_29_6_5_shake_esk = snova.branch("16");
    ASN1ObjectIdentifier snova_37_8_4_ssk = snova.branch("17");
    ASN1ObjectIdentifier snova_37_8_4_esk = snova.branch("18");
    ASN1ObjectIdentifier snova_37_8_4_shake_ssk = snova.branch("19");
    ASN1ObjectIdentifier snova_37_8_4_shake_esk = snova.branch("20");
    ASN1ObjectIdentifier snova_37_17_2_ssk = snova.branch("21");
    ASN1ObjectIdentifier snova_37_17_2_esk = snova.branch("22");
    ASN1ObjectIdentifier snova_37_17_2_shake_ssk = snova.branch("23");
    ASN1ObjectIdentifier snova_37_17_2_shake_esk = snova.branch("24");
    ASN1ObjectIdentifier snova_49_11_3_ssk = snova.branch("25");
    ASN1ObjectIdentifier snova_49_11_3_esk = snova.branch("26");
    ASN1ObjectIdentifier snova_49_11_3_shake_ssk = snova.branch("27");
    ASN1ObjectIdentifier snova_49_11_3_shake_esk = snova.branch("28");
    ASN1ObjectIdentifier snova_56_25_2_ssk = snova.branch("29");
    ASN1ObjectIdentifier snova_56_25_2_esk = snova.branch("30");
    ASN1ObjectIdentifier snova_56_25_2_shake_ssk = snova.branch("31");
    ASN1ObjectIdentifier snova_56_25_2_shake_esk = snova.branch("32");
    ASN1ObjectIdentifier snova_60_10_4_ssk = snova.branch("33");
    ASN1ObjectIdentifier snova_60_10_4_esk = snova.branch("34");
    ASN1ObjectIdentifier snova_60_10_4_shake_ssk = snova.branch("35");
    ASN1ObjectIdentifier snova_60_10_4_shake_esk = snova.branch("36");
    ASN1ObjectIdentifier snova_66_15_3_ssk = snova.branch("37");
    ASN1ObjectIdentifier snova_66_15_3_esk = snova.branch("38");
    ASN1ObjectIdentifier snova_66_15_3_shake_ssk = snova.branch("39");
    ASN1ObjectIdentifier snova_66_15_3_shake_esk = snova.branch("40");
    ASN1ObjectIdentifier snova_75_33_2_ssk = snova.branch("41");
    ASN1ObjectIdentifier snova_75_33_2_esk = snova.branch("42");
    ASN1ObjectIdentifier snova_75_33_2_shake_ssk = snova.branch("43");
    ASN1ObjectIdentifier snova_75_33_2_shake_esk = snova.branch("44");

    /**
     * FAEST &mdash; symmetric-primitive signature scheme based on AES and the
     * VOLE-in-the-Head proof system. See
     * <a href="https://csrc.nist.gov/projects/pqc-dig-sig/round-3-additional-signatures">
     * NIST PQC additional signatures Round 3</a> and the FAEST team's specification
     * (<a href="https://faest.info/faest-spec-v2.0.pdf">FAEST v2.0</a>).
     * <p>
     * Twelve parameter sets per the v2.0 spec: six base FAEST variants ({128,192,256}-bit
     * security in "small signature" (s) and "fast signing" (f) trade-offs) and six
     * FAEST-EM (Even-Mansour) variants over the same security/trade-off matrix.
     * <p>
     * No OQS-tracked OIDs are defined here because the upstream
     * <a href="https://github.com/open-quantum-safe/liboqs">liboqs</a> /
     * <a href="https://github.com/open-quantum-safe/oqs-provider">oqs-provider</a> did
     * not have FAEST integrated as of the bcjava 1.85 cycle. If OQS publishes
     * 1.3.9999.* identifiers for FAEST, add them as additional commented constants
     * alongside the BC-arc identifiers below (cf. the {@link #mayo_1} / {@link #mayo1}
     * dual-arc precedent in the Mayo block).
     */
    ASN1ObjectIdentifier faest = bc_sig.branch("12");

    ASN1ObjectIdentifier faest_128s = faest.branch("1");
    ASN1ObjectIdentifier faest_128f = faest.branch("2");
    ASN1ObjectIdentifier faest_192s = faest.branch("3");
    ASN1ObjectIdentifier faest_192f = faest.branch("4");
    ASN1ObjectIdentifier faest_256s = faest.branch("5");
    ASN1ObjectIdentifier faest_256f = faest.branch("6");

    ASN1ObjectIdentifier faest_em_128s = faest.branch("7");
    ASN1ObjectIdentifier faest_em_128f = faest.branch("8");
    ASN1ObjectIdentifier faest_em_192s = faest.branch("9");
    ASN1ObjectIdentifier faest_em_192f = faest.branch("10");
    ASN1ObjectIdentifier faest_em_256s = faest.branch("11");
    ASN1ObjectIdentifier faest_em_256f = faest.branch("12");


    /**
     * MQOM v2.1 ("MQ on my Mind"). BC-allocated arc pending NIST OID assignment.
     * 36 child OIDs follow the canonical naming
     * {@code mqom2_&lt;category&gt;_&lt;base-field&gt;_&lt;trade-off&gt;_&lt;variant&gt;}
     * with category in {cat1, cat3, cat5}, base-field in {gf2, gf16, gf256},
     * trade-off in {fast, short}, variant in {r3, r5}.
     */
    ASN1ObjectIdentifier mqom = bc_sig.branch("13");
    ASN1ObjectIdentifier mqom2_cat1_gf2_fast_r3      = mqom.branch("1");
    ASN1ObjectIdentifier mqom2_cat1_gf2_fast_r5      = mqom.branch("2");
    ASN1ObjectIdentifier mqom2_cat1_gf2_short_r3     = mqom.branch("3");
    ASN1ObjectIdentifier mqom2_cat1_gf2_short_r5     = mqom.branch("4");
    ASN1ObjectIdentifier mqom2_cat1_gf16_fast_r3     = mqom.branch("5");
    ASN1ObjectIdentifier mqom2_cat1_gf16_fast_r5     = mqom.branch("6");
    ASN1ObjectIdentifier mqom2_cat1_gf16_short_r3    = mqom.branch("7");
    ASN1ObjectIdentifier mqom2_cat1_gf16_short_r5    = mqom.branch("8");
    ASN1ObjectIdentifier mqom2_cat1_gf256_fast_r3    = mqom.branch("9");
    ASN1ObjectIdentifier mqom2_cat1_gf256_fast_r5    = mqom.branch("10");
    ASN1ObjectIdentifier mqom2_cat1_gf256_short_r3   = mqom.branch("11");
    ASN1ObjectIdentifier mqom2_cat1_gf256_short_r5   = mqom.branch("12");
    ASN1ObjectIdentifier mqom2_cat3_gf2_fast_r3      = mqom.branch("13");
    ASN1ObjectIdentifier mqom2_cat3_gf2_fast_r5      = mqom.branch("14");
    ASN1ObjectIdentifier mqom2_cat3_gf2_short_r3     = mqom.branch("15");
    ASN1ObjectIdentifier mqom2_cat3_gf2_short_r5     = mqom.branch("16");
    ASN1ObjectIdentifier mqom2_cat3_gf16_fast_r3     = mqom.branch("17");
    ASN1ObjectIdentifier mqom2_cat3_gf16_fast_r5     = mqom.branch("18");
    ASN1ObjectIdentifier mqom2_cat3_gf16_short_r3    = mqom.branch("19");
    ASN1ObjectIdentifier mqom2_cat3_gf16_short_r5    = mqom.branch("20");
    ASN1ObjectIdentifier mqom2_cat3_gf256_fast_r3    = mqom.branch("21");
    ASN1ObjectIdentifier mqom2_cat3_gf256_fast_r5    = mqom.branch("22");
    ASN1ObjectIdentifier mqom2_cat3_gf256_short_r3   = mqom.branch("23");
    ASN1ObjectIdentifier mqom2_cat3_gf256_short_r5   = mqom.branch("24");
    ASN1ObjectIdentifier mqom2_cat5_gf2_fast_r3      = mqom.branch("25");
    ASN1ObjectIdentifier mqom2_cat5_gf2_fast_r5      = mqom.branch("26");
    ASN1ObjectIdentifier mqom2_cat5_gf2_short_r3     = mqom.branch("27");
    ASN1ObjectIdentifier mqom2_cat5_gf2_short_r5     = mqom.branch("28");
    ASN1ObjectIdentifier mqom2_cat5_gf16_fast_r3     = mqom.branch("29");
    ASN1ObjectIdentifier mqom2_cat5_gf16_fast_r5     = mqom.branch("30");
    ASN1ObjectIdentifier mqom2_cat5_gf16_short_r3    = mqom.branch("31");
    ASN1ObjectIdentifier mqom2_cat5_gf16_short_r5    = mqom.branch("32");
    ASN1ObjectIdentifier mqom2_cat5_gf256_fast_r3    = mqom.branch("33");
    ASN1ObjectIdentifier mqom2_cat5_gf256_fast_r5    = mqom.branch("34");
    ASN1ObjectIdentifier mqom2_cat5_gf256_short_r3   = mqom.branch("35");
    ASN1ObjectIdentifier mqom2_cat5_gf256_short_r5   = mqom.branch("36");

    /**
     * UOV (Unbalanced Oil and Vinegar). BC-allocated arc pending NIST OID
     * assignment from the additional-signatures round of NIST's PQC
     * standardisation. Twelve child OIDs follow the canonical naming
     * {@code uov_&lt;security-level&gt;_&lt;encoding-variant&gt;} where
     * security-level is in {Is, Ip, III, V} and encoding-variant is in
     * {classic, pkc, pkc_skc}. See pqov reference implementation
     * (https://github.com/pqov/pqov) for the algorithm definitions.
     */
    ASN1ObjectIdentifier uov = bc_sig.branch("14");
    ASN1ObjectIdentifier uov_Is_classic   = uov.branch("1");
    ASN1ObjectIdentifier uov_Is_pkc       = uov.branch("2");
    ASN1ObjectIdentifier uov_Is_pkc_skc   = uov.branch("3");
    ASN1ObjectIdentifier uov_Ip_classic   = uov.branch("4");
    ASN1ObjectIdentifier uov_Ip_pkc       = uov.branch("5");
    ASN1ObjectIdentifier uov_Ip_pkc_skc   = uov.branch("6");
    ASN1ObjectIdentifier uov_III_classic  = uov.branch("7");
    ASN1ObjectIdentifier uov_III_pkc      = uov.branch("8");
    ASN1ObjectIdentifier uov_III_pkc_skc  = uov.branch("9");
    ASN1ObjectIdentifier uov_V_classic    = uov.branch("10");
    ASN1ObjectIdentifier uov_V_pkc        = uov.branch("11");
    ASN1ObjectIdentifier uov_V_pkc_skc    = uov.branch("12");

    /**
     * SQIsign (Short Quaternion and Isogeny Signature). BC-allocated arc
     * pending NIST OID assignment from the additional-signatures round of
     * NIST's PQC standardisation. Three child OIDs follow the canonical
     * NIST-API parameter-set naming {@code sqisign_lvl&lt;n&gt;} with
     * n in {1, 3, 5}.
     */
    ASN1ObjectIdentifier sqisign       = bc_sig.branch("19");
    ASN1ObjectIdentifier sqisign_lvl1  = sqisign.branch("1");
    ASN1ObjectIdentifier sqisign_lvl3  = sqisign.branch("2");
    ASN1ObjectIdentifier sqisign_lvl5  = sqisign.branch("3");

    /**
     * HAETAE &mdash; lattice-based signature scheme submitted to the
     * KpqC (Korean Post-Quantum Cryptography) standardisation effort. See
     * <a href="https://kpqc.or.kr">KpqC</a> and the HAETAE team's
     * specification document.
     * <p>
     * Three parameter sets are provided: HAETAE-2 (NIST level 2), HAETAE-3
     * (NIST level 3) and HAETAE-5 (NIST level 5).
     */
    ASN1ObjectIdentifier haetae = bc_sig.branch("18");

    ASN1ObjectIdentifier haetae2 = haetae.branch("1");
    ASN1ObjectIdentifier haetae3 = haetae.branch("2");
    ASN1ObjectIdentifier haetae5 = haetae.branch("3");

    /**
     * NTRU+
     * */
    ASN1ObjectIdentifier pqc_kem_ntruplus = bc_kem.branch("10");
    ASN1ObjectIdentifier ntruplus768 = pqc_kem_ntruplus.branch("1");
    ASN1ObjectIdentifier ntruplus864 = pqc_kem_ntruplus.branch("2");
    ASN1ObjectIdentifier ntruplus1152 = pqc_kem_ntruplus.branch("3");

    /**
     * Hawk PQC signature scheme — parent arc and the three parameter-set OIDs
     * (hawk-256, hawk-512, hawk-1024).
     */
    ASN1ObjectIdentifier hawk = bc_sig.branch("15");
    ASN1ObjectIdentifier hawk256 = hawk.branch("1");
    ASN1ObjectIdentifier hawk512 = hawk.branch("2");
    ASN1ObjectIdentifier hawk1024 = hawk.branch("3");

    /**
     * SDitH (Syndrome-Decoding-in-the-Head). BC-allocated arc pending NIST OID
     * assignment. The Round-2 submission defines 12 variants formed from the
     * cross of {hypercube, threshold} × {cat1, cat3, cat5} × {gf256, p251};
     * all 12 are wired in. Branches are assigned in canonical order:
     * hypercube cat1/3/5 gf256 = .1/.2/.3, hypercube cat1/3/5 p251 = .4/.5/.6,
     * threshold cat1/3/5 gf256 = .7/.8/.9, threshold cat1/3/5 p251 = .10/.11/.12.
     */
    ASN1ObjectIdentifier sdith = bc_sig.branch("16");
    ASN1ObjectIdentifier sdith_hypercube_cat1_gf256 = sdith.branch("1");
    ASN1ObjectIdentifier sdith_hypercube_cat3_gf256 = sdith.branch("2");
    ASN1ObjectIdentifier sdith_hypercube_cat5_gf256 = sdith.branch("3");
    ASN1ObjectIdentifier sdith_hypercube_cat1_p251  = sdith.branch("4");
    ASN1ObjectIdentifier sdith_hypercube_cat3_p251  = sdith.branch("5");
    ASN1ObjectIdentifier sdith_hypercube_cat5_p251  = sdith.branch("6");
    ASN1ObjectIdentifier sdith_threshold_cat1_gf256 = sdith.branch("7");
    ASN1ObjectIdentifier sdith_threshold_cat3_gf256 = sdith.branch("8");
    ASN1ObjectIdentifier sdith_threshold_cat5_gf256 = sdith.branch("9");
    ASN1ObjectIdentifier sdith_threshold_cat1_p251  = sdith.branch("10");
    ASN1ObjectIdentifier sdith_threshold_cat3_p251  = sdith.branch("11");
    ASN1ObjectIdentifier sdith_threshold_cat5_p251  = sdith.branch("12");

    /**
     * QR-UOV &mdash; multivariate signature scheme based on quotient-ring UOV.
     * Round 2 submission to the NIST PQC additional signatures process.
     * <p>
     * Twelve parameter sets covering NIST security categories 1/3/5 with various
     * (q, L, v, m) combinations.
     */
    ASN1ObjectIdentifier qruov = bc_sig.branch("17");

    ASN1ObjectIdentifier qruov1q127L3v156m54 = qruov.branch("1");
    ASN1ObjectIdentifier qruov1q31L3v165m60 = qruov.branch("2");
    ASN1ObjectIdentifier qruov1q31L10v600m70 = qruov.branch("3");
    ASN1ObjectIdentifier qruov1q7L10v740m100 = qruov.branch("4");
    ASN1ObjectIdentifier qruov3q127L3v228m78 = qruov.branch("5");
    ASN1ObjectIdentifier qruov3q31L3v246m87 = qruov.branch("6");
    ASN1ObjectIdentifier qruov3q31L10v890m100 = qruov.branch("7");
    ASN1ObjectIdentifier qruov3q7L10v1100m140 = qruov.branch("8");
    ASN1ObjectIdentifier qruov5q127L3v306m105 = qruov.branch("9");
    ASN1ObjectIdentifier qruov5q31L3v324m114 = qruov.branch("10");
    ASN1ObjectIdentifier qruov5q31L10v1120m120 = qruov.branch("11");
    ASN1ObjectIdentifier qruov5q7L10v1490m190 = qruov.branch("12");
}
