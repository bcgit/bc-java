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

    ASN1ObjectIdentifier sphincsPlus_sha2_128f = new ASN1ObjectIdentifier("1.3.9999.6.4.13");
    ASN1ObjectIdentifier sphincsPlus_sha2_128s = new ASN1ObjectIdentifier("1.3.9999.6.4.16");
    ASN1ObjectIdentifier sphincsPlus_sha2_192f = new ASN1ObjectIdentifier("1.3.9999.6.5.10");
    ASN1ObjectIdentifier sphincsPlus_sha2_192s = new ASN1ObjectIdentifier("1.3.9999.6.5.12");
    ASN1ObjectIdentifier sphincsPlus_sha2_256f = new ASN1ObjectIdentifier("1.3.9999.6.6.10");
    ASN1ObjectIdentifier sphincsPlus_sha2_256s = new ASN1ObjectIdentifier("1.3.9999.6.6.12");

    ASN1ObjectIdentifier sphincsPlus_shake_128f = new ASN1ObjectIdentifier("1.3.9999.6.7.13");
    ASN1ObjectIdentifier sphincsPlus_shake_128s = new ASN1ObjectIdentifier("1.3.9999.6.7.16");
    ASN1ObjectIdentifier sphincsPlus_shake_192f = new ASN1ObjectIdentifier("1.3.9999.6.8.10");
    ASN1ObjectIdentifier sphincsPlus_shake_192s = new ASN1ObjectIdentifier("1.3.9999.6.8.12");
    ASN1ObjectIdentifier sphincsPlus_shake_256f = new ASN1ObjectIdentifier("1.3.9999.6.9.10");
    ASN1ObjectIdentifier sphincsPlus_shake_256s = new ASN1ObjectIdentifier("1.3.9999.6.9.12");

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

    ASN1ObjectIdentifier falcon_512 = new ASN1ObjectIdentifier("1.3.9999.3.1");  // falcon.branch("1");
    ASN1ObjectIdentifier falcon_1024 =  new ASN1ObjectIdentifier("1.3.9999.3.4"); // falcon.branch("2");

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
}
