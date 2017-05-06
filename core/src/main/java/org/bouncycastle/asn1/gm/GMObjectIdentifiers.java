package org.bouncycastle.asn1.gm;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface GMObjectIdentifiers
{
    ASN1ObjectIdentifier sm_scheme = new ASN1ObjectIdentifier("1.2.156.10197.1");

    ASN1ObjectIdentifier sm6_ecb = sm_scheme.branch("101.1");
    ASN1ObjectIdentifier sm6_cbc = sm_scheme.branch("101.2");
    ASN1ObjectIdentifier sm6_ofb128 = sm_scheme.branch("101.3");
    ASN1ObjectIdentifier sm6_cfb128 = sm_scheme.branch("101.4");

    ASN1ObjectIdentifier sm1_ecb = sm_scheme.branch("102.1");
    ASN1ObjectIdentifier sm1_cbc = sm_scheme.branch("102.2");
    ASN1ObjectIdentifier sm1_ofb128 = sm_scheme.branch("102.3");
    ASN1ObjectIdentifier sm1_cfb128 = sm_scheme.branch("102.4");
    ASN1ObjectIdentifier sm1_cfb1 = sm_scheme.branch("102.5");
    ASN1ObjectIdentifier sm1_cfb8 = sm_scheme.branch("102.6");

    ASN1ObjectIdentifier ssf33_ecb = sm_scheme.branch("103.1");
    ASN1ObjectIdentifier ssf33_cbc = sm_scheme.branch("103.2");
    ASN1ObjectIdentifier ssf33_ofb128 = sm_scheme.branch("103.3");
    ASN1ObjectIdentifier ssf33_cfb128 = sm_scheme.branch("103.4");
    ASN1ObjectIdentifier ssf33_cfb1 = sm_scheme.branch("103.5");
    ASN1ObjectIdentifier ssf33_cfb8 = sm_scheme.branch("103.6");

    ASN1ObjectIdentifier sms4_ecb = sm_scheme.branch("104.1");
    ASN1ObjectIdentifier sms4_cbc = sm_scheme.branch("104.2");
    ASN1ObjectIdentifier sms4_ofb128 = sm_scheme.branch("104.3");
    ASN1ObjectIdentifier sms4_cfb128 = sm_scheme.branch("104.4");
    ASN1ObjectIdentifier sms4_cfb1 = sm_scheme.branch("104.5");
    ASN1ObjectIdentifier sms4_cfb8 = sm_scheme.branch("104.6");
    ASN1ObjectIdentifier sms4_ctr = sm_scheme.branch("104.7");
    ASN1ObjectIdentifier sms4_gcm = sm_scheme.branch("104.8");
    ASN1ObjectIdentifier sms4_ccm = sm_scheme.branch("104.9");
    ASN1ObjectIdentifier sms4_xts = sm_scheme.branch("104.10");
    ASN1ObjectIdentifier sms4_wrap = sm_scheme.branch("104.11");
    ASN1ObjectIdentifier sms4_wrap_pad = sm_scheme.branch("104.12");
    ASN1ObjectIdentifier sms4_ocb = sm_scheme.branch("104.100");

    ASN1ObjectIdentifier sm5 = sm_scheme.branch("201");

    ASN1ObjectIdentifier sm2p256v1 = sm_scheme.branch("301");
    ASN1ObjectIdentifier sm2sign = sm_scheme.branch("301.1");
    ASN1ObjectIdentifier sm2exchange = sm_scheme.branch("301.2");
    ASN1ObjectIdentifier sm2encrypt = sm_scheme.branch("301.3");

    ASN1ObjectIdentifier wapip192v1 = sm_scheme.branch("301.101");

    ASN1ObjectIdentifier sm2encrypt_recommendedParameters = sm2encrypt.branch("1");
    ASN1ObjectIdentifier sm2encrypt_specifiedParameters = sm2encrypt.branch("2");
    ASN1ObjectIdentifier sm2encrypt_with_sm3 = sm2encrypt.branch("2.1");
    ASN1ObjectIdentifier sm2encrypt_with_sha1 = sm2encrypt.branch("2.2");
    ASN1ObjectIdentifier sm2encrypt_with_sha224 = sm2encrypt.branch("2.3");
    ASN1ObjectIdentifier sm2encrypt_with_sha256 = sm2encrypt.branch("2.4");
    ASN1ObjectIdentifier sm2encrypt_with_sha384 = sm2encrypt.branch("2.5");
    ASN1ObjectIdentifier sm2encrypt_with_sha512 = sm2encrypt.branch("2.6");
    ASN1ObjectIdentifier sm2encrypt_with_rmd160 =  sm2encrypt.branch("2.7");
    ASN1ObjectIdentifier sm2encrypt_with_whirlpool =sm2encrypt.branch("2.8");
    ASN1ObjectIdentifier sm2encrypt_with_blake2b512 = sm2encrypt.branch("2.9");
    ASN1ObjectIdentifier sm2encrypt_with_blake2s256 = sm2encrypt.branch("2.10");
    ASN1ObjectIdentifier sm2encrypt_with_md5 = sm2encrypt.branch("2.11");

    ASN1ObjectIdentifier id_sm9PublicKey = sm_scheme.branch("302");
    ASN1ObjectIdentifier sm9sign = sm_scheme.branch("302.1");
    ASN1ObjectIdentifier sm9keyagreement = sm_scheme.branch("302.2");
    ASN1ObjectIdentifier sm9encrypt = sm_scheme.branch("302.3");

    ASN1ObjectIdentifier sm3 = sm_scheme.branch("401");

    ASN1ObjectIdentifier hmac_sm3 = sm3.branch("2");

    ASN1ObjectIdentifier sm2sign_with_sm3 = sm_scheme.branch("501");
    ASN1ObjectIdentifier sm2sign_with_sha1 = sm_scheme.branch("502");
    ASN1ObjectIdentifier sm2sign_with_sha256 = sm_scheme.branch("503");
    ASN1ObjectIdentifier sm2sign_with_sha512 = sm_scheme.branch("504");
    ASN1ObjectIdentifier sm2sign_with_sha224 = sm_scheme.branch("505");
    ASN1ObjectIdentifier sm2sign_with_sha384 = sm_scheme.branch("506");
    ASN1ObjectIdentifier sm2sign_with_rmd160 = sm_scheme.branch("507");
    ASN1ObjectIdentifier sm2sign_with_whirlpool = sm_scheme.branch("520");
    ASN1ObjectIdentifier sm2sign_with_blake2b512 = sm_scheme.branch("521");
    ASN1ObjectIdentifier sm2sign_with_blake2s256 = sm_scheme.branch("522");
}
