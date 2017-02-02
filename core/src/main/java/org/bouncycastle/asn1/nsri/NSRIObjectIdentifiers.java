package org.bouncycastle.asn1.nsri;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface NSRIObjectIdentifiers
{
    static final ASN1ObjectIdentifier   nsri                = new ASN1ObjectIdentifier("1.2.410.200046");

    static final ASN1ObjectIdentifier   id_algorithm        = nsri.branch("1");

    static final ASN1ObjectIdentifier   id_sea              = id_algorithm.branch("1");
    static final ASN1ObjectIdentifier   id_pad              = id_algorithm.branch("2");

    static final ASN1ObjectIdentifier   id_pad_null         = id_algorithm.branch("0");
    static final ASN1ObjectIdentifier   id_pad_1            = id_algorithm.branch("1");

    static final ASN1ObjectIdentifier   id_aria128_ecb      = id_sea.branch("1");
    static final ASN1ObjectIdentifier   id_aria128_cbc      = id_sea.branch("2");
    static final ASN1ObjectIdentifier   id_aria128_cfb      = id_sea.branch("3");
    static final ASN1ObjectIdentifier   id_aria128_ofb      = id_sea.branch("4");
    static final ASN1ObjectIdentifier   id_aria128_ctr      = id_sea.branch("5");

    static final ASN1ObjectIdentifier   id_aria192_ecb      = id_sea.branch("6");
    static final ASN1ObjectIdentifier   id_aria192_cbc      = id_sea.branch("7");
    static final ASN1ObjectIdentifier   id_aria192_cfb      = id_sea.branch("8");
    static final ASN1ObjectIdentifier   id_aria192_ofb      = id_sea.branch("9");
    static final ASN1ObjectIdentifier   id_aria192_ctr      = id_sea.branch("10");

    static final ASN1ObjectIdentifier   id_aria256_ecb      = id_sea.branch("11");
    static final ASN1ObjectIdentifier   id_aria256_cbc      = id_sea.branch("12");
    static final ASN1ObjectIdentifier   id_aria256_cfb      = id_sea.branch("13");
    static final ASN1ObjectIdentifier   id_aria256_ofb      = id_sea.branch("14");
    static final ASN1ObjectIdentifier   id_aria256_ctr      = id_sea.branch("15");

    static final ASN1ObjectIdentifier   id_aria128_cmac     = id_sea.branch("21");
    static final ASN1ObjectIdentifier   id_aria192_cmac     = id_sea.branch("22");
    static final ASN1ObjectIdentifier   id_aria256_cmac     = id_sea.branch("23");

    static final ASN1ObjectIdentifier   id_aria128_ocb2     = id_sea.branch("31");
    static final ASN1ObjectIdentifier   id_aria192_ocb2     = id_sea.branch("32");
    static final ASN1ObjectIdentifier   id_aria256_ocb2     = id_sea.branch("33");

    static final ASN1ObjectIdentifier   id_aria128_gcm      = id_sea.branch("34");
    static final ASN1ObjectIdentifier   id_aria192_gcm      = id_sea.branch("35");
    static final ASN1ObjectIdentifier   id_aria256_gcm      = id_sea.branch("36");

    static final ASN1ObjectIdentifier   id_aria128_ccm      = id_sea.branch("37");
    static final ASN1ObjectIdentifier   id_aria192_ccm      = id_sea.branch("38");
    static final ASN1ObjectIdentifier   id_aria256_ccm      = id_sea.branch("39");

    static final ASN1ObjectIdentifier   id_aria128_kw       = id_sea.branch("40");
    static final ASN1ObjectIdentifier   id_aria192_kw       = id_sea.branch("41");
    static final ASN1ObjectIdentifier   id_aria256_kw       = id_sea.branch("42");

    static final ASN1ObjectIdentifier   id_aria128_kwp      = id_sea.branch("43");
    static final ASN1ObjectIdentifier   id_aria192_kwp      = id_sea.branch("44");
    static final ASN1ObjectIdentifier   id_aria256_kwp      = id_sea.branch("45");
}
