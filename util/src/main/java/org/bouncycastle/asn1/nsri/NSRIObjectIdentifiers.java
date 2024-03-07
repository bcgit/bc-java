package org.bouncycastle.asn1.nsri;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface NSRIObjectIdentifiers
{
    ASN1ObjectIdentifier nsri = new ASN1ObjectIdentifier("1.2.410.200046");

    ASN1ObjectIdentifier id_algorithm = nsri.branch("1");

    ASN1ObjectIdentifier id_sea = id_algorithm.branch("1");
    ASN1ObjectIdentifier id_pad = id_algorithm.branch("2");

    ASN1ObjectIdentifier id_pad_null = id_algorithm.branch("0");
    ASN1ObjectIdentifier id_pad_1 = id_algorithm.branch("1");

    ASN1ObjectIdentifier id_aria128_ecb = id_sea.branch("1");
    ASN1ObjectIdentifier id_aria128_cbc = id_sea.branch("2");
    ASN1ObjectIdentifier id_aria128_cfb = id_sea.branch("3");
    ASN1ObjectIdentifier id_aria128_ofb = id_sea.branch("4");
    ASN1ObjectIdentifier id_aria128_ctr = id_sea.branch("5");

    ASN1ObjectIdentifier id_aria192_ecb = id_sea.branch("6");
    ASN1ObjectIdentifier id_aria192_cbc = id_sea.branch("7");
    ASN1ObjectIdentifier id_aria192_cfb = id_sea.branch("8");
    ASN1ObjectIdentifier id_aria192_ofb = id_sea.branch("9");
    ASN1ObjectIdentifier id_aria192_ctr = id_sea.branch("10");

    ASN1ObjectIdentifier id_aria256_ecb = id_sea.branch("11");
    ASN1ObjectIdentifier id_aria256_cbc = id_sea.branch("12");
    ASN1ObjectIdentifier id_aria256_cfb = id_sea.branch("13");
    ASN1ObjectIdentifier id_aria256_ofb = id_sea.branch("14");
    ASN1ObjectIdentifier id_aria256_ctr = id_sea.branch("15");

    ASN1ObjectIdentifier id_aria128_cmac = id_sea.branch("21");
    ASN1ObjectIdentifier id_aria192_cmac = id_sea.branch("22");
    ASN1ObjectIdentifier id_aria256_cmac = id_sea.branch("23");

    ASN1ObjectIdentifier id_aria128_ocb2 = id_sea.branch("31");
    ASN1ObjectIdentifier id_aria192_ocb2 = id_sea.branch("32");
    ASN1ObjectIdentifier id_aria256_ocb2 = id_sea.branch("33");

    ASN1ObjectIdentifier id_aria128_gcm = id_sea.branch("34");
    ASN1ObjectIdentifier id_aria192_gcm = id_sea.branch("35");
    ASN1ObjectIdentifier id_aria256_gcm = id_sea.branch("36");

    ASN1ObjectIdentifier id_aria128_ccm = id_sea.branch("37");
    ASN1ObjectIdentifier id_aria192_ccm = id_sea.branch("38");
    ASN1ObjectIdentifier id_aria256_ccm = id_sea.branch("39");

    ASN1ObjectIdentifier id_aria128_kw = id_sea.branch("40");
    ASN1ObjectIdentifier id_aria192_kw = id_sea.branch("41");
    ASN1ObjectIdentifier id_aria256_kw = id_sea.branch("42");

    ASN1ObjectIdentifier id_aria128_kwp = id_sea.branch("43");
    ASN1ObjectIdentifier id_aria192_kwp = id_sea.branch("44");
    ASN1ObjectIdentifier id_aria256_kwp = id_sea.branch("45");
}
