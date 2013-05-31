package org.bouncycastle.asn1.dvcs;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface DVCSObjectIdentifiers
{

    //    id-pkix     OBJECT IDENTIFIER ::= {iso(1)
    //                   identified-organization(3) dod(6)
    //                   internet(1) security(5) mechanisms(5) pkix(7)}
    //
    //    id-smime    OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    //                   us(840) rsadsi(113549) pkcs(1) pkcs-9(9) 16 }
    public static final ASN1ObjectIdentifier id_pkix = new ASN1ObjectIdentifier("1.3.6.1.5.5.7");
    public static final ASN1ObjectIdentifier id_smime = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16");

    //    -- Authority Information Access for DVCS
    //
    //    id-ad-dvcs  OBJECT IDENTIFIER ::= {id-pkix id-ad(48) 4}
    public static final ASN1ObjectIdentifier id_ad_dvcs = id_pkix.branch("48.4");

    //    -- Key Purpose for DVCS
    //
    //    id-kp-dvcs  OBJECT IDENTIFIER ::= {id-pkix id-kp(3) 10}
    public static final ASN1ObjectIdentifier id_kp_dvcs = id_pkix.branch("3.10");

    //    id-ct-DVCSRequestData  OBJECT IDENTIFIER ::= { id-smime ct(1) 7 }
    //    id-ct-DVCSResponseData OBJECT IDENTIFIER ::= { id-smime ct(1) 8 }
    public static final ASN1ObjectIdentifier id_ct_DVCSRequestData = id_smime.branch("1.7");
    public static final ASN1ObjectIdentifier id_ct_DVCSResponseData = id_smime.branch("1.8");

    //    -- Data validation certificate attribute
    //
    //    id-aa-dvcs-dvc OBJECT IDENTIFIER ::= { id-smime aa(2) 29 }
    public static final ASN1ObjectIdentifier id_aa_dvcs_dvc = id_smime.branch("2.29");
}
