package org.bouncycastle.asn1.rosstandart;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface RosstandartObjectIdentifiers
{
    static final ASN1ObjectIdentifier rosstandart = new ASN1ObjectIdentifier("1.2.643.7");

    static final ASN1ObjectIdentifier id_tc26 = rosstandart.branch("1");

    static final ASN1ObjectIdentifier id_tc26_gost_3411_12_256 = id_tc26.branch("1.2.2");

    static final ASN1ObjectIdentifier id_tc26_gost_3411_12_512 = id_tc26.branch("1.2.3");

    static final ASN1ObjectIdentifier id_tc26_hmac_gost_3411_12_256 = id_tc26.branch("1.4.1");

    static final ASN1ObjectIdentifier id_tc26_hmac_gost_3411_12_512 = id_tc26.branch("1.4.2");

    static final ASN1ObjectIdentifier id_tc26_gost_3410_12_256 = id_tc26.branch("1.1.1");

    static final ASN1ObjectIdentifier id_tc26_gost_3410_12_512 = id_tc26.branch("1.1.2");

    static final ASN1ObjectIdentifier id_tc26_signwithdigest_gost_3410_12_256 = id_tc26.branch("1.3.2");

    static final ASN1ObjectIdentifier id_tc26_signwithdigest_gost_3410_12_512 = id_tc26.branch("1.3.3");

    static final ASN1ObjectIdentifier id_tc26_agreement = id_tc26.branch("1.6");

    static final ASN1ObjectIdentifier id_tc26_agreement_gost_3410_12_256 = id_tc26_agreement.branch("1");

    static final ASN1ObjectIdentifier id_tc26_agreement_gost_3410_12_512  = id_tc26_agreement.branch("2");

    static final ASN1ObjectIdentifier id_tc26_gost_3410_12_256_paramSet = id_tc26.branch("2.1.1");

    static final ASN1ObjectIdentifier id_tc26_gost_3410_12_256_paramSetA = id_tc26_gost_3410_12_256_paramSet.branch("1");

    static final ASN1ObjectIdentifier id_tc26_gost_3410_12_512_paramSet = id_tc26.branch("2.1.2");

    static final ASN1ObjectIdentifier id_tc26_gost_3410_12_512_paramSetA = id_tc26_gost_3410_12_512_paramSet.branch("1");

    static final ASN1ObjectIdentifier id_tc26_gost_3410_12_512_paramSetB = id_tc26_gost_3410_12_512_paramSet.branch("2");

    static final ASN1ObjectIdentifier id_tc26_gost_3410_12_512_paramSetC = id_tc26_gost_3410_12_512_paramSet.branch("3");

    static final ASN1ObjectIdentifier id_tc26_gost_28147_param_Z = id_tc26.branch("2.5.1.1");
}
