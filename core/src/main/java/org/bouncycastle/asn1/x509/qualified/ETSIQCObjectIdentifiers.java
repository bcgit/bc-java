package org.bouncycastle.asn1.x509.qualified;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface ETSIQCObjectIdentifiers
{
    static final ASN1ObjectIdentifier    id_etsi_qcs_QcCompliance     = new ASN1ObjectIdentifier("0.4.0.1862.1.1");
    static final ASN1ObjectIdentifier    id_etsi_qcs_LimiteValue      = new ASN1ObjectIdentifier("0.4.0.1862.1.2");
    static final ASN1ObjectIdentifier    id_etsi_qcs_RetentionPeriod  = new ASN1ObjectIdentifier("0.4.0.1862.1.3");
    static final ASN1ObjectIdentifier    id_etsi_qcs_QcSSCD           = new ASN1ObjectIdentifier("0.4.0.1862.1.4");

    static final ASN1ObjectIdentifier    id_etsi_qcs_QcPds = new ASN1ObjectIdentifier("0.4.0.1862.1.5");

    static final ASN1ObjectIdentifier    id_etsi_qcs_QcType = new ASN1ObjectIdentifier("0.4.0.1862.1.6");
    static final ASN1ObjectIdentifier    id_etsi_qct_esign = id_etsi_qcs_QcType.branch("1");
    static final ASN1ObjectIdentifier    id_etsi_qct_eseal = id_etsi_qcs_QcType.branch("2");
    static final ASN1ObjectIdentifier    id_etsi_qct_web = id_etsi_qcs_QcType.branch("3");
}
