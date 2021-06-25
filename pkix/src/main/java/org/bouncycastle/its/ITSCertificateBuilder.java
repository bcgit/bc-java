package org.bouncycastle.its;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.its.ToBeSignedCertificate;

public class ITSCertificateBuilder
{

    protected final ToBeSignedCertificate.Builder tbsCertificateBuilder;
    private ASN1Integer version = new ASN1Integer(3);

    // TODO: temp constructor to get signing working.
    public ITSCertificateBuilder(ToBeSignedCertificate.Builder tbsCertificateBuilder)
    {
        this.tbsCertificateBuilder = tbsCertificateBuilder;
    }


    public ITSCertificateBuilder setVersion(ASN1Integer version)
    {
        this.version = version;
        return this;
    }


}
