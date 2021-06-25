package org.bouncycastle.its;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.its.ToBeSignedCertificate;

public class ITSCertificateBuilder
{
    protected final ToBeSignedCertificate.Builder tbsCertificateBuilder;
    protected final ITSCertificate issuer;
    protected ASN1Integer version = new ASN1Integer(3);

    // TODO: temp constructor to get signing working - self signed
    public ITSCertificateBuilder(ToBeSignedCertificate.Builder tbsCertificateBuilder)
    {
        this(null, tbsCertificateBuilder);
    }

    // TODO: temp constructor to get signing working - non self signed
    public ITSCertificateBuilder(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificateBuilder)
    {
        this.issuer = issuer;
        this.tbsCertificateBuilder = tbsCertificateBuilder;
    }

    public ITSCertificate getIssuer()
    {
        return issuer;
    }
    
    /**
     * set the version - default value is 3.
     *
     * @param version  certificate version.
     * @return  the current builder.
     */
    public ITSCertificateBuilder setVersion(ASN1Integer version)
    {
        this.version = version;
        return this;
    }
}
