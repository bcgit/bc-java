package org.bouncycastle.its;

import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.its.Duration;
import org.bouncycastle.oer.its.ToBeSignedCertificate;
import org.bouncycastle.oer.its.ValidityPeriod;

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
    public ITSCertificateBuilder setVersion(int version)
    {
        this.version = new ASN1Integer(version);
        return this;
    }

    public ITSCertificateBuilder setValidityPeriod(Date startDate, Duration duration)
    {
        tbsCertificateBuilder.setValidityPeriod(ValidityPeriod.builder()
            .setTime32(new ASN1Integer(startDate.getTime() / 1000))
            .setDuration(duration).createValidityPeriod());
        return this;
    }
}
