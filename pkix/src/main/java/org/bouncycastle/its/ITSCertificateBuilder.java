package org.bouncycastle.its;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.its.CrlSeries;

import org.bouncycastle.oer.its.HashedId3;
import org.bouncycastle.oer.its.PsidGroupPermissions;
import org.bouncycastle.oer.its.PsidSsp;
import org.bouncycastle.oer.its.SequenceOfPsidGroupPermissions;
import org.bouncycastle.oer.its.SequenceOfPsidSsp;
import org.bouncycastle.oer.its.ToBeSignedCertificate;

public class ITSCertificateBuilder
{
    protected final ToBeSignedCertificate.Builder tbsCertificateBuilder;
    protected final ITSCertificate issuer;

    protected ASN1Integer version = new ASN1Integer(3);
    //  ETSI TS 103 097 V1.4.1 (2020-10) default/constraint - Section 6.
    protected HashedId3 cracaId = new HashedId3(new byte[3]);
    //  ETSI TS 103 097 V1.4.1 (2020-10) default/constraint - Section 6.
    protected CrlSeries crlSeries = new CrlSeries(0);

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
        this.tbsCertificateBuilder.setCracaId(cracaId);
        this.tbsCertificateBuilder.setCrlSeries(crlSeries);
    }

    public ITSCertificate getIssuer()
    {
        return issuer;
    }

    /**
     * set the version - default value is 3.
     *
     * @param version certificate version.
     * @return the current builder.
     */
    public ITSCertificateBuilder setVersion(int version)
    {
        this.version = new ASN1Integer(version);
        return this;
    }

    /**
     * Set the cracaId. The default value for the field is 000000'H in line with ETSI TS 103 097 V1.4.1 (2020-10) default/constraint - Section 6.
     *
     * @param cracaId hashedId for the craca, the ID of the CRL manager.
     * @return the current builder.
     */
    public ITSCertificateBuilder setCracaId(byte[] cracaId)
    {
        this.cracaId = new HashedId3(cracaId);
        this.tbsCertificateBuilder.setCracaId(this.cracaId);

        return this;
    }

    /**
     * Set the crlSeries. The default value for the field is 0'D in line with ETSI TS 103 097 V1.4.1 (2020-10) default/constraint - Section 6.
     *
     * @param crlSeries id for the CRL series for revocation.
     * @return the current builder.
     */
    public ITSCertificateBuilder setCrlSeries(int crlSeries)
    {
        this.crlSeries = new CrlSeries(crlSeries);
        this.tbsCertificateBuilder.setCrlSeries(this.crlSeries);

        return this;
    }

    public ITSCertificateBuilder setValidityPeriod(ITSValidityPeriod validityPeriod)
    {
        tbsCertificateBuilder.setValidityPeriod(validityPeriod.toASN1Structure());

        return this;
    }
    
    public ITSCertificateBuilder setCertIssuePermissions(PsidGroupPermissions... permissions)
    {
        tbsCertificateBuilder.setCertIssuePermissions(
            SequenceOfPsidGroupPermissions.builder().addGroupPermission(permissions).createSequenceOfPsidGroupPermissions());

        return this;
    }

    public ITSCertificateBuilder setAppPermissions(PsidSsp... psidSsps)
    {
        SequenceOfPsidSsp.Builder bldr = SequenceOfPsidSsp.builder();

        for (int i = 0; i != psidSsps.length; i++)
        {
            bldr.setItem(psidSsps[i]);
        }

        tbsCertificateBuilder.setAppPermissions(bldr.createSequenceOfPsidSsp());

        return this;
    }
}
