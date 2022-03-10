package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.HashedData;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;

public class ToBeSignedLinkCertificateRca
    extends ToBeSignedLinkCertificate
{
    public ToBeSignedLinkCertificateRca(Time32 expiryTime, HashedData certificateHash)
    {
        super(expiryTime, certificateHash);
    }

    protected ToBeSignedLinkCertificateRca(ASN1Sequence seq)
    {
        super(seq);
    }

    private ToBeSignedLinkCertificateRca(ToBeSignedLinkCertificate cert)
    {
        super(cert.getExpiryTime(), cert.getCertificateHash());
    }


    public static ToBeSignedLinkCertificateRca getInstance(Object o)
    {
        if (o instanceof ToBeSignedLinkCertificateRca)
        {
            return (ToBeSignedLinkCertificateRca)o;
        }

        if (o instanceof ToBeSignedLinkCertificate)
        {
            return new ToBeSignedLinkCertificateRca((ToBeSignedLinkCertificate)o);
        }

        if (o != null)
        {
            return new ToBeSignedLinkCertificateRca(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
