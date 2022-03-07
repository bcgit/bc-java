package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class RcaDoubleSignedLinkCertificateMessage
    extends EtsiTs103097DataSigned
{

    public RcaDoubleSignedLinkCertificateMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected RcaDoubleSignedLinkCertificateMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static RcaDoubleSignedLinkCertificateMessage getInstance(Object o)
    {
        if (o instanceof RcaDoubleSignedLinkCertificateMessage)
        {
            return (RcaDoubleSignedLinkCertificateMessage)o;
        }
        if (o != null)
        {
            return new RcaDoubleSignedLinkCertificateMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
