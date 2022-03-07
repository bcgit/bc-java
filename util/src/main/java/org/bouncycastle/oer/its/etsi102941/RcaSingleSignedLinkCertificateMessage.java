package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class RcaSingleSignedLinkCertificateMessage
    extends EtsiTs103097DataSigned
{

    public RcaSingleSignedLinkCertificateMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected RcaSingleSignedLinkCertificateMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static RcaSingleSignedLinkCertificateMessage getInstance(Object o)
    {
        if (o instanceof RcaSingleSignedLinkCertificateMessage)
        {
            return (RcaSingleSignedLinkCertificateMessage)o;
        }
        if (o != null)
        {
            return new RcaSingleSignedLinkCertificateMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
