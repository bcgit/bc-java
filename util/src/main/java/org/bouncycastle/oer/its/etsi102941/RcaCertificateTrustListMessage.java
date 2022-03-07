package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class RcaCertificateTrustListMessage
    extends EtsiTs103097DataSigned
{

    public RcaCertificateTrustListMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected RcaCertificateTrustListMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static RcaCertificateTrustListMessage getInstance(Object o)
    {
        if (o instanceof RcaCertificateTrustListMessage)
        {
            return (RcaCertificateTrustListMessage)o;
        }
        if (o != null)
        {
            return new RcaCertificateTrustListMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
