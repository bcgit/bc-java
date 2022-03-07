package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class TlmLinkCertificateMessage
    extends EtsiTs103097DataSigned
{

    public TlmLinkCertificateMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected TlmLinkCertificateMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static TlmLinkCertificateMessage getInstance(Object o)
    {
        if (o instanceof TlmLinkCertificateMessage)
        {
            return (TlmLinkCertificateMessage)o;
        }
        if (o != null)
        {
            return new TlmLinkCertificateMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
