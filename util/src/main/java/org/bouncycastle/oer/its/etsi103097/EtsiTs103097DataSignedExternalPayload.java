package org.bouncycastle.oer.its.etsi103097;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class EtsiTs103097DataSignedExternalPayload
    extends EtsiTs103097Data
{
    public EtsiTs103097DataSignedExternalPayload(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected EtsiTs103097DataSignedExternalPayload(ASN1Sequence src)
    {
        super(src);
    }

    public static EtsiTs103097DataSignedExternalPayload getInstance(Object o)
    {
        if (o instanceof EtsiTs103097DataSignedExternalPayload)
        {
            return (EtsiTs103097DataSignedExternalPayload)o;
        }
        if (o != null)
        {
            return new EtsiTs103097DataSignedExternalPayload(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
