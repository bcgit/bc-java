package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSignedAndEncryptedUnicast;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class EnrolmentResponseMessage
    extends EtsiTs103097DataSignedAndEncryptedUnicast
{

    public EnrolmentResponseMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected EnrolmentResponseMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static EnrolmentResponseMessage getInstance(Object o)
    {
        if (o instanceof EnrolmentResponseMessage)
        {
            return (EnrolmentResponseMessage)o;
        }
        if (o != null)
        {
            return new EnrolmentResponseMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
