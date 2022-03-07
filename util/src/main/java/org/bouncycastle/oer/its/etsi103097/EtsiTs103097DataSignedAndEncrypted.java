package org.bouncycastle.oer.its.etsi103097;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class EtsiTs103097DataSignedAndEncrypted
    extends EtsiTs103097Data
{
    public EtsiTs103097DataSignedAndEncrypted(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected EtsiTs103097DataSignedAndEncrypted(ASN1Sequence src)
    {
        super(src);
    }

    public static EtsiTs103097DataSignedAndEncrypted getInstance(Object o)
    {
        if (o instanceof EtsiTs103097DataSignedAndEncrypted)
        {
            return (EtsiTs103097DataSignedAndEncrypted)o;
        }
        if (o != null)
        {
            return new EtsiTs103097DataSignedAndEncrypted(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
