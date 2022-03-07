package org.bouncycastle.oer.its.etsi103097;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class EtsiTs103097DataSignedAndEncryptedUnicast
    extends EtsiTs103097Data
{
    public EtsiTs103097DataSignedAndEncryptedUnicast(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected EtsiTs103097DataSignedAndEncryptedUnicast(ASN1Sequence src)
    {
        super(src);
    }

    public static EtsiTs103097DataSignedAndEncryptedUnicast getInstance(Object o)
    {
        if (o instanceof EtsiTs103097DataSignedAndEncryptedUnicast)
        {
            return (EtsiTs103097DataSignedAndEncryptedUnicast)o;
        }
        if (o != null)
        {
            return new EtsiTs103097DataSignedAndEncryptedUnicast(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
