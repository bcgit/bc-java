package org.bouncycastle.oer.its.etsi103097;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class EtsiTs103097DataEncrypted
    extends EtsiTs103097Data
{

    public EtsiTs103097DataEncrypted(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected EtsiTs103097DataEncrypted(ASN1Sequence src)
    {
        super(src);
    }

    public static EtsiTs103097DataEncrypted getInstance(Object o)
    {
        if (o instanceof EtsiTs103097DataEncrypted)
        {
            return (EtsiTs103097DataEncrypted)o;
        }
        if (o != null)
        {
            return new EtsiTs103097DataEncrypted(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
