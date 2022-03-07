package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataEncryptedUnicast;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class AuthorizationRequestMessage
    extends EtsiTs103097DataEncryptedUnicast
{

    public AuthorizationRequestMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected AuthorizationRequestMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static AuthorizationRequestMessage getInstance(Object o)
    {
        if (o instanceof AuthorizationRequestMessage)
        {
            return (AuthorizationRequestMessage)o;
        }
        if (o != null)
        {
            return new AuthorizationRequestMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
