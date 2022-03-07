package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSignedAndEncryptedUnicast;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class AuthorizationValidationRequestMessage
    extends EtsiTs103097DataSignedAndEncryptedUnicast
{

    public AuthorizationValidationRequestMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected AuthorizationValidationRequestMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static AuthorizationValidationRequestMessage getInstance(Object o)
    {
        if (o instanceof AuthorizationValidationRequestMessage)
        {
            return (AuthorizationValidationRequestMessage)o;
        }
        if (o != null)
        {
            return new AuthorizationValidationRequestMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
