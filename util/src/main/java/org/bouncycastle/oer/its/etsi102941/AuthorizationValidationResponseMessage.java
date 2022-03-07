package org.bouncycastle.oer.its.etsi102941;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSignedAndEncryptedUnicast;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class AuthorizationValidationResponseMessage
    extends EtsiTs103097DataSignedAndEncryptedUnicast
{

    public AuthorizationValidationResponseMessage(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected AuthorizationValidationResponseMessage(ASN1Sequence src)
    {
        super(src);
    }

    public static AuthorizationValidationResponseMessage getInstance(Object o)
    {
        if (o instanceof AuthorizationValidationResponseMessage)
        {
            return (AuthorizationValidationResponseMessage)o;
        }
        if (o != null)
        {
            return new AuthorizationValidationResponseMessage(ASN1Sequence.getInstance(o));
        }
        return null;
    }


}
