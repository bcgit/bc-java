package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/**
 * PreSharedKeyRecipientInfo ::= HashedId8
 */
public class PreSharedKeyRecipientInfo
    extends HashedId8
{
    public PreSharedKeyRecipientInfo(byte[] string)
    {
        super(string);
    }

    public static PreSharedKeyRecipientInfo getInstance(Object object)
    {
        if (object instanceof PreSharedKeyRecipientInfo)
        {
            return (PreSharedKeyRecipientInfo)object;
        }
        ASN1OctetString octetString = ASN1OctetString.getInstance(object);
        return new PreSharedKeyRecipientInfo(octetString.getOctets());
    }
}
