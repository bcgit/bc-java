package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId;

/**
 * <pre>
 *     SymmRecipientInfo ::= SEQUENCE {
 *         recipientId HashedId8,
 *         encKey SymmetricCiphertext
 *     }
 * </pre>
 */
public class SymmRecipientInfo
    extends ASN1Object
{

    private final HashedId recipientId;
    private final SymmetricCiphertext encKey;

    public SymmRecipientInfo(HashedId recipientId, SymmetricCiphertext encKey)
    {
        this.recipientId = recipientId;
        this.encKey = encKey;
    }

    public HashedId getRecipientId()
    {
        return recipientId;
    }

    public SymmetricCiphertext getEncKey()
    {
        return encKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(recipientId, encKey);
    }
}
