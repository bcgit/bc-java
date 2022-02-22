package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

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

    private final HashedId8 recipientId;
    private final SymmetricCiphertext encKey;

    public SymmRecipientInfo(HashedId8 recipientId, SymmetricCiphertext encKey)
    {
        this.recipientId = recipientId;
        this.encKey = encKey;
    }

    private SymmRecipientInfo(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        recipientId = HashedId8.getInstance(sequence.getObjectAt(0));
        encKey = SymmetricCiphertext.getInstance(sequence.getObjectAt(1));
    }

    public static SymmRecipientInfo getInstance(Object o)
    {
        if (o instanceof SymmRecipientInfo)
        {
            return (SymmRecipientInfo)o;
        }
        if (o != null)
        {
            return new SymmRecipientInfo(ASN1Sequence.getInstance(o));
        }

        return null;
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

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private HashedId8 recipientId;
        private SymmetricCiphertext encKey;

        public Builder setRecipientId(HashedId8 recipientId)
        {
            this.recipientId = recipientId;
            return this;
        }

        public Builder setEncKey(SymmetricCiphertext encKey)
        {
            this.encKey = encKey;
            return this;
        }

        public SymmRecipientInfo createSymmRecipientInfo()
        {
            return new SymmRecipientInfo(recipientId, encKey);
        }
    }

}
