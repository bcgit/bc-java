package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/**
 * <pre>
 *     PKRecipientInfo ::= SEQUENCE {
 *         recipientId HashedId8,
 *         encKey EncryptedDataEncryptionKey
 *     }
 * </pre>
 */
public class PKRecipientInfo
    extends ASN1Object
{

    private final HashedId8 recipientId;
    private final EncryptedDataEncryptionKey encKey;

    public PKRecipientInfo(HashedId8 recipientId, EncryptedDataEncryptionKey encKey)
    {
        this.recipientId = recipientId;
        this.encKey = encKey;
    }

    private PKRecipientInfo(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        recipientId = HashedId8.getInstance(sequence.getObjectAt(0));
        encKey = EncryptedDataEncryptionKey.getInstance(sequence.getObjectAt(1));

    }


    public static PKRecipientInfo getInstance(Object object)
    {
        if (object instanceof PKRecipientInfo)
        {
            return (PKRecipientInfo)object;
        }

        if (object != null)
        {
            return new PKRecipientInfo(ASN1Sequence.getInstance(object));
        }

        return null;

    }

    public HashedId getRecipientId()
    {
        return recipientId;
    }

    public EncryptedDataEncryptionKey getEncKey()
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
        private EncryptedDataEncryptionKey encKey;

        public Builder setRecipientId(HashedId8 recipientId)
        {
            this.recipientId = recipientId;
            return this;
        }

        public Builder setEncKey(EncryptedDataEncryptionKey encKey)
        {
            this.encKey = encKey;
            return this;
        }

        public PKRecipientInfo createPKRecipientInfo()
        {
            return new PKRecipientInfo(recipientId, encKey);
        }
    }
}
