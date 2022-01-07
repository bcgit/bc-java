package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

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

    public static PKRecipientInfo getInstance(Object object)
    {
        if (object instanceof PKRecipientInfo)
        {
            return (PKRecipientInfo)object;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(object);

        return new PKRecipientInfo(
            HashedId8.getInstance(seq.getObjectAt(0)),
            EncryptedDataEncryptionKey.getInstance(seq.getObjectAt(0)));
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
        return Utils.toSequence(recipientId, encKey);
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
