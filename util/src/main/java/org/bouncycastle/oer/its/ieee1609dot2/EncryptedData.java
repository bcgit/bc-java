package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;

/**
 * <pre>
 *     EncryptedData ::= SEQUENCE {
 *         recipients SequenceOfRecipientInfo,
 *         ciphertext SymmetricCiphertext
 *     }
 * </pre>
 */
public class EncryptedData
    extends ASN1Object
{
    private final SequenceOfRecipientInfo recipients;
    private final SymmetricCiphertext ciphertext;

    public EncryptedData(SequenceOfRecipientInfo recipients, SymmetricCiphertext ciphertext)
    {
        this.recipients = recipients;
        this.ciphertext = ciphertext;
    }

    private EncryptedData(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        recipients = SequenceOfRecipientInfo.getInstance(sequence.getObjectAt(0));
        ciphertext = SymmetricCiphertext.getInstance(sequence.getObjectAt(1));

    }

    public static EncryptedData getInstance(Object o)
    {
        if (o instanceof EncryptedData)
        {
            return (EncryptedData)o;
        }

        if (o != null)
        {
            return new EncryptedData(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(recipients, ciphertext);
    }

    public SequenceOfRecipientInfo getRecipients()
    {
        return recipients;
    }

    public SymmetricCiphertext getCiphertext()
    {
        return ciphertext;
    }

    public static Builder builder()
    {
        return new Builder();
    }


    public static class Builder
    {

        private SequenceOfRecipientInfo recipients;
        private SymmetricCiphertext ciphertext;

        public Builder setRecipients(SequenceOfRecipientInfo recipients)
        {
            this.recipients = recipients;
            return this;
        }

        public Builder setCiphertext(SymmetricCiphertext ciphertext)
        {
            this.ciphertext = ciphertext;
            return this;
        }

        public EncryptedData createEncryptedData()
        {
            return new EncryptedData(recipients, ciphertext);
        }
    }
}
