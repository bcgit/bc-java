package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

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

    public static EncryptedData getInstance(Object o)
    {
        if (o == null || o instanceof EncryptedData)
        {
            return (EncryptedData)o;
        }

        ASN1Sequence sequence = ASN1Sequence.getInstance(o);

        return new EncryptedData(
            SequenceOfRecipientInfo.getInstance(sequence.getObjectAt(0)),
            SymmetricCiphertext.getInstance(sequence.getObjectAt(1))
        );
    }


    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(recipients, ciphertext);
    }

    public SequenceOfRecipientInfo getRecipients()
    {
        return recipients;
    }

    public SymmetricCiphertext getCiphertext()
    {
        return ciphertext;
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
