package org.bouncycastle.its.asn1;

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
{
    private EncryptedData(ASN1Sequence seq)
    {

    }

    public static EncryptedData getInstance(Object o)
    {
        if (o instanceof EncryptedData)
        {
            return (EncryptedData)o;
        }
        else if (o != null)
        {
            return new EncryptedData(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
