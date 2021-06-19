package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * <pre>
 *     AesCcmCiphertext ::= SEQUENCE {
 *         nonce OCTET STRING (SIZE (12))
 *         ccmCiphertext Opaque -- 16 bytes longer than plaintext
 *     }
 * </pre>
 */
public class AesCcmCiphertext
    extends ASN1Object
{
    private final ASN1OctetString nonce;
    private final SequenceOfOctetString opaque;

    public AesCcmCiphertext(ASN1OctetString nonce, SequenceOfOctetString opaque)
    {
        this.nonce = nonce;
        this.opaque = opaque;
    }

    public static AesCcmCiphertext getInstance(Object o)
    {
        if (o instanceof AesCcmCiphertext)
        {
            return (AesCcmCiphertext)o;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(o);
        return new Builder()
            .setNonce(ASN1OctetString.getInstance(seq.getObjectAt(0)))
            .setOpaque(SequenceOfOctetString.getInstance(seq.getObjectAt(1)))
            .createAesCcmCiphertext();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(nonce, opaque);
    }

    public static class Builder
    {

        private ASN1OctetString nonce;
        private SequenceOfOctetString opaque;

        public Builder setNonce(ASN1OctetString nonce)
        {
            this.nonce = nonce;
            return this;
        }

        public Builder setOpaque(SequenceOfOctetString opaque)
        {
            this.opaque = opaque;
            return this;
        }

        public AesCcmCiphertext createAesCcmCiphertext()
        {
            return new AesCcmCiphertext(nonce, opaque);
        }
    }
}