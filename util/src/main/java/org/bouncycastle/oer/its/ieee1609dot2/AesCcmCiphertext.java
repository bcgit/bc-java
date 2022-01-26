package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfOctetString;

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

    private AesCcmCiphertext(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence length of 2");
        }
        Iterator<ASN1Encodable> it = seq.iterator();
        nonce = ASN1OctetString.getInstance(it.next());
        opaque = SequenceOfOctetString.getInstance(it.next());
    }

    public static AesCcmCiphertext getInstance(Object o)
    {
        if (o instanceof AesCcmCiphertext)
        {
            return (AesCcmCiphertext)o;
        }

        if (o != null)
        {
            return new AesCcmCiphertext(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(nonce, opaque);
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