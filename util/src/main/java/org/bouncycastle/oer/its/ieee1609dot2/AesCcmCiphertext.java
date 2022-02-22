package org.bouncycastle.oer.its.ieee1609dot2;

import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.oer.its.ItsUtils;

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
    private final ASN1OctetString ccmCiphertext;

    public AesCcmCiphertext(ASN1OctetString nonce, ASN1OctetString opaque)
    {
        this.nonce = nonce;
        this.ccmCiphertext = opaque;
    }

    private AesCcmCiphertext(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        Iterator<ASN1Encodable> it = seq.iterator();
        nonce = ASN1OctetString.getInstance(it.next());
        ccmCiphertext = ASN1OctetString.getInstance(it.next());
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

    public ASN1OctetString getNonce()
    {
        return nonce;
    }

    public ASN1OctetString getCcmCiphertext()
    {
        return ccmCiphertext;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(nonce, ccmCiphertext);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {

        private ASN1OctetString nonce;
        private ASN1OctetString opaque;

        public Builder setNonce(ASN1OctetString nonce)
        {
            this.nonce = nonce;
            return this;
        }

        public Builder setNonce(byte[] nonce)
        {
            return setNonce(new DEROctetString(nonce));
        }
        
        public Builder setCcmCiphertext(ASN1OctetString opaque)
        {
            this.opaque = opaque;
            return this;
        }

        public Builder setCcmCiphertext(byte[] opaque)
        {
            return setCcmCiphertext(new DEROctetString(opaque));
        }

        public AesCcmCiphertext createAesCcmCiphertext()
        {
            return new AesCcmCiphertext(nonce, opaque);
        }
    }
}