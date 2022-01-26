package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;


/**
 * <pre>
 *     SignedDataPayload ::= SEQUENCE {
 *         data Ieee1609Dot2Data OPTIONAL,
 *         extDataHash HashedData OPTIONAL,
 *         ...
 *     }
 * </pre>
 */
public class SignedDataPayload
    extends ASN1Object
{
    private final Ieee1609Dot2Data data;
    private final HashedData extDataHash;


    public SignedDataPayload(Ieee1609Dot2Data data, HashedData extDataHash)
    {
        this.data = data;
        this.extDataHash = extDataHash;
    }

    public static SignedDataPayload getInstance(Object o)
    {
        if (o instanceof SignedDataPayload)
        {
            return (SignedDataPayload)o;
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(o);
        return new SignedDataPayload(Ieee1609Dot2Data.getInstance(seq.getObjectAt(0)), HashedData.getInstance(seq.getObjectAt(1)));

    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        return new DERSequence(v);
    }

    public Ieee1609Dot2Data getData()
    {
        return data;
    }

    public HashedData getExtDataHash()
    {
        return extDataHash;
    }

    public static class Builder
    {
        private Ieee1609Dot2Data data;
        private HashedData extDataHash;


        public Builder setData(Ieee1609Dot2Data data)
        {
            this.data = data;
            return this;
        }

        public Builder setExtDataHash(HashedData extDataHash)
        {
            this.extDataHash = extDataHash;
            return this;
        }

        public SignedDataPayload build()
        {
            return new SignedDataPayload(data, extDataHash);
        }
    }
}
