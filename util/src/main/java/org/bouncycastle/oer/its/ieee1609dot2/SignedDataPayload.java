package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.oer.OEROptional;


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

    private SignedDataPayload(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        data = OEROptional.getValue(Ieee1609Dot2Data.class, sequence.getObjectAt(0));
        extDataHash = OEROptional.getValue(HashedData.class, sequence.getObjectAt(1));
    }


    public static SignedDataPayload getInstance(Object o)
    {
        if (o instanceof SignedDataPayload)
        {
            return (SignedDataPayload)o;
        }
        if (o != null)
        {
            return new SignedDataPayload(ASN1Sequence.getInstance(o));
        }

        return null;

    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(
            new ASN1Encodable[]{
                OEROptional.getInstance(data),
                OEROptional.getInstance(extDataHash)});
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

        public SignedDataPayload createSignedDataPayload()
        {
            return new SignedDataPayload(data, extDataHash);
        }
    }
}
