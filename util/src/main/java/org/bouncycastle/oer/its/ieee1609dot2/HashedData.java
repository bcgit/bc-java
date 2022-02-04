package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 *    HashedData::= CHOICE {
 *     sha256HashedData  OCTET STRING (SIZE(32)),
 *     ...,
 *     sha384HashedData  OCTET STRING (SIZE(48)),
 *     reserved          OCTET STRING (SIZE(32))
 *   }
 * </pre>
 */
public class HashedData
    extends ASN1Object
    implements ASN1Choice
{
    public static final int sha256HashedData = 0;
    public static final int extension = 1;
    public static final int sha384HashedData = 2;
    public static final int reserved = 3;


    private final int choice;
    private final ASN1Encodable value;

    public HashedData(int choice, ASN1Encodable sha256HashedData)
    {
        this.choice = choice;
        this.value = sha256HashedData;
    }

    private HashedData(ASN1TaggedObject dto)
    {
        switch (dto.getTagNo())
        {
        case sha256HashedData:
        case extension:
        case sha384HashedData:
        case reserved:
            this.choice = dto.getTagNo();
            this.value = DEROctetString.getInstance(dto.getObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + dto.getTagNo());
        }
    }

    public static HashedData getInstance(Object o)
    {
        if (o instanceof HashedData)
        {
            return (HashedData)o;
        }

        if (o != null)
        {
            return new HashedData(ASN1TaggedObject.getInstance(o));
        }

        return null;

    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, value);
    }

    public static class Builder
    {

        private int choice;
        private ASN1Encodable value;

        public Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder setSha256HashedData(ASN1Encodable sha256HashedData)
        {
            value = sha256HashedData;
            return this;
        }

        public Builder extension(byte[] extension)
        {
            value = new DEROctetString(extension);
            return this;
        }

        public Builder sha384HashedData(ASN1OctetString sha384HashedData)
        {
            value = sha384HashedData;
            return this;
        }

        public Builder reserved(ASN1OctetString reserved)
        {
            value = reserved;
            return this;
        }

        public HashedData createHashedData()
        {
            return new HashedData(choice, value);
        }
    }
}
