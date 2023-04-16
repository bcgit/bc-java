package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Arrays;

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
    public static final int sha384HashedData = 1;
    public static final int reserved = 2;


    private final int choice;
    private final ASN1Encodable hashedData;

    public HashedData(int choice, ASN1Encodable sha256HashedData)
    {
        this.choice = choice;
        this.hashedData = sha256HashedData;
    }

    private HashedData(ASN1TaggedObject dto)
    {
        switch (dto.getTagNo())
        {
        case sha256HashedData:
        case sha384HashedData:
        case reserved:
            this.choice = dto.getTagNo();
            this.hashedData = DEROctetString.getInstance(dto.getExplicitBaseObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + dto.getTagNo());
        }
    }

    public static HashedData sha256HashedData(ASN1OctetString sha256HashedData)
    {
        return new HashedData(HashedData.sha256HashedData,sha256HashedData);
    }

    public static HashedData sha256HashedData(byte[] sha256HashedData)
    {
        return new HashedData(HashedData.sha256HashedData,new DEROctetString(Arrays.clone(sha256HashedData)));
    }

    public static HashedData sha384HashedData(ASN1OctetString sha384HashedData)
    {
        return new HashedData(HashedData.sha384HashedData,sha384HashedData);
    }

    public static HashedData sha384HashedData(byte[] sha384HashedData)
    {
        return new HashedData(HashedData.sha384HashedData,new DEROctetString(Arrays.clone(sha384HashedData)));
    }

    public static HashedData reserved(ASN1OctetString reserved)
    {
       return new HashedData(HashedData.reserved,reserved);
    }

    public static HashedData reserved(byte[] reserved)
    {
        return new HashedData(HashedData.reserved, new DEROctetString(Arrays.clone(reserved)));
    }

    public static HashedData getInstance(Object o)
    {
        if (o instanceof HashedData)
        {
            return (HashedData)o;
        }

        if (o != null)
        {
            return new HashedData(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;

    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getHashedData()
    {
        return hashedData;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, hashedData);
    }


}
