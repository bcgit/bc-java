package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 *     HashedData ::= CHOICE {
 *         sha256HashedData OCTET STRING (SIZE(32))
 *     }
 * </pre>
 */
public class HashedData
    extends ASN1Object
    implements ASN1Choice
{
    public static final int sha256_HashedData = 0;


    private final int choice;
    private final ASN1Encodable value;

    public static HashedData getInstance(Object o)
    {
        if (o instanceof HashedData)
        {
            return (HashedData)o;
        }

        ASN1TaggedObject dto = ASN1TaggedObject.getInstance(o);
        return new Builder()
            .setChoice(dto.getTagNo())
            .setSha256HashedData(dto.getObject())
            .createHashedData();
    }


    public HashedData(int choice, ASN1Encodable sha256HashedData)
    {
        this.choice = choice;
        this.value = sha256HashedData;
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
        private ASN1Encodable sha256HashedData;

        public Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder setSha256HashedData(ASN1Encodable sha256HashedData)
        {
            this.sha256HashedData = sha256HashedData;
            return this;
        }

        public HashedData createHashedData()
        {
            return new HashedData(choice, sha256HashedData);
        }
    }
}
