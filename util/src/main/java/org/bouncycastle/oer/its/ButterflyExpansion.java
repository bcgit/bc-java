package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;


/**
 * ButterflyExpansion ::= CHOICE {
 * aes128      OCTET STRING (SIZE(16)),
 * ...
 * }
 */
public class ButterflyExpansion
    extends ASN1Object
    implements ASN1Choice
{
    public static final int aes128 = 0;
    public static final int extension = 1;

    protected final int choice;
    protected final ASN1Encodable butterflyExpansion;

    ButterflyExpansion(int choice, ASN1Encodable butterflyExpansion)
    {
        this.choice = choice;
        this.butterflyExpansion = butterflyExpansion;
    }

    public static ButterflyExpansion getInstance(Object o)
    {
        if (o instanceof ButterflyExpansion)
        {
            return (ButterflyExpansion)o;
        }

        ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(o);
        int choice = taggedObject.getTagNo();
        switch (choice)
        {
        case aes128:
            return new ButterflyExpansion(
                aes128,
                DEROctetString.getInstance(taggedObject.getObject()));
        case extension:
            return new ButterflyExpansion(
                extension,
                DEROctetString.getInstance(taggedObject.getObject()));
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, butterflyExpansion);
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getButterflyExpansion()
    {
        return butterflyExpansion;
    }

    public static class Builder
    {
        private int choice;
        private ASN1Encodable butterflyExpansion;

        public Builder aes128(ASN1OctetString value)
        {
            choice = ButterflyExpansion.aes128;
            butterflyExpansion = value;
            return this;
        }

        public Builder extension(ASN1OctetString value)
        {
            choice = ButterflyExpansion.extension;
            butterflyExpansion = value;
            return this;
        }

        public ButterflyExpansion build()
        {
            return new ButterflyExpansion(choice, butterflyExpansion);
        }
    }

}
