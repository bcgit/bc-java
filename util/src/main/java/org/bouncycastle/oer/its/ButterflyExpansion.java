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

    private ButterflyExpansion(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
        switch (choice)
        {
        case extension:
        case aes128:
            this.butterflyExpansion = DEROctetString.getInstance(ato.getObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }

    public static ButterflyExpansion getInstance(Object o)
    {
        if (o instanceof ButterflyExpansion)
        {
            return (ButterflyExpansion)o;
        }

        if (o != null)
        {
            return new ButterflyExpansion(ASN1TaggedObject.getInstance(o));
        }

        return null;
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
