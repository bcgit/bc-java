package org.bouncycastle.oer.its.ieee1609dot2dot1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
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

        case aes128:
            this.butterflyExpansion = DEROctetString.getInstance(ato.getExplicitBaseObject());
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
            return new ButterflyExpansion(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }

    public static ButterflyExpansion aes128(byte[] value)
    {
        if (value.length != 16)
        {
            throw new IllegalArgumentException("length must be 16");
        }
        return new ButterflyExpansion(aes128, new DEROctetString(value));
    }

    public static ButterflyExpansion aes128(ASN1OctetString value)
    {
        return aes128(value.getOctets());
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

}
