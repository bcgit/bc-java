package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * SymmetricCiphertext ::= CHOICE {
 * aes128ccm  AesCcmCiphertext,
 * ...
 * }
 */
public class SymmetricCiphertext
    extends ASN1Object
    implements ASN1Choice
{
    public static final int aes128ccm = 0;

    private final int choice;
    private final ASN1Encodable symmetricCiphertext;

    public SymmetricCiphertext(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.symmetricCiphertext = value;
    }


    private SymmetricCiphertext(ASN1TaggedObject ato)
    {
        this.choice = ato.getTagNo();
        switch (choice)
        {
        case aes128ccm:
            symmetricCiphertext = AesCcmCiphertext.getInstance(ato.getExplicitBaseObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }

    public static SymmetricCiphertext aes128ccm(AesCcmCiphertext ciphertext)
    {
        return new SymmetricCiphertext(aes128ccm, ciphertext);
    }



    public static SymmetricCiphertext getInstance(Object o)
    {
        if (o instanceof SymmetricCiphertext)
        {
            return (SymmetricCiphertext)o;
        }

        if (o != null)
        {
            return new SymmetricCiphertext(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getSymmetricCiphertext()
    {
        return symmetricCiphertext;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, symmetricCiphertext);
    }

}

