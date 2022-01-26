package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
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
    private final ASN1Encodable value;

    public SymmetricCiphertext(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
    }

    public static SymmetricCiphertext getInstance(Object o)
    {
        if (o instanceof SymmetricCiphertext)
        {
            return (SymmetricCiphertext)o;
        }

        ASN1TaggedObject ato = ASN1TaggedObject.getInstance(o);
        return new Builder().setChoice(ato.getTagNo()).setValue(ato.getObject()).createSymmetricCiphertext();
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

        public Builder setValue(ASN1Encodable value)
        {
            this.value = value;
            return this;
        }

        public SymmetricCiphertext createSymmetricCiphertext()
        {
            return new SymmetricCiphertext(choice, value);
        }
    }
}
