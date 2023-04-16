package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

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
 * SymmetricEncryptionKey ::= CHOICE {
 * aes128Ccm  OCTET STRING(SIZE(16)),
 * ...
 * }
 */
public class SymmetricEncryptionKey
    extends ASN1Object
    implements ASN1Choice
{
    public static final int aes128ccm = 0;



    private final int choice;
    private final ASN1Encodable symmetricEncryptionKey;

    public SymmetricEncryptionKey(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.symmetricEncryptionKey = value;
    }

    private SymmetricEncryptionKey(ASN1TaggedObject instance)
    {
        this.choice = instance.getTagNo();
        if (choice == aes128ccm)
        {
            ASN1OctetString str = DEROctetString.getInstance(instance.getExplicitBaseObject());
            if (str.getOctets().length != 16)
            {
                throw new IllegalArgumentException("aes128ccm string not 16 bytes");
            }
            this.symmetricEncryptionKey = str;
        }
        else
        {
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }

    public static SymmetricEncryptionKey getInstance(Object o)
    {
        if (o instanceof SymmetricEncryptionKey)
        {
            return (SymmetricEncryptionKey)o;
        }
        if (o != null)
        {
            return new SymmetricEncryptionKey(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;

    }


    public static SymmetricEncryptionKey aes128ccm(byte[] octetString)
    {
        return new SymmetricEncryptionKey(aes128ccm, new DEROctetString(octetString));
    }




    public static SymmetricEncryptionKey aes128ccm(ASN1OctetString octetString)
    {
        return new SymmetricEncryptionKey(aes128ccm, octetString);
    }


    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getSymmetricEncryptionKey()
    {
        return symmetricEncryptionKey;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, symmetricEncryptionKey);
    }
}
