package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;

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
    public static final int extension = 1;


    private final int choice;
    private final ASN1Encodable value;

    public SymmetricEncryptionKey(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
    }

    public SymmetricEncryptionKey(ASN1TaggedObject instance)
    {
        this.choice = instance.getTagNo();
        if (choice == aes128ccm)
        {
            ASN1OctetString str = DEROctetString.getInstance(instance.getObject());
            if (str.getOctets().length != 16)
            {
                throw new IllegalArgumentException("aes128ccm string not 16 bytes");
            }
            this.value = str;
        }
        else if (choice == extension)
        {
            this.value = DEROctetString.getInstance(instance.getObject());
        }
        else
        {
            throw new IllegalArgumentException("unknown tag " + choice);
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
            return new SymmetricEncryptionKey(ASN1TaggedObject.getInstance(o));
        }

        return null;

    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}
