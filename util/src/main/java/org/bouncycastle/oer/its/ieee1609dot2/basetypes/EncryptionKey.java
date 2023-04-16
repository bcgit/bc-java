package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * EncryptionKey ::= CHOICE {
 * public     PublicEncryptionKey,
 * symmetric  SymmetricEncryptionKey
 * }
 */
public class EncryptionKey
    extends ASN1Object
    implements ASN1Choice
{

    public static final int publicOption = 0;
    public static final int symmetric = 1;

    private final int choice;
    private final ASN1Encodable encryptionKey;


    public static EncryptionKey getInstance(Object o)
    {
        if (o instanceof EncryptionKey)
        {
            return (EncryptionKey)o;
        }
        if (o != null)
        {
            return new EncryptionKey(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }
        return null;
    }

    public EncryptionKey(int choice, ASN1Encodable value)
    {
        this.choice = choice;

        switch (choice)
        {
        case publicOption:
        case symmetric:
            this.encryptionKey = value;
            return;
        }

        throw new IllegalArgumentException("invalid choice value " + choice);

    }

    public static EncryptionKey publicOption(PublicEncryptionKey key)
    {
        return new EncryptionKey(publicOption, key);
    }

    public static EncryptionKey symmetric(SymmetricEncryptionKey key)
    {
        return new EncryptionKey(symmetric, key);
    }

    private EncryptionKey(ASN1TaggedObject value)
    {
        this(value.getTagNo(), value.getExplicitBaseObject());
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getEncryptionKey()
    {
        return encryptionKey;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, encryptionKey);
    }
}
