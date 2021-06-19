package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 *     IssuerIdentifier ::= CHOICE {
 *         sha256AndDigest HashedId8,
 *         self HashAlgorithm,
 *         ...,
 *         sha384AndDigest HashedId8
 *     }
 * </pre>
 */
public class IssuerIdentifier
    extends ASN1Object
    implements ASN1Choice
{

    public static final int sha256AndDigest = 0;
    public static final int self = 1;
    public static final int sha384AndDigest = 2;

    private final int choice;
    private final ASN1Encodable value;

    /**
     * @param choice one of sha256AndDigest,self or sha384AndDigest
     * @param value  the associated value.
     */
    public IssuerIdentifier(int choice, byte[] value)
    {
        this(choice, new DEROctetString(value));
    }

    public IssuerIdentifier(HashAlgorithm value)
    {
        this(self, value);
    }

    public IssuerIdentifier(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
    }

    public static IssuerIdentifier getInstance(Object choice)
    {
        if (choice instanceof IssuerIdentifier)
        {
            return (IssuerIdentifier)choice;
        }
        else
        {
            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(choice);
            int item = taggedObject.getTagNo();

            switch (item)
            {
            case 0: // sha256AndDigest HashId8
                return new IssuerIdentifier(sha256AndDigest, taggedObject.getObject());
            case 1: // self HashAlgorithm
                return new IssuerIdentifier(self, taggedObject.getObject());
            case 2: // sha384AndDigest  HashedId8
                return new IssuerIdentifier(sha384AndDigest, taggedObject.getObject());
            default:
                throw new IllegalArgumentException("unable to decode into known choice" + item);
            }

        }
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
}
