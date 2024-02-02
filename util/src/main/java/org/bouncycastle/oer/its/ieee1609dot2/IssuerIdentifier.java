package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashAlgorithm;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

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
    private final ASN1Encodable issuerIdentifier;


    public static IssuerIdentifier sha256AndDigest(HashedId8 data)
    {
        return new IssuerIdentifier(sha256AndDigest, data);
    }

    public static IssuerIdentifier self(HashAlgorithm data)
    {
        return new IssuerIdentifier(self, data);
    }


    public static IssuerIdentifier sha384AndDigest(HashedId8 data)
    {
        return new IssuerIdentifier(sha384AndDigest, data);
    }

    public IssuerIdentifier(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.issuerIdentifier = value;
    }

    private IssuerIdentifier(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
        Object o = ato.getExplicitBaseObject();
        switch (choice)
        {
        case sha384AndDigest: // sha384AndDigest  HashedId8
        case sha256AndDigest: // sha256AndDigest HashId8
            issuerIdentifier = HashedId8.getInstance(o);
            break;
        case self: // self HashAlgorithm
            issuerIdentifier = HashAlgorithm.getInstance(o);
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }

    }

    public static IssuerIdentifier getInstance(Object choice)
    {
        if (choice instanceof IssuerIdentifier)
        {
            return (IssuerIdentifier)choice;
        }

        if (choice != null)
        {
            return new IssuerIdentifier(ASN1TaggedObject.getInstance(choice, BERTags.CONTEXT_SPECIFIC));
        }

        return null;

    }

    public boolean isSelf()
    {
        return choice == self;
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getIssuerIdentifier()
    {
        return issuerIdentifier;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, issuerIdentifier);
    }

}
