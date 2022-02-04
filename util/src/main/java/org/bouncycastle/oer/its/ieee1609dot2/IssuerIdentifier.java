package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
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
    public static final int extension = 2;
    public static final int sha384AndDigest = 3;

    private final int choice;
    private final ASN1Encodable value;


    public IssuerIdentifier(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.value = value;
    }

    private IssuerIdentifier(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
        Object o = ato.getObject();
        switch (choice)
        {
        case sha384AndDigest: // sha384AndDigest  HashedId8
        case sha256AndDigest: // sha256AndDigest HashId8
            value = HashedId8.getInstance(o);
            break;
        case self: // self HashAlgorithm
            value = HashAlgorithm.getInstance(o);
            break;
        case extension: // sha384AndDigest  HashedId8
            value = DEROctetString.getInstance(o);
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
            return new IssuerIdentifier(ASN1TaggedObject.getInstance(choice));
        }

        return null;

    }

    public static Builder builder()
    {
        return new Builder();
    }

    public boolean isSelf()
    {
        return choice == self;
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
        public int choice;
        public ASN1Encodable value;

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

        public Builder sha256AndDigest(HashedId8 id)
        {
            this.choice = sha256AndDigest;
            this.value = id;
            return this;
        }

        public Builder self(HashAlgorithm alg)
        {
            this.choice = self;
            this.value = alg;
            return this;
        }

        public Builder extension(byte[] ext)
        {
            this.choice = extension;
            this.value = new DEROctetString(ext);
            return this;
        }

        public Builder sha384AndDigest(HashedId8 id)
        {
            this.choice = sha384AndDigest;
            this.value = id;
            return this;
        }

        public IssuerIdentifier createIssuerIdentifier()
        {
            return new IssuerIdentifier(choice, value);
        }
    }


}
