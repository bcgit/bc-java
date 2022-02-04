package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.HashedId8;

/**
 * <pre>
 *     SignerIdentifier ::= CHOICE {
 *         digest HashedId8,
 *         certificate SequenceOfCertificate,
 *         self NULL,
 *         ...
 *     }
 * </pre>
 */
public class SignerIdentifier
    extends ASN1Object
    implements ASN1Choice
{

    public static final int digest = 0;
    public static final int certificate = 1;
    public static final int self = 2;
    public static final int extension = 3;


    private final int choice;
    private final ASN1Encodable signerIdentifier;


    public SignerIdentifier(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.signerIdentifier = value;
    }

    private SignerIdentifier(ASN1TaggedObject ato)
    {
        choice = ato.getTagNo();
        switch (choice)
        {
        case digest:
            signerIdentifier =  HashedId8.getInstance(ato.getObject());
            break;
        case certificate:
            signerIdentifier = SequenceOfCertificate.getInstance(ato.getObject());
            break;
        case self:
            signerIdentifier = DERNull.getInstance(ato.getObject());
            break;
        case extension:
            signerIdentifier = ASN1OctetString.getInstance(ato.getObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }

    }

    public static SignerIdentifier getInstance(Object src)
    {

        if (src instanceof SignerIdentifier)
        {
            return (SignerIdentifier)src;
        }

        if (src != null)
        {
            return new SignerIdentifier(ASN1TaggedObject.getInstance(src));
        }

        return null;
    }

    public static Builder builder()
    {
        return new Builder();
    }


    public int getChoice()
    {
        return choice;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, signerIdentifier);
    }


    public ASN1Encodable getSignerIdentifier()
    {
        return signerIdentifier;
    }

    public static class Builder
    {
        private ASN1Encodable encodable;
        private int choice;

        public Builder setEncodable(ASN1Encodable encodable)
        {
            this.encodable = encodable;
            return this;
        }

        public Builder setChoice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder digest(HashedId8 digest)
        {
            this.choice = SignerIdentifier.digest;
            this.encodable = digest;
            return this;
        }

        public Builder certificate(SequenceOfCertificate sequenceOfCertificate)
        {
            this.choice = SignerIdentifier.certificate;
            this.encodable = sequenceOfCertificate;
            return this;
        }

        public Builder self()
        {
            this.choice = self;
            this.encodable = DERNull.INSTANCE;
            return this;
        }

        public Builder extension(byte[] value)
        {
            this.choice = extension;
            this.encodable = new DEROctetString(value);
            return this;
        }

        public SignerIdentifier build()
        {
            return new SignerIdentifier(choice, encodable);
        }
    }

}