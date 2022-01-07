package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

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
    private final ASN1Encodable object;


    public SignerIdentifier(int choice, ASN1Encodable value)
    {
        this.choice = choice;
        this.object = value;
    }

    public static final SignerIdentifier getInstance(Object src)
    {

        if (src instanceof SignerIdentifier)
        {
            return (SignerIdentifier)src;
        }

        ASN1TaggedObject to = ASN1TaggedObject.getInstance(src);
        switch (to.getTagNo())
        {
        case digest:
            return new SignerIdentifier(to.getTagNo(), HashedId8.getInstance(to.getObject()));

        case certificate:
            return new SignerIdentifier(to.getTagNo(), SequenceOfCertificate.getInstance(to.getObject()));
        case self:
            break;
        case extension:
            break;
        }
        throw new IllegalArgumentException("unknown choice " + to.getTagNo());
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, object);
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getObject()
    {
        return object;
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