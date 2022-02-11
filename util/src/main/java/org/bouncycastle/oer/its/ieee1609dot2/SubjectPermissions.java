package org.bouncycastle.oer.its.ieee1609dot2;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfPsidSspRange;


/**
 * <pre>
 *     SubjectPermissions ::= CHOICE {
 *         explicit SequenceOfPsidSspRange,
 *         all NULL,
 *         ...
 *     }
 * </pre>
 */
public class SubjectPermissions
    extends ASN1Object
    implements ASN1Choice
{

    public static final int explicit = 0;
    public static final int all = 1;
    public static final int extension = 2;

    private final ASN1Encodable value;
    private final int choice;

    SubjectPermissions(int choice, ASN1Encodable value)
    {
        this.value = value;
        this.choice = choice;
    }

    private SubjectPermissions(ASN1TaggedObject ato)
    {
        this.choice = ato.getTagNo();

        switch (choice)
        {
        case explicit:
            value = SequenceOfPsidSspRange.getInstance(ato.getObject());
            break;
        case all:
            value = ASN1Null.getInstance(ato.getObject());
            break;
        case extension:
            value = DEROctetString.getInstance(ato.getObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }


    public static SubjectPermissions getInstance(Object src)
    {
        if (src instanceof SubjectPermissions)
        {
            return (SubjectPermissions)src;
        }

        if (src != null)
        {
            return new SubjectPermissions(ASN1TaggedObject.getInstance(src));
        }
        return null;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }

    public int getChoice()
    {
        return choice;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, value);
    }

    public static class Builder
    {
        int choice;
        ASN1Encodable value;

        public Builder choice(int choice)
        {
            this.choice = choice;
            return this;
        }

        public Builder value(ASN1Encodable value)
        {
            this.value = value;
            return this;
        }


        public Builder explicit(SequenceOfPsidSspRange value)
        {
            this.choice = explicit;
            this.value = value;
            return this;
        }

        public Builder all()
        {
            this.choice = all;
            this.value = DERNull.INSTANCE;
            return this;
        }

        public Builder extension(ASN1Encodable encodable)
        {
            this.choice = extension;
            if (encodable instanceof ASN1OctetString)
            {
                value = encodable;
            }
            else
            {
                try
                {
                    value = new DEROctetString(encodable.toASN1Primitive().getEncoded());
                }
                catch (IOException ioException)
                {
                    throw new RuntimeException(ioException.getMessage(), ioException);
                }
            }
            return this;
        }

        public SubjectPermissions createSubjectPermissions()
        {
            return new SubjectPermissions(choice, value);
        }

    }

}
