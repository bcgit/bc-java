package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

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

/**
 * <pre>
 * SspRange ::= CHOICE {
 *     opaque SequenceOfOctetString,
 *     all NULL,
 *     ...
 *     bitmapSspRange BitmapSspRange
 * }
 * </pre>
 */
public class SspRange
    extends ASN1Object
    implements ASN1Choice
{

    private static final int opaque = 0;
    private static final int all = 1;
    private static final int extension = 2;
    private static final int bitmapSspRange = 3;

    private final int choice;
    private final ASN1Encodable value;


    public SspRange(int choice, ASN1Encodable value)
    {

        switch (choice)
        {
        case opaque:
            if (!(value instanceof SequenceOfOctetString))
            {
                throw new IllegalArgumentException("value is not SequenceOfOctetString");
            }
            break;
        case all:
            if (!(value instanceof ASN1Null))
            {
                throw new IllegalArgumentException("value is not ASN1Null");
            }
            break;
        case extension:
            if (!(value instanceof ASN1OctetString))
            {
                throw new IllegalArgumentException("value is not ASN1OctetString");
            }
            break;
        case bitmapSspRange:
            if (!(value instanceof BitmapSspRange))
            {
                throw new IllegalArgumentException("value is not BitmapSspRange");
            }
            break;
        }


        this.choice = choice;
        this.value = value;
    }


    public static SspRange getInstance(Object src)
    {
        if (src instanceof SspRange)
        {
            return (SspRange)src;
        }

        ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(src);
        int item = taggedObject.getTagNo();

        switch (item)
        {
        case opaque:
            return new SspRange(opaque,
                SequenceOfOctetString.getInstance(taggedObject.getObject()));
        case all:
            return new SspRange(all, DERNull.INSTANCE);
        case extension:
            try
            {
                return new SspRange(extension, new DEROctetString(taggedObject.getObject().getEncoded()));
            }
            catch (IOException ioException)
            {
                throw new RuntimeException(ioException.getMessage(), ioException);
            }

        case bitmapSspRange:
            return new SspRange(bitmapSspRange, BitmapSspRange.getInstance(taggedObject.getObject()));
        }

        throw new IllegalStateException("unknown choice " + item);

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

        public Builder opaque(SequenceOfOctetString value)
        {
            this.value = value;
            this.choice = opaque;
            return this;
        }

        public Builder all()
        {
            this.value = DERNull.INSTANCE;
            this.choice = opaque;
            return this;
        }

        // byte array
        public Builder extension(byte[] value)
        {
            this.value = new DEROctetString(value);
            this.choice = extension;
            return this;
        }

        public Builder bitmapSSPRange(BitmapSspRange value)
        {
            this.value = value;
            this.choice = bitmapSspRange;
            return this;
        }

        public SspRange createSspRange()
        {
            return new SspRange(choice, value);
        }

    }
}
