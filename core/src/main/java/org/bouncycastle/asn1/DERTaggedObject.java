package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * DER TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class DERTaggedObject
    extends ASN1TaggedObject
{
    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public DERTaggedObject(
        boolean       explicit,
        int           tagNo,
        ASN1Encodable obj)
    {
        super(explicit, tagNo, obj);
    }

    public DERTaggedObject(int tagNo, ASN1Encodable encodable)
    {
        super(true, tagNo, encodable);
    }

    boolean isConstructed()
    {
        return explicit || obj.toASN1Primitive().toDERObject().isConstructed();
    }

    int encodedLength()
        throws IOException
    {
        ASN1Primitive primitive = obj.toASN1Primitive().toDERObject();
        int length = primitive.encodedLength();

        if (explicit)
        {
            return StreamUtil.calculateTagLength(tagNo) + StreamUtil.calculateBodyLength(length) + length;
        }
        else
        {
            // header length already in calculation
            length = length - 1;

            return StreamUtil.calculateTagLength(tagNo) + length;
        }
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        ASN1Primitive primitive = obj.toASN1Primitive().toDERObject();

        if (explicit)
        {
            out.writeTag(BERTags.CONSTRUCTED | BERTags.TAGGED, tagNo);
            out.writeLength(primitive.encodedLength());

            primitive.encode(out.getDERSubStream());
            return;
        }

        int flags = BERTags.TAGGED;
        if (primitive.isConstructed())
        {
            flags |= BERTags.CONSTRUCTED;
        }

        out.writeTag(flags, tagNo);

        primitive.encode(out.getDERSubStream().getImplicitOutputStream());
    }

    ASN1Primitive toDERObject()
    {
        return this;
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }
}
