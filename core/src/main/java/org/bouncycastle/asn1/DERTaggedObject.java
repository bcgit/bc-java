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
    public DERTaggedObject(int tagNo, ASN1Encodable encodable)
    {
        super(true, tagNo, encodable);
    }

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public DERTaggedObject(boolean explicit, int tagNo, ASN1Encodable obj)
    {
        super(explicit, tagNo, obj);
    }

    public DERTaggedObject(boolean explicit, int tagClass, int tagNo, ASN1Encodable obj)
    {
        super(explicit, tagClass, tagNo, obj);
    }

    boolean isConstructed()
    {
        return explicit || obj.toASN1Primitive().toDERObject().isConstructed();
    }

    int encodedLength(boolean withTag) throws IOException
    {
        ASN1Primitive primitive = obj.toASN1Primitive().toDERObject();

        int length = primitive.encodedLength(explicit);

        if (explicit)
        {
            length += ASN1OutputStream.getLengthOfDL(length);
        }

        length += withTag ? ASN1OutputStream.getLengthOfIdentifier(tagNo) : 0;

        return length;
    }

    void encode(ASN1OutputStream out, boolean withTag, int tagClass, int tagNo) throws IOException
    {
//      assert out.getClass().isAssignableFrom(DEROutputStream.class);

        ASN1Primitive primitive = obj.toASN1Primitive().toDERObject();

        if (withTag)
        {
            int flags = tagClass;
            if (explicit || primitive.isConstructed())
            {
                flags |= BERTags.CONSTRUCTED;
            }

            out.writeIdentifier(true, flags, tagNo);
        }

        if (explicit)
        {
            out.writeDL(primitive.encodedLength(true));
        }

        primitive.encode(out.getDERSubStream(), explicit);
    }

    String getASN1Encoding()
    {
        return ASN1Encoding.DER;
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
