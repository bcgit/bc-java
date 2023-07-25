package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * BER TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class BERTaggedObject
    extends ASN1TaggedObject
{
    /**
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public BERTaggedObject(int tagNo, ASN1Encodable obj)
    {
        super(true, tagNo, obj);
    }

    public BERTaggedObject(int tagClass, int tagNo, ASN1Encodable obj)
    {
        super(true, tagClass, tagNo, obj);
    }

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public BERTaggedObject(boolean explicit, int tagNo, ASN1Encodable obj)
    {
        super(explicit, tagNo, obj);
    }

    public BERTaggedObject(boolean explicit, int tagClass, int tagNo, ASN1Encodable obj)
    {
        super(explicit, tagClass, tagNo, obj);
    }

    BERTaggedObject(int explicitness, int tagClass, int tagNo, ASN1Encodable obj)
    {
        super(explicitness, tagClass, tagNo, obj);
    }

    boolean encodeConstructed()
    {
        return isExplicit() || obj.toASN1Primitive().encodeConstructed();
    }

    int encodedLength(boolean withTag) throws IOException
    {
        ASN1Primitive primitive = obj.toASN1Primitive();
        boolean explicit = isExplicit();

        int length = primitive.encodedLength(explicit);

        if (explicit)
        {
            length += 3;
        }

        length += withTag ? ASN1OutputStream.getLengthOfIdentifier(tagNo) : 0;

        return length;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
//        assert out.getClass().isAssignableFrom(ASN1OutputStream.class);

        ASN1Primitive primitive = obj.toASN1Primitive();
        boolean explicit = isExplicit();

        if (withTag)
        {
            int flags = tagClass;
            if (explicit || primitive.encodeConstructed())
            {
                flags |= BERTags.CONSTRUCTED;
            }

            out.writeIdentifier(true, flags, tagNo);
        }

        if (explicit)
        {
            out.write(0x80);
            primitive.encode(out, true);
            out.write(0x00);
            out.write(0x00);
        }
        else
        {
            primitive.encode(out, false);
        }
    }

    ASN1Sequence rebuildConstructed(ASN1Primitive primitive)
    {
        return new BERSequence(primitive);
    }

    ASN1TaggedObject replaceTag(int tagClass, int tagNo)
    {
        return new BERTaggedObject(explicitness, tagClass, tagNo, obj);
    }
}
