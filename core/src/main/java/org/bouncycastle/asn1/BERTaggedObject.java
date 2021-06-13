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
    public BERTaggedObject(
        int             tagNo,
        ASN1Encodable    obj)
    {
        super(true, tagNo, obj);
    }

    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public BERTaggedObject(
        boolean         explicit,
        int             tagNo,
        ASN1Encodable    obj)
    {
        super(explicit, tagNo, obj);
    }

    /**
     * create an implicitly tagged object that contains a zero
     * length sequence.
     */
    public BERTaggedObject(
        int             tagNo)
    {
        super(false, tagNo, new BERSequence());
    }

    boolean isConstructed()
    {
        return explicit || obj.toASN1Primitive().isConstructed();
    }

    int encodedLength(boolean withTag) throws IOException
    {
        ASN1Primitive primitive = obj.toASN1Primitive();

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

        if (withTag)
        {
            int flags = BERTags.TAGGED;
            if (explicit || primitive.isConstructed())
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
}
