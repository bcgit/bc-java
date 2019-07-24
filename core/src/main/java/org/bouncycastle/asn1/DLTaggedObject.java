package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Definite Length TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class DLTaggedObject
    extends ASN1TaggedObject
{
    /**
     * @param explicit true if an explicitly tagged object.
     * @param tagNo the tag number for this object.
     * @param obj the tagged object.
     */
    public DLTaggedObject(
        boolean explicit,
        int tagNo,
        ASN1Encodable obj)
    {
        super(explicit, tagNo, obj);
    }

    boolean isConstructed()
    {
        return explicit || obj.toASN1Primitive().toDLObject().isConstructed();
    }

    int encodedLength()
        throws IOException
    {
        int length = obj.toASN1Primitive().toDLObject().encodedLength();

        if (explicit)
        {
            return  StreamUtil.calculateTagLength(tagNo) + StreamUtil.calculateBodyLength(length) + length;
        }
        else
        {
            // header length already in calculation
            length = length - 1;

            return StreamUtil.calculateTagLength(tagNo) + length;
        }
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        ASN1Primitive primitive = obj.toASN1Primitive().toDLObject();

        int flags = BERTags.TAGGED;
        if (explicit || primitive.isConstructed())
        {
            flags |= BERTags.CONSTRUCTED;
        }

        out.writeTag(withTag, flags, tagNo);

        if (explicit)
        {
            out.writeLength(primitive.encodedLength());
        }

        out.getDLSubStream().writePrimitive(primitive, explicit);
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }
}
