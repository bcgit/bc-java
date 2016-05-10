package com.github.gv2011.bcasn;

import java.io.IOException;

/**
 * Definite Length TaggedObject - in ASN.1 notation this is any object preceded by
 * a [n] where n is some number - these are assumed to follow the construction
 * rules (as with sequences).
 */
public class DLTaggedObject
    extends ASN1TaggedObject
{
    private static final byte[] ZERO_BYTES = new byte[0];

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
        if (!empty)
        {
            if (explicit)
            {
                return true;
            }
            else
            {
                ASN1Primitive primitive = obj.toASN1Primitive().toDLObject();

                return primitive.isConstructed();
            }
        }
        else
        {
            return true;
        }
    }

    int encodedLength()
        throws IOException
    {
        if (!empty)
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
        else
        {
            return StreamUtil.calculateTagLength(tagNo) + 1;
        }
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        if (!empty)
        {
            ASN1Primitive primitive = obj.toASN1Primitive().toDLObject();

            if (explicit)
            {
                out.writeTag(BERTags.CONSTRUCTED | BERTags.TAGGED, tagNo);
                out.writeLength(primitive.encodedLength());
                out.writeObject(primitive);
            }
            else
            {
                //
                // need to mark constructed types...
                //
                int flags;
                if (primitive.isConstructed())
                {
                    flags = BERTags.CONSTRUCTED | BERTags.TAGGED;
                }
                else
                {
                    flags = BERTags.TAGGED;
                }

                out.writeTag(flags, tagNo);
                out.writeImplicitObject(primitive);
            }
        }
        else
        {
            out.writeEncoded(BERTags.CONSTRUCTED | BERTags.TAGGED, tagNo, ZERO_BYTES);
        }
    }
}
