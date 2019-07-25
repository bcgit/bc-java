package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

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

    int encodedLength()
        throws IOException
    {
        ASN1Primitive primitive = obj.toASN1Primitive();
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

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeTag(withTag, BERTags.CONSTRUCTED | BERTags.TAGGED, tagNo);
        out.write(0x80);

        if (!explicit)
        {
            Enumeration e;
            if (obj instanceof ASN1OctetString)
            {
                if (obj instanceof BEROctetString)
                {
                    e = ((BEROctetString)obj).getObjects();
                }
                else
                {
                    ASN1OctetString octs = (ASN1OctetString)obj;
                    BEROctetString berO = new BEROctetString(octs.getOctets());
                    e = berO.getObjects();
                }
            }
            else if (obj instanceof ASN1Sequence)
            {
                e = ((ASN1Sequence)obj).getObjects();
            }
            else if (obj instanceof ASN1Set)
            {
                e = ((ASN1Set)obj).getObjects();
            }
            else
            {
                throw new ASN1Exception("not implemented: " + obj.getClass().getName());
            }

            out.writeElements(e);
        }
        else
        {
            out.writePrimitive(obj.toASN1Primitive(), true);
        }

        out.write(0x00);
        out.write(0x00);

//        ASN1Primitive primitive = obj.toASN1Primitive();
//
//        int flags = BERTags.TAGGED;
//        if (explicit || primitive.isConstructed())
//        {
//            flags |= BERTags.CONSTRUCTED;
//        }
//
//        out.writeTag(withTag, flags, tagNo);
//
//        if (explicit)
//        {
//            out.write(0x80);
//            out.writePrimitive(obj.toASN1Primitive(), true);
//            out.write(0x00);
//            out.write(0x00);
//        }
//        else
//        {
//            out.writePrimitive(obj.toASN1Primitive(), false);
//        }
    }
}
