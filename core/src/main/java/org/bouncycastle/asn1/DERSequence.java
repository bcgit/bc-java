package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Definite length SEQUENCE, encoding tells explicit number of bytes
 * that the content of this sequence occupies.
 * <p>
 * For X.690 syntax rules, see {@link ASN1Sequence}.
 */
public class DERSequence
    extends ASN1Sequence
{
    public static DERSequence convert(ASN1Sequence seq)
    {
        return (DERSequence)seq.toDERObject();
    }

    private int bodyLength = -1;

    /**
     * Create an empty sequence
     */
    public DERSequence()
    {
    }

    /**
     * Create a sequence containing one object
     * @param obj the object to go in the sequence.
     */
    public DERSequence(
        ASN1Encodable obj)
    {
        super(obj);
    }

    /**
     * Create a sequence containing a vector of objects.
     * @param v the vector of objects to make up the sequence.
     */
    public DERSequence(
        ASN1EncodableVector v)
    {
        super(v);
    }

    /**
     * Create a sequence containing an array of objects.
     * @param array the array of objects to make up the sequence.
     */
    public DERSequence(
        ASN1Encodable[]   array)
    {
        super(array);
    }

    DERSequence(ASN1Encodable[] array, boolean clone)
    {
        super(array, clone);
    }

    private int getBodyLength()
        throws IOException
    {
        if (bodyLength < 0)
        {
            int count = elements.length;
            int totalLength = 0;

            for (int i = 0; i < count; ++i)
            {
                ASN1Primitive derObject = elements[i].toASN1Primitive().toDERObject();
                totalLength += derObject.encodedLength();
            }

            this.bodyLength = totalLength;
        }

        return bodyLength;
    }

    int encodedLength()
        throws IOException
    {
        int length = getBodyLength();

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    /*
     * A note on the implementation:
     * <p>
     * As DER requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SEQUENCE,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    void encode(ASN1OutputStream out) throws IOException
    {
        out.write(BERTags.SEQUENCE | BERTags.CONSTRUCTED);

        DEROutputStream derOut = out.getDERSubStream();

        int count = elements.length;
        if (bodyLength >= 0 || count > 16)
        {
            out.writeLength(getBodyLength());

            for (int i = 0; i < count; ++i)
            {
                ASN1Primitive derObject = elements[i].toASN1Primitive().toDERObject();
                derObject.encode(derOut);
            }
        }
        else
        {
            int totalLength = 0;

            ASN1Primitive[] derObjects = new ASN1Primitive[count];
            for (int i = 0; i < count; ++i)
            {
                ASN1Primitive derObject = elements[i].toASN1Primitive().toDERObject();
                derObjects[i] = derObject;
                totalLength += derObject.encodedLength();
            }

            this.bodyLength = totalLength;
            out.writeLength(totalLength);

            for (int i = 0; i < count; ++i)
            {
                derObjects[i].encode(derOut);
            }
        }
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
