package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A DER encoded SET object
 * <p>
 * For X.690 syntax rules, see {@link ASN1Set}.
 * </p><p>
 * For short: Constructing this form does sort the supplied elements,
 * and the sorting happens also before serialization (if necesssary).
 * This is different from the way {@link BERSet},{@link DLSet} does things.
 * </p>
 */
public class DERSet
    extends ASN1Set
{
    public static DERSet convert(ASN1Set set)
    {
        return (DERSet)set.toDERObject();
    }

    private int bodyLength = -1;

    /**
     * create an empty set
     */
    public DERSet()
    {
    }

    /**
     * create a set containing one object
     * @param element the object to go in the set
     */
    public DERSet(ASN1Encodable element)
    {
        super(element);
    }

    /**
     * create a set containing a vector of objects.
     * @param elementVector the vector of objects to make up the set.
     */
    public DERSet(ASN1EncodableVector elementVector)
    {
        super(elementVector, true);
    }

    /**
     * create a set containing an array of objects.
     * @param elements the array of objects to make up the set.
     */
    public DERSet(ASN1Encodable[] elements)
    {
        super(elements, true);
    }

    DERSet(boolean isSorted, ASN1Encodable[] elements)
    {
        super(checkSorted(isSorted), elements);
    }

    private int getBodyLength() throws IOException
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

    int encodedLength() throws IOException
    {
        int length = getBodyLength();

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    /*
     * A note on the implementation:
     * <p>
     * As DER requires the constructed, definite-length model to
     * be used for structured types, this varies slightly from the
     * ASN.1 descriptions given. Rather than just outputting SET,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        if (withTag)
        {
            out.write(BERTags.SET | BERTags.CONSTRUCTED);
        }

        DEROutputStream derOut = out.getDERSubStream();

        int count = elements.length;
        if (bodyLength >= 0 || count > 16)
        {
            out.writeLength(getBodyLength());

            for (int i = 0; i < count; ++i)
            {
                ASN1Primitive derObject = elements[i].toASN1Primitive().toDERObject();
                derObject.encode(derOut, true);
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
                derObjects[i].encode(derOut, true);
            }
        }
    }

    ASN1Primitive toDERObject()
    {
        return isSorted ? this : super.toDERObject();
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }

    private static boolean checkSorted(boolean isSorted)
    {
        if (!isSorted)
        {
            throw new IllegalStateException("DERSet elements should always be in sorted order");
        }
        return isSorted;
    }
}
