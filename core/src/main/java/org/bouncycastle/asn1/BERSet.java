package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Indefinite length <code>SET</code> and <code>SET OF</code> constructs.
 * <p>
 * Note: This does not know which syntax the set is!
 * </p><p>
 * Length field has value 0x80, and the set ends with two bytes of: 0x00, 0x00.
 * </p><p>
 * For X.690 syntax rules, see {@link ASN1Set}.
 * </p><p>
 * In brief: Constructing this form does not sort the supplied elements,
 * nor does the sorting happen before serialization. This is different
 * from the way {@link DERSet} does things.
 * </p>
 */
public class BERSet
    extends ASN1Set
{
    /**
     * Create an empty SET.
     */
    public BERSet()
    {
    }

    /**
     * Create a SET containing one object.
     *
     * @param element - a single object that makes up the set.
     */
    public BERSet(ASN1Encodable element)
    {
        super(element);
    }

    /**
     * Create a SET containing multiple objects.
     * @param elementVector a vector of objects making up the set.
     */
    public BERSet(ASN1EncodableVector elementVector)
    {
        super(elementVector, false);
    }

    /**
     * Create a SET from an array of objects.
     * @param elements an array of ASN.1 objects.
     */
    public BERSet(ASN1Encodable[] elements)
    {
        super(elements, false);
    }

    BERSet(boolean isSorted, ASN1Encodable[] elements)
    {
        super(isSorted, elements);
    }

    int encodedLength(boolean withTag) throws IOException
    {
        int totalLength = withTag ? 4 : 3;

        for (ASN1Encodable element : elements)
        {
            ASN1Primitive p = element.toASN1Primitive();
            totalLength += p.encodedLength(true);
        }

        return totalLength;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingIL(withTag, BERTags.CONSTRUCTED | BERTags.SET, elements);
    }
}
