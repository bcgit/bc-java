package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

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
     * @param obj - a single object that makes up the set.
     */
    public BERSet(
        ASN1Encodable obj)
    {
        super(obj);
    }

    /**
     * Create a SET containing multiple objects.
     * @param v a vector of objects making up the set.
     */
    public BERSet(
        ASN1EncodableVector v)
    {
        super(v, false);
    }

    /**
     * Create a SET from an array of objects.
     * @param a an array of ASN.1 objects.
     */
    public BERSet(
        ASN1Encodable[]   a)
    {
        super(a, false);
    }

    int encodedLength()
        throws IOException
    {
        int length = 0;
        for (Enumeration e = getObjects(); e.hasMoreElements();)
        {
            length += ((ASN1Encodable)e.nextElement()).toASN1Primitive().encodedLength();
        }

        return 2 + length + 2;
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.write(BERTags.SET | BERTags.CONSTRUCTED);
        out.write(0x80);

        Enumeration e = getObjects();
        while (e.hasMoreElements())
        {
            out.writeObject((ASN1Encodable)e.nextElement());
        }

        out.write(0x00);
        out.write(0x00);
    }
}