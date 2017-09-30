package com.github.gv2011.asn1;

import java.util.Enumeration;

/**
 * Carrier class for an indefinite-length SET.
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
        final ASN1Encodable obj)
    {
        super(obj);
    }

    /**
     * Create a SET containing multiple objects.
     * @param v a vector of objects making up the set.
     */
    public BERSet(
        final ASN1EncodableVector v)
    {
        super(v, false);
    }

    /**
     * Create a SET from an array of objects.
     * @param a an array of ASN.1 objects.
     */
    public BERSet(
        final ASN1Encodable[]   a)
    {
        super(a, false);
    }

    @Override
    int encodedLength()
    {
        int length = 0;
        for (final Enumeration<?> e = getObjects(); e.hasMoreElements();)
        {
            length += ((ASN1Encodable)e.nextElement()).toASN1Primitive().encodedLength();
        }

        return 2 + length + 2;
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.write(BERTags.SET | BERTags.CONSTRUCTED);
        out.write(0x80);

        final Enumeration<?> e = getObjects();
        while (e.hasMoreElements())
        {
            out.writeObject((ASN1Encodable)e.nextElement());
        }

        out.write(0x00);
        out.write(0x00);
    }
}