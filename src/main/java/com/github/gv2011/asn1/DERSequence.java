package com.github.gv2011.asn1;

import java.util.Enumeration;

public class DERSequence
    extends ASN1Sequence
{
    private int bodyLength = -1;

    /**
     * create an empty sequence
     */
    public DERSequence()
    {
    }

    /**
     * create a sequence containing one object
     * @param obj the object to go in the sequence.
     */
    public DERSequence(
        final ASN1Encodable obj)
    {
        super(obj);
    }

    /**
     * create a sequence containing a vector of objects.
     * @param v the vector of objects to make up the sequence.
     */
    public DERSequence(
        final ASN1EncodableVector v)
    {
        super(v);
    }

    /**
     * create a sequence containing an array of objects.
     * @param array the array of objects to make up the sequence.
     */
    public DERSequence(
        final ASN1Encodable[]   array)
    {
        super(array);
    }

    private int getBodyLength()
    {
        if (bodyLength < 0)
        {
            int length = 0;

            for (final Enumeration<?> e = getObjects(); e.hasMoreElements();)
            {
                final Object    obj = e.nextElement();

                length += ((ASN1Encodable)obj).toASN1Primitive().toDERObject().encodedLength();
            }

            bodyLength = length;
        }

        return bodyLength;
    }

    @Override
    int encodedLength()
    {
        final int length = getBodyLength();

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
    @Override
    void encode(
        final ASN1OutputStream out)
    {
        final ASN1OutputStream        dOut = out.getDERSubStream();
        final int                     length = getBodyLength();

        out.write(BERTags.SEQUENCE | BERTags.CONSTRUCTED);
        out.writeLength(length);

        for (final Enumeration<?> e = getObjects(); e.hasMoreElements();)
        {
            final Object    obj = e.nextElement();

            dOut.writeObject((ASN1Encodable)obj);
        }
    }
}
