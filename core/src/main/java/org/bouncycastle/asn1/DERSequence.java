package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

/**
 * Definite length SEQUENCE, encoding tells explicit number of bytes
 * that the content of this sequence occupies.
 * <p>
 * For X.690 syntax rules, see {@link ASN1Sequence}.
 */
public class DERSequence
    extends ASN1Sequence
{
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

    private int getBodyLength()
        throws IOException
    {
        if (bodyLength < 0)
        {
            int length = 0;

            for (Enumeration e = this.getObjects(); e.hasMoreElements();)
            {
                Object    obj = e.nextElement();

                length += ((ASN1Encodable)obj).toASN1Primitive().toDERObject().encodedLength();
            }

            bodyLength = length;
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
    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        ASN1OutputStream        dOut = out.getDERSubStream();
        int                     length = getBodyLength();

        out.write(BERTags.SEQUENCE | BERTags.CONSTRUCTED);
        out.writeLength(length);

        for (Enumeration e = this.getObjects(); e.hasMoreElements();)
        {
            Object    obj = e.nextElement();

            dOut.writeObject((ASN1Encodable)obj);
        }
    }
}
