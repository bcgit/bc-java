package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

/**
 * Indefinite length SEQUENCE of objects.
 * <p>
 * Length field has value 0x80, and the sequence ends with two bytes of: 0x00, 0x00.
 * </p><p>
 * For X.690 syntax rules, see {@link ASN1Sequence}.
 * </p>
 */
public class BERSequence
    extends ASN1Sequence
{
    /**
     * Create an empty sequence
     */
    public BERSequence()
    {
    }

    /**
     * Create a sequence containing one object
     */
    public BERSequence(
        ASN1Encodable obj)
    {
        super(obj);
    }

    /**
     * Create a sequence containing a vector of objects.
     */
    public BERSequence(
        ASN1EncodableVector v)
    {
        super(v);
    }

    /**
     * Create a sequence containing an array of objects.
     */
    public BERSequence(
        ASN1Encodable[]   array)
    {
        super(array);
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
        out.write(BERTags.SEQUENCE | BERTags.CONSTRUCTED);
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
