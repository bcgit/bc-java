package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

/**
 * Carrier class for an indefinite-length SEQUENCE.
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
