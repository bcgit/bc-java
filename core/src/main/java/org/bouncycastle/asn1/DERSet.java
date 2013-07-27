package org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

/**
 * A DER encoded set object
 * <p>
 * For syntax rules, see {@link ASN1Set} document.
 * <p>
 * For short: Constructing this form does sort the supplied elements,
 * and the sorting happens also before serialization (if necesssary).
 * This is different from the way how e.g. {@link BERSet} does things.
 */
public class DERSet
    extends ASN1Set
{
    private int bodyLength = -1;

    /**
     * Create an empty set
     */
    public DERSet()
    {
    }

    /**
     * Create a SET object from ASN1Encodable.
     * 
     * @param obj - a single object that makes up the set.
     */
    public DERSet(
        ASN1Encodable obj)
    {
        super(obj);
    }

    /**
     * Create a SET object from a vector of ASN1Encodable items,
     * and order the items into ascending binary order.
     * 
     * @param v - a vector of objects making up the set.
     */
    public DERSet(
        ASN1EncodableVector v)
    {
        super(v, true);
    }
    
    /**
     * Create a SET from an array of ASN1Encodable objects,
     * and order the items into ascending binary order.
     */
    public DERSet(
        ASN1Encodable[]   a)
    {
        super(a, true);
    }

    DERSet(
        ASN1EncodableVector v,
        boolean                  doSort)
    {
        super(v, doSort);
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
     * ASN.1 descriptions given. Rather than just outputting SET,
     * we also have to specify CONSTRUCTED, and the objects length.
     */
    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        ASN1OutputStream        dOut = out.getDERSubStream();
        int                     length = getBodyLength();

        out.write(BERTags.SET | BERTags.CONSTRUCTED);
        out.writeLength(length);

        for (Enumeration e = this.getObjects(); e.hasMoreElements();)
        {
            Object    obj = e.nextElement();

            dOut.writeObject((ASN1Encodable)obj);
        }
    }
}
