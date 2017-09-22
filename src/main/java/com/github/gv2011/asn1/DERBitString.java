package com.github.gv2011.asn1;

import java.io.IOException;

/**
 * A BIT STRING with DER encoding.
 */
public class DERBitString
    extends ASN1BitString
{
    /**
     * return a Bit String from the passed in object
     *
     * @param obj a DERBitString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERBitString instance, or null.
     */
    public static DERBitString getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DERBitString)
        {
            return (DERBitString)obj;
        }
        if (obj instanceof DLBitString)
        {
            return new DERBitString(((DLBitString)obj).data, ((DLBitString)obj).padBits);
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a Bit String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return a DERBitString instance, or null.
     */
    public static DERBitString getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERBitString)
        {
            return getInstance(o);
        }
        else
        {
            return fromOctetString(((ASN1OctetString)o).getOctets());
        }
    }

    protected DERBitString(
        final byte    data,
        final int     padBits)
    {
        this(toByteArray(data), padBits);
    }

    private static byte[] toByteArray(final byte data)
    {
        final byte[] rv = new byte[1];

        rv[0] = data;

        return rv;
    }

    /**
     * @param data the octets making up the bit string.
     * @param padBits the number of extra bits at the end of the string.
     */
    public DERBitString(
        final byte[]  data,
        final int     padBits)
    {
        super(data, padBits);
    }

    public DERBitString(
        final byte[]  data)
    {
        this(data, 0);
    }

    public DERBitString(
        final int value)
    {
        super(getBytes(value), getPadBits(value));
    }

    public DERBitString(
        final ASN1Encodable obj)
        throws IOException
    {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(data.length + 1) + data.length + 1;
    }

    @Override
    void encode(
        final ASN1OutputStream  out)
    {
        final byte[] string = derForm(data, padBits);
        final byte[] bytes = new byte[string.length + 1];

        bytes[0] = (byte)getPadBits();
        System.arraycopy(string, 0, bytes, 1, bytes.length - 1);

        out.writeEncoded(BERTags.BIT_STRING, bytes);
    }

    static DERBitString fromOctetString(final byte[] bytes)
    {
        if (bytes.length < 1)
        {
            throw new IllegalArgumentException("truncated BIT STRING detected");
        }

        final int padBits = bytes[0];
        final byte[] data = new byte[bytes.length - 1];

        if (data.length != 0)
        {
            System.arraycopy(bytes, 1, data, 0, bytes.length - 1);
        }

        return new DERBitString(data, padBits);
    }
}
