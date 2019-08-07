package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A Definite length BIT STRING
 */
public class DLBitString
    extends ASN1BitString
{
    /**
     * return a Bit String that can be definite-length encoded from the passed in object.
     *
     * @param obj a DL or DER BitString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1BitString instance, or null.
     */
    public static ASN1BitString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DLBitString)
        {
            return (DLBitString)obj;
        }
        if (obj instanceof DERBitString)
        {
            return (DERBitString)obj;
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1BitString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
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
     * @return an ASN1BitString instance, or null.
     */
    public static ASN1BitString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DLBitString)
        {
            return getInstance(o);
        }
        else
        {
            return fromOctetString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    protected DLBitString(byte data, int padBits)
    {
        super(data, padBits);
    }

    /**
     * @param data the octets making up the bit string.
     * @param padBits the number of extra bits at the end of the string.
     */
    public DLBitString(
        byte[]  data,
        int     padBits)
    {
        super(data, padBits);
    }

    public DLBitString(
        byte[]  data)
    {
        this(data, 0);
    }

    public DLBitString(
        int value)
    {
        super(getBytes(value), getPadBits(value));
    }

    public DLBitString(
        ASN1Encodable obj)
        throws IOException
    {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(data.length + 1) + data.length + 1;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncoded(withTag, BERTags.BIT_STRING, (byte)padBits, data);
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }

    static DLBitString fromOctetString(byte[] bytes)
    {
        if (bytes.length < 1)
        {
            throw new IllegalArgumentException("truncated BIT STRING detected");
        }

        int padBits = bytes[0];
        byte[] data = new byte[bytes.length - 1];

        if (data.length != 0)
        {
            System.arraycopy(bytes, 1, data, 0, bytes.length - 1);
        }

        return new DLBitString(data, padBits);
    }
}
