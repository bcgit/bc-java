package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A BIT STRING with DER encoding - the first byte contains the count of padding bits included in the byte array's last byte.
 */
public class DERBitString
    extends ASN1BitString
{
    public static DERBitString convert(ASN1BitString bitString)
    {
        return (DERBitString)bitString.toDERObject();
    }

    /**
     * return a Bit String from the passed in object
     *
     * @param obj a DERBitString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERBitString instance, or null.
     * 
     * @deprecated Use {@link ASN1BitString#getInstance(Object)} and
     *             {@link #convert(ASN1BitString)} instead.
     */
    public static DERBitString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERBitString)
        {
            return (DERBitString)obj;
        }
        if (obj instanceof ASN1BitString)
        {
            return convert((ASN1BitString)obj);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return convert((ASN1BitString)fromByteArray((byte[])obj));
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
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERBitString instance, or null.
     * 
     * @deprecated Use {@link ASN1BitString#getInstance(ASN1TaggedObject, boolean)}
     *             and {@link #convert(ASN1BitString)} instead.
     */
    public static DERBitString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERBitString)
        {
            return getInstance(o);
        }
        else
        {
            return fromOctetString(ASN1OctetString.getInstance(o));
        }
    }

    public DERBitString(byte[] data)
    {
        this(data, 0);
    }

    public DERBitString(byte data, int padBits)
    {
        super(data, padBits);
    }

    public DERBitString(byte[] data, int padBits)
    {
        super(data, padBits);
    }

    public DERBitString(int value)
    {
        // TODO[asn1] Unify in single allocation of 'contents'
        super(getBytes(value), getPadBits(value));
    }

    public DERBitString(ASN1Encodable obj) throws IOException
    {
        // TODO[asn1] Unify in single allocation of 'contents'
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    DERBitString(byte[] contents, boolean check)
    {
        super(contents, check);
    }

    boolean encodeConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        int padBits = contents[0] & 0xFF;
        int length = contents.length;
        int last = length - 1;

        byte lastOctet = contents[last];
        byte lastOctetDER = (byte)(contents[last] & (0xFF << padBits));

        if (lastOctet == lastOctetDER)
        {
            out.writeEncodingDL(withTag, BERTags.BIT_STRING, contents);
        }
        else
        {
            out.writeEncodingDL(withTag, BERTags.BIT_STRING, contents, 0, last, lastOctetDER);
        }
    }

    ASN1Primitive toDERObject()
    {
        return this;
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }

    static DERBitString fromOctetString(ASN1OctetString octetString)
    {
        return new DERBitString(octetString.getOctets(), true);
    }
}
