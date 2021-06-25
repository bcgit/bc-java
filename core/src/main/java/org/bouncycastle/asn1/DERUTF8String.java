package org.bouncycastle.asn1;

/**
 * DER UTF8String object.
 */
public class DERUTF8String
    extends ASN1UTF8String
{
    /**
     * Return an UTF8 string from the passed in object.
     *
     * @param obj a DERUTF8String or an object that can be converted into one.
     * @exception IllegalArgumentException
     *                if the object cannot be converted.
     * @return a DERUTF8String instance, or null
     * 
     * @deprecated Use {@link ASN1UTF8String#getInstance(Object)} instead.
     */
    public static DERUTF8String getInstance(Object obj)
    {
        if (obj == null || obj instanceof DERUTF8String)
        {
            return (DERUTF8String)obj;
        }
        if (obj instanceof ASN1UTF8String)
        {
            return new DERUTF8String(((ASN1UTF8String)obj).contents, false);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (DERUTF8String)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
                + obj.getClass().getName());
    }

    /**
     * Return an UTF8 String from a tagged object.
     * 
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERUTF8String instance, or null
     * 
     * @deprecated Use {@link ASN1UTF8String#getInstance(ASN1TaggedObject, boolean)}
     *             instead.
     */
    public static DERUTF8String getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERUTF8String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERUTF8String(ASN1OctetString.getInstance(o).getOctets(), true);
        }
    }

    /**
     * Basic constructor
     *
     * @param string the string to be carried in the UTF8String object,
     */
    public DERUTF8String(String string)
    {
        super(string);
    }

    DERUTF8String(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
