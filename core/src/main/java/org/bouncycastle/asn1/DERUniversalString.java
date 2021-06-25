package org.bouncycastle.asn1;

/**
 * DER UniversalString object - encodes UNICODE (ISO 10646) characters using 32-bit format. In Java we
 * have no way of representing this directly so we rely on byte arrays to carry these.
 */
public class DERUniversalString
    extends ASN1UniversalString
{
    /**
     * Return a Universal String from the passed in object.
     *
     * @param obj a DERUniversalString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERUniversalString instance, or null
     * 
     * @deprecated Use {@link ASN1UniversalString#getInstance(Object)} instead.
     */
    public static DERUniversalString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERUniversalString)
        {
            return (DERUniversalString)obj;
        }
        if (obj instanceof ASN1UniversalString)
        {
            return new DERUniversalString(((ASN1UniversalString)obj).contents, false);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (DERUniversalString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a Universal String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return a DERUniversalString instance, or null
     * 
     * @deprecated Use {@link ASN1UniversalString#getInstance(ASN1TaggedObject, boolean)}
     *             instead.
     */
    public static DERUniversalString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERUniversalString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERUniversalString(ASN1OctetString.getInstance(o).getOctets(), true);
        }
    }

    /**
     * Basic constructor - byte encoded string.
     *
     * @param string the byte encoding of the string to be carried in the UniversalString object,
     */
    public DERUniversalString(byte[] string)
    {
        this(string, true);
    }

    DERUniversalString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
