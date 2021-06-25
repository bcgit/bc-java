package org.bouncycastle.asn1;

public class DERVideotexString
    extends ASN1VideotexString
{
    /**
     * return a Videotex String from the passed in object
     *
     * @param obj a DERVideotexString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERVideotexString instance, or null.
     * 
     * @deprecated Use {@link ASN1VideotexString#getInstance(Object)} instead.
     */
    public static DERVideotexString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERVideotexString)
        {
            return (DERVideotexString)obj;
        }
        if (obj instanceof ASN1VideotexString)
        {
            return new DERVideotexString(((ASN1VideotexString)obj).contents, false);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (DERVideotexString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a Videotex String from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERVideotexString instance, or null.
     * 
     * @deprecated Use
     *             {@link ASN1VideotexString#getInstance(ASN1TaggedObject, boolean)}
     *             instead.
     */
    public static DERVideotexString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERVideotexString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERVideotexString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    public DERVideotexString(byte[] octets)
    {
        this(octets, true);
    }

    DERVideotexString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
