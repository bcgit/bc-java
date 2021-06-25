package org.bouncycastle.asn1;

/**
 * DER BMPString object encodes BMP (<i>Basic Multilingual Plane</i>) subset
 * (aka UCS-2) of UNICODE (ISO 10646) characters in codepoints 0 to 65535.
 * <p>
 * At ISO-10646:2011 the term "BMP" has been withdrawn, and replaced by
 * term "UCS-2".
 * </p>
 */
public class DERBMPString
    extends ASN1BMPString
{
    /**
     * Return a BMP String from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERBMPString instance, or null.
     * 
     * @deprecated Use {@link ASN1BMPString#getInstance(Object)} instead.
     */
    public static DERBMPString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERBMPString)
        {
            return (DERBMPString)obj;
        }
        if (obj instanceof ASN1BMPString)
        {
            return new DERBMPString(((ASN1BMPString)obj).string);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (DERBMPString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a BMP String from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERBMPString instance.
     * 
     * @deprecated Use {@link ASN1BMPString#getInstance(ASN1TaggedObject, boolean)}
     *             instead.
     */
    public static DERBMPString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERBMPString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERBMPString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * Basic constructor
     * @param string a String to wrap as a BMP STRING.
     */
    public DERBMPString(String string)
    {
        super(string);
    }

    /**
     * Basic constructor - byte encoded string.
     * @param string the encoded BMP STRING to wrap.
     */
    DERBMPString(byte[] contents)
    {
        super(contents);
    }

    DERBMPString(char[] string)
    {
        super(string);
    }
}
