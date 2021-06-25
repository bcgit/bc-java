package org.bouncycastle.asn1;

/**
 * ASN.1 GENERAL-STRING data type.
 * <p>
 * This is an 8-bit encoded ISO 646 (ASCII) character set
 * with optional escapes to other character sets.
 * </p>
 */
public class DERGeneralString 
    extends ASN1GeneralString
{
    /**
     * Return a GeneralString from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERBMPString instance, or null.
     * 
     * @deprecated Use {@link ASN1GeneralString#getInstance(Object)} instead.
     */
    public static DERGeneralString getInstance(
        Object obj) 
    {
        if (obj == null || obj instanceof DERGeneralString) 
        {
            return (DERGeneralString) obj;
        }
        if (obj instanceof ASN1GeneralString)
        {
            return new DERGeneralString(((ASN1GeneralString)obj).contents, false);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (DERGeneralString)fromByteArray((byte[])obj);
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
     * Return a GeneralString from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERGeneralString instance.
     * 
     * @deprecated Use
     *             {@link ASN1GeneralString#getInstance(ASN1TaggedObject, boolean)}
     *             instead.
     */
    public static DERGeneralString getInstance(
        ASN1TaggedObject obj, 
        boolean explicit) 
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERGeneralString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERGeneralString(ASN1OctetString.getInstance(o).getOctets(), true);
        }
    }

    /**
     * Construct a GeneralString from the passed in String.
     *
     * @param string the string to be contained in this object.
     */
    public DERGeneralString(String string)
    {
        super(string);
    }

    DERGeneralString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
