package org.bouncycastle.asn1;

/**
 * DER VisibleString object encoding ISO 646 (ASCII) character code points 32 to 126.
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public class DERVisibleString
    extends ASN1VisibleString
{
    /**
     * Return a Visible String from the passed in object.
     *
     * @param obj a DERVisibleString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERVisibleString instance, or null
     * 
     * @deprecated Use {@link ASN1VisibleString#getInstance(Object)} instead.
     */
    public static DERVisibleString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERVisibleString)
        {
            return (DERVisibleString)obj;
        }
        if (obj instanceof ASN1VisibleString)
        {
            return new DERVisibleString(((ASN1VisibleString)obj).contents, false);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (DERVisibleString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a Visible String from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERVisibleString instance, or null
     * 
     * @deprecated Use
     *             {@link ASN1VisibleString#getInstance(ASN1TaggedObject, boolean)}
     *             instead.
     */
    public static DERVisibleString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERVisibleString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERVisibleString(ASN1OctetString.getInstance(o).getOctets(), true);
        }
    }

    /**
     * Basic constructor
     *
     * @param string the string to be carried in the VisibleString object,
     */
    public DERVisibleString(String string)
    {
        super(string);
    }

    DERVisibleString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
