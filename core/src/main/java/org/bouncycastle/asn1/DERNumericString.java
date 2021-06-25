package org.bouncycastle.asn1;

/**
 * DER NumericString object - this is an ascii string of characters {0,1,2,3,4,5,6,7,8,9, }.
 * ASN.1 NUMERIC-STRING object.
 * <p>
 * This is an ASCII string of characters {0,1,2,3,4,5,6,7,8,9} + space.
 * <p>
 * See X.680 section 37.2.
 * <p>
 * Explicit character set escape sequences are not allowed.
 */
public class DERNumericString
    extends ASN1NumericString
{
    /**
     * Return a Numeric string from the passed in object
     *
     * @param obj a DERNumericString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERNumericString instance, or null
     * 
     * @deprecated Use {@link ASN1NumericString#getInstance(Object)} instead.
     */
    public static DERNumericString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERNumericString)
        {
            return (DERNumericString)obj;
        }
        if (obj instanceof ASN1NumericString)
        {
            return new DERNumericString(((ASN1NumericString)obj).contents, false);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (DERNumericString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an Numeric String from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERNumericString instance, or null.
     * 
     * @deprecated Use
     *             {@link ASN1NumericString#getInstance(ASN1TaggedObject, boolean)}
     *             instead.
     */
    public static DERNumericString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERNumericString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERNumericString(ASN1OctetString.getInstance(o).getOctets(), true);
        }
    }

    /**
     * Basic constructor -  without validation..
     */
    public DERNumericString(String string)
    {
        this(string, false);
    }

    /**
     * Constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws IllegalArgumentException if validate is true and the string
     * contains characters that should not be in a NumericString.
     */
    public DERNumericString(String string, boolean validate)
    {
        super(string, validate);
    }

    DERNumericString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
