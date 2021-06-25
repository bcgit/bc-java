package org.bouncycastle.asn1;

/**
 * DER IA5String object - this is a ISO 646 (ASCII) string encoding code points 0 to 127.
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public class DERIA5String
    extends ASN1IA5String
{
    /**
     * Return an IA5 string from the passed in object
     *
     * @param obj a DERIA5String or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERIA5String instance, or null.
     * 
     * @deprecated Use {@link ASN1IA5String#getInstance(Object)} instead.
     */
    public static DERIA5String getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERIA5String)
        {
            return (DERIA5String)obj;
        }
        if (obj instanceof ASN1IA5String)
        {
            return new DERIA5String(((ASN1IA5String)obj).contents, false);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (DERIA5String)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an IA5 String from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERIA5String instance, or null.
     * 
     * @deprecated Use {@link ASN1IA5String#getInstance(ASN1TaggedObject, boolean)}
     *             instead.
     */
    public static DERIA5String getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERIA5String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERIA5String(ASN1OctetString.getInstance(o).getOctets(), true);
        }
    }

    /**
     * Basic constructor - without validation.
     * @param string the base string to use..
     */
    public DERIA5String(String string)
    {
        this(string, false);
    }

    /**
     * Constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws IllegalArgumentException if validate is true and the string
     * contains characters that should not be in an IA5String.
     */
    public DERIA5String(String string, boolean validate)
    {
        super(string, validate);
    }

    DERIA5String(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
