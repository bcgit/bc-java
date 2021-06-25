package org.bouncycastle.asn1;

/**
 * DER T61String (also the teletex string), try not to use this if you don't need to. The standard support the encoding for
 * this has been withdrawn.
 */
public class DERT61String
    extends ASN1T61String
{
    /**
     * Return a T61 string from the passed in object.
     *
     * @param obj a DERT61String or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERT61String instance, or null
     * 
     * @deprecated Use {@link ASN1T61String#getInstance(Object)} instead.
     */
    public static DERT61String getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERT61String)
        {
            return (DERT61String)obj;
        }
        if (obj instanceof ASN1T61String)
        {
            return new DERT61String(((ASN1T61String)obj).contents, false);
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (DERT61String)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an T61 String from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERT61String instance, or null
     * 
     * @deprecated Use {@link ASN1T61String#getInstance(ASN1TaggedObject, boolean)}
     *             instead.
     */
    public static DERT61String getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERT61String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERT61String(ASN1OctetString.getInstance(o).getOctets(), true);
        }
    }

    /**
     * Basic constructor - with string 8 bit assumed.
     *
     * @param string the string to be wrapped.
     */
    public DERT61String(String string)
    {
        super(string);
    }

    /**
     * Basic constructor - string encoded as a sequence of bytes.
     *
     * @param string the byte encoding of the string to be wrapped.
     */
    public DERT61String(byte[] string)
    {
        this(string, true);
    }

    DERT61String(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
