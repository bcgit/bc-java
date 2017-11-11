package com.github.gv2011.asn1;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.util.bytes.Bytes;

/**
 * DER T61String (also the teletex string), try not to use this if you don't need to. The standard support the encoding for
 * this has been withdrawn.
 */
public final class DERT61String
    extends ASN1PrimitiveBytes
    implements ASN1String
{

    /**
     * return a T61 string from the passed in object.
     *
     * @param obj a DERT61String or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERT61String instance, or null
     */
    public static DERT61String getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DERT61String)
        {
            return (DERT61String)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (DERT61String)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an T61 String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return a DERT61String instance, or null
     */
    public static DERT61String getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERT61String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERT61String(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * basic constructor - string encoded as a sequence of bytes.
     *
     * @param string the byte encoding of the string to be wrapped.
     */
    public DERT61String(
        final Bytes   string)
    {
        super(string);
    }

    /**
     * basic constructor - with string 8 bit assumed.
     *
     * @param string the string to be wrapped.
     */
    public DERT61String(
        final String   string)
    {
        this(Strings.toByteArray(string));
    }

    /**
     * Decode the encoded string and return it, 8 bit encoding assumed.
     * @return the decoded String
     */
    @Override
    public String getString()
    {
        return Strings.fromByteArray(string);
    }

    @Override
    public String toString()
    {
        return getString();
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.T61_STRING, string);
    }

}
