package com.github.gv2011.asn1;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.util.bytes.Bytes;

/**
 * DER UTF8String object.
 */
public class DERUTF8String
    extends ASN1PrimitiveBytes
    implements ASN1String
{

    /**
     * Return an UTF8 string from the passed in object.
     *
     * @param obj a DERUTF8String or an object that can be converted into one.
     * @exception IllegalArgumentException
     *                if the object cannot be converted.
     * @return a DERUTF8String instance, or null
     */
    public static DERUTF8String getInstance(final Object obj)
    {
        if (obj == null || obj instanceof DERUTF8String)
        {
            return (DERUTF8String)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (DERUTF8String)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
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
     * @param obj
     *            the tagged object holding the object we want
     * @param explicit
     *            true if the object is meant to be explicitly tagged false
     *            otherwise.
     * @exception IllegalArgumentException
     *                if the tagged object cannot be converted.
     * @return a DERUTF8String instance, or null
     */
    public static DERUTF8String getInstance(
        final ASN1TaggedObject obj,
        final boolean explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERUTF8String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERUTF8String(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /*
     * Basic constructor - byte encoded string.
     */
    DERUTF8String(final Bytes string)
    {
        super(string);
    }

    /**
     * Basic constructor
     *
     * @param string the string to be carried in the UTF8String object,
     */
    public DERUTF8String(final String string)
    {
        this(Strings.toUTF8ByteArray(string));
    }

    @Override
    public String getString()
    {
        return Strings.fromUTF8ByteArray(string);
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
    void encode(final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.UTF8_STRING, string);
    }
}
