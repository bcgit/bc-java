package com.github.gv2011.asn1;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.util.bytes.Bytes;

public final class DERGraphicString extends ASN1PrimitiveBytes implements ASN1String {

    /**
     * return a Graphic String from the passed in object
     *
     * @param obj a DERGraphicString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERGraphicString instance, or null.
     */
    public static DERGraphicString getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DERGraphicString)
        {
            return (DERGraphicString)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (DERGraphicString)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a Graphic String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return a DERGraphicString instance, or null.
     */
    public static DERGraphicString getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERGraphicString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERGraphicString(((ASN1OctetString)o).getOctets());
        }
    }

    /**
     * basic constructor - with bytes.
     * @param string the byte encoding of the characters making up the string.
     */
    public DERGraphicString(final Bytes string){
      super(string);
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
        out.writeEncoded(BERTags.GRAPHIC_STRING, string);
    }

    @Override
    public String getString()
    {
        return Strings.fromByteArray(string);
    }
}
