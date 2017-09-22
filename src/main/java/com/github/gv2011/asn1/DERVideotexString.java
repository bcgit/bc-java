package com.github.gv2011.asn1;

import java.io.IOException;

import com.github.gv2011.asn1.util.Arrays;
import com.github.gv2011.asn1.util.Strings;

public class DERVideotexString
    extends ASN1Primitive
    implements ASN1String
{
    private final byte[] string;

    /**
     * return a Videotex String from the passed in object
     *
     * @param obj a DERVideotexString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERVideotexString instance, or null.
     */
    public static DERVideotexString getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DERVideotexString)
        {
            return (DERVideotexString)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERVideotexString)fromByteArray((byte[])obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a Videotex String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return a DERVideotexString instance, or null.
     */
    public static DERVideotexString getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERVideotexString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERVideotexString(((ASN1OctetString)o).getOctets());
        }
    }

    /**
     * basic constructor - with bytes.
     * @param string the byte encoding of the characters making up the string.
     */
    public DERVideotexString(
        final byte[]   string)
    {
        this.string = Arrays.clone(string);
    }

    public byte[] getOctets()
    {
        return Arrays.clone(string);
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.VIDEOTEX_STRING, string);
    }

    @Override
    public int hashCode()
    {
        return Arrays.hashCode(string);
    }

    @Override
    boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof DERVideotexString))
        {
            return false;
        }

        final DERVideotexString  s = (DERVideotexString)o;

        return Arrays.areEqual(string, s.string);
    }

    @Override
    public String getString()
    {
        return Strings.fromByteArray(string);
    }
}
