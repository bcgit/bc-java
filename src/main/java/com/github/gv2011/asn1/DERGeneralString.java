package com.github.gv2011.asn1;

import java.io.IOException;

import com.github.gv2011.asn1.util.Arrays;
import com.github.gv2011.asn1.util.Strings;

/**
 * Carrier class for a DER encoding GeneralString
 */
public class DERGeneralString
    extends ASN1Primitive
    implements ASN1String
{
    private final byte[] string;

    /**
     * return a GeneralString from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERBMPString instance, or null.
     */
    public static DERGeneralString getInstance(
        final Object obj)
    {
        if (obj == null || obj instanceof DERGeneralString)
        {
            return (DERGeneralString) obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERGeneralString)fromByteArray((byte[])obj);
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
     * return a GeneralString from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *              be converted.
     * @return a DERGeneralString instance.
     */
    public static DERGeneralString getInstance(
        final ASN1TaggedObject obj,
        final boolean explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERGeneralString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERGeneralString(((ASN1OctetString)o).getOctets());
        }
    }

    DERGeneralString(final byte[] string)
    {
        this.string = string;
    }

    /**
     * Construct a GeneralString from the passed in String.
     *
     * @param string the string to be contained in this object.
     */
    public DERGeneralString(final String string)
    {
        this.string = Strings.toByteArray(string);
    }

    /**
     * Return a Java String representation of our contained String.
     *
     * @return a Java String representing our contents.
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

    /**
     * Return a byte array representation of our contained String.
     *
     * @return a byte array representing our contents.
     */
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
    void encode(final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.GENERAL_STRING, string);
    }

    @Override
    public int hashCode()
    {
        return Arrays.hashCode(string);
    }

    @Override
    boolean asn1Equals(final ASN1Primitive o)
    {
        if (!(o instanceof DERGeneralString))
        {
            return false;
        }
        final DERGeneralString s = (DERGeneralString)o;

        return Arrays.areEqual(string, s.string);
    }
}
