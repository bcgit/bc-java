package com.github.gv2011.asn1;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.util.bytes.Bytes;

/**
 * DER PrintableString object.
 */
public class DERPrintableString
    extends ASN1Primitive
    implements ASN1String
{
    private final Bytes string;

    /**
     * return a printable string from the passed in object.
     *
     * @param obj a DERPrintableString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERPrintableString instance, or null.
     */
    public static DERPrintableString getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DERPrintableString)
        {
            return (DERPrintableString)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (DERPrintableString)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a Printable String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return a DERPrintableString instance, or null.
     */
    public static DERPrintableString getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERPrintableString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERPrintableString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * basic constructor - byte encoded string.
     */
    DERPrintableString(
        final Bytes   string)
    {
        this.string = string;
    }

    /**
     * basic constructor - this does not validate the string
     */
    public DERPrintableString(
        final String   string)
    {
        this(string, false);
    }

    /**
     * Constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws IllegalArgumentException if validate is true and the string
     * contains characters that should not be in a PrintableString.
     */
    public DERPrintableString(
        final String   string,
        final boolean  validate)
    {
        if (validate && !isPrintableString(string))
        {
            throw new IllegalArgumentException("string contains illegal characters");
        }

        this.string = Strings.toByteArray(string);
    }

    @Override
    public String getString()
    {
        return Strings.fromByteArray(string);
    }

    public Bytes getOctets()
    {
        return string;
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.size()) + string.size();
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.PRINTABLE_STRING, string);
    }

    @Override
    public int hashCode()
    {
        return string.hashCode();
    }

    @Override
    boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof DERPrintableString))
        {
            return false;
        }

        final DERPrintableString  s = (DERPrintableString)o;

        return string.equals(s.string);
    }

    @Override
    public String toString()
    {
        return getString();
    }

    /**
     * return true if the passed in String can be represented without
     * loss as a PrintableString, false otherwise.
     *
     * @return true if in printable set, false otherwise.
     */
    public static boolean isPrintableString(
        final String  str)
    {
        for (int i = str.length() - 1; i >= 0; i--)
        {
            final char    ch = str.charAt(i);

            if (ch > 0x007f)
            {
                return false;
            }

            if ('a' <= ch && ch <= 'z')
            {
                continue;
            }

            if ('A' <= ch && ch <= 'Z')
            {
                continue;
            }

            if ('0' <= ch && ch <= '9')
            {
                continue;
            }

            switch (ch)
            {
            case ' ':
            case '\'':
            case '(':
            case ')':
            case '+':
            case '-':
            case '.':
            case ':':
            case '=':
            case '?':
            case '/':
            case ',':
                continue;
            }

            return false;
        }

        return true;
    }
}
