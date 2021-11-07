package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * NumericString object - this is an ascii string of characters {0,1,2,3,4,5,6,7,8,9, }.
 * ASN.1 NUMERIC-STRING object.
 * <p>
 * This is an ASCII string of characters {0,1,2,3,4,5,6,7,8,9} + space.
 * <p>
 * See X.680 section 37.2.
 * <p>
 * Explicit character set escape sequences are not allowed.
 */
public abstract class ASN1NumericString
    extends ASN1Primitive
    implements ASN1String
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1NumericString.class, BERTags.NUMERIC_STRING)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return a Numeric string from the passed in object
     *
     * @param obj an ASN1NumericString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1NumericString instance, or null
     */
    public static ASN1NumericString getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1NumericString)
        {
            return (ASN1NumericString)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1NumericString)
            {
                return (ASN1NumericString)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1NumericString)TYPE.fromByteArray((byte[])obj);
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
     * @param taggedObject the tagged object holding the object we want
     * @param explicit     true if the object is meant to be explicitly tagged false
     *                     otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return an ASN1NumericString instance, or null.
     */
    public static ASN1NumericString getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1NumericString)TYPE.getContextInstance(taggedObject, explicit);
    }

    final byte[] contents;

    /**
     * Constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws IllegalArgumentException if validate is true and the string
     * contains characters that should not be in a NumericString.
     */
    ASN1NumericString(String string, boolean validate)
    {
        if (validate && !isNumericString(string))
        {
            throw new IllegalArgumentException("string contains illegal characters");
        }

        this.contents = Strings.toByteArray(string);
    }

    ASN1NumericString(byte[] contents, boolean clone)
    {
        this.contents = clone ? Arrays.clone(contents) : contents;
    }

    public final String getString()
    {
        return Strings.fromByteArray(contents);
    }

    public String toString()
    {
        return getString();
    }

    public final byte[] getOctets()
    {
        return Arrays.clone(contents);
    }

    final boolean encodeConstructed()
    {
        return false;
    }

    final int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    final void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.NUMERIC_STRING, contents);
    }

    public final int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    final boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1NumericString))
        {
            return false;
        }

        ASN1NumericString that = (ASN1NumericString)other;

        return Arrays.areEqual(this.contents, that.contents);
    }

    /**
     * Return true if the string can be represented as a NumericString ('0'..'9', ' ')
     *
     * @param str string to validate.
     * @return true if numeric, false otherwise.
     */
    public static boolean isNumericString(String str)
    {
        for (int i = str.length() - 1; i >= 0; i--)
        {
            char ch = str.charAt(i);

            if (ch > 0x007f)
            {
                return false;
            }

            if (('0' <= ch && ch <= '9') || ch == ' ')
            {
                continue;
            }

            return false;
        }

        return true;
    }

    static boolean isNumericString(byte[] contents)
    {
        for (int i = 0; i < contents.length; ++i)
        {
            switch (contents[i])
            {
            case 0x20:
            case 0x30:
            case 0x31:
            case 0x32:
            case 0x33:
            case 0x34:
            case 0x35:
            case 0x36:
            case 0x37:
            case 0x38:
            case 0x39:
                break;
            default:
                return false;
            }
        }

        return true;
    }

    static ASN1NumericString createPrimitive(byte[] contents)
    {
        // TODO Validation - sort out exception types
//        if (!isNumericString(contents))

        return new DERNumericString(contents, false);
    }
}
