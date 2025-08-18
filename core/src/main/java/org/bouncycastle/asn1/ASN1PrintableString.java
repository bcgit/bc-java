package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * ASN.1 PrintableString object.
 * <p>
 * X.680 section 37.4 defines PrintableString character codes as ASCII subset of following characters:
 * </p>
 * <ul>
 * <li>Latin capital letters: 'A' .. 'Z'</li>
 * <li>Latin small letters: 'a' .. 'z'</li>
 * <li>Digits: '0'..'9'</li>
 * <li>Space</li>
 * <li>Apostrophe: '\''</li>
 * <li>Left parenthesis: '('</li>
 * <li>Right parenthesis: ')'</li>
 * <li>Plus sign: '+'</li>
 * <li>Comma: ','</li>
 * <li>Hyphen-minus: '-'</li>
 * <li>Full stop: '.'</li>
 * <li>Solidus: '/'</li>
 * <li>Colon: ':'</li>
 * <li>Equals sign: '='</li>
 * <li>Question mark: '?'</li>
 * </ul>
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public abstract class ASN1PrintableString
    extends ASN1Primitive
    implements ASN1String
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1PrintableString.class, BERTags.PRINTABLE_STRING)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return a printable string from the passed in object.
     *
     * @param obj an ASN1PrintableString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1PrintableString instance, or null.
     */
    public static ASN1PrintableString getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1PrintableString)
        {
            return (ASN1PrintableString)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1PrintableString)
            {
                return (ASN1PrintableString)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1PrintableString)TYPE.fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a Printable String from a tagged object.
     *
     * @param taggedObject the tagged object holding the object we want
     * @param declaredExplicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return an ASN1PrintableString instance, or null.
     */
    public static ASN1PrintableString getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return (ASN1PrintableString)TYPE.getContextTagged(taggedObject, declaredExplicit);
    }

    public static ASN1PrintableString getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return (ASN1PrintableString)TYPE.getTagged(taggedObject, declaredExplicit);
    }

    final byte[] contents;

    /**
     * Constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws IllegalArgumentException if validate is true and the string
     * contains characters that should not be in a PrintableString.
     */
    ASN1PrintableString(String string, boolean validate)
    {
        if (validate && !isPrintableString(string))
        {
            throw new IllegalArgumentException("string contains illegal characters");
        }

        this.contents = Strings.toByteArray(string);
    }

    ASN1PrintableString(byte[] contents, boolean clone)
    {
        this.contents = clone ? Arrays.clone(contents) : contents;
    }

    public final String getString()
    {
        return Strings.fromByteArray(contents);
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
        out.writeEncodingDL(withTag, BERTags.PRINTABLE_STRING, contents);
    }

    final boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1PrintableString))
        {
            return false;
        }

        ASN1PrintableString that = (ASN1PrintableString)other;

        return Arrays.areEqual(this.contents, that.contents);
    }

    public final int hashCode()
    {
        return Arrays.hashCode(contents);
    }

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
        String  str)
    {
        for (int i = str.length() - 1; i >= 0; i--)
        {
            char    ch = str.charAt(i);

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

    static ASN1PrintableString createPrimitive(byte[] contents)
    {
        return new DERPrintableString(contents, false);
    }
}
