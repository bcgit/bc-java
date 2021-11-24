package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * ASN.1 IA5String object - this is a ISO 646 (ASCII) string encoding code points 0 to 127.
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public abstract class ASN1IA5String
    extends ASN1Primitive
    implements ASN1String
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1IA5String.class, BERTags.IA5_STRING)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return an IA5 string from the passed in object
     *
     * @param obj an ASN1IA5String or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a ASN1IA5String instance, or null.
     */
    public static ASN1IA5String getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1IA5String)
        {
            return (ASN1IA5String)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1IA5String)
            {
                return (ASN1IA5String)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1IA5String)TYPE.fromByteArray((byte[])obj);
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
     * @param taggedObject the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return an ASN1IA5String instance, or null.
     */
    public static ASN1IA5String getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1IA5String)TYPE.getContextInstance(taggedObject, explicit);
    }

    final byte[] contents;

    ASN1IA5String(String string, boolean validate)
    {
        if (string == null)
        {
            throw new NullPointerException("'string' cannot be null");
        }
        if (validate && !isIA5String(string))
        {
            throw new IllegalArgumentException("'string' contains illegal characters");
        }

        this.contents = Strings.toByteArray(string);
    }

    ASN1IA5String(byte[] contents, boolean clone)
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
        out.writeEncodingDL(withTag, BERTags.IA5_STRING, contents);
    }

    final boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1IA5String))
        {
            return false;
        }

        ASN1IA5String that = (ASN1IA5String)other;

        return Arrays.areEqual(this.contents, that.contents);
    }

    public final int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    /**
     * return true if the passed in String can be represented without
     * loss as an IA5String, false otherwise.
     *
     * @param str the string to check.
     * @return true if character set in IA5String set, false otherwise.
     */
    public static boolean isIA5String(String str)
    {
        for (int i = str.length() - 1; i >= 0; i--)
        {
            char ch = str.charAt(i);
            if (ch > 0x007f)
            {
                return false;
            }
        }

        return true;
    }

    static ASN1IA5String createPrimitive(byte[] contents)
    {
        return new DERIA5String(contents, false);
    }
}
