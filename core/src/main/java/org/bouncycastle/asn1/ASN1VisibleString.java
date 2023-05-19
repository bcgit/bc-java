package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * ASN.1 VisibleString object encoding ISO 646 (ASCII) character code points 32 to 126.
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public abstract class ASN1VisibleString
    extends ASN1Primitive
    implements ASN1String
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1VisibleString.class, BERTags.VISIBLE_STRING)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return a Visible String from the passed in object.
     *
     * @param obj an ASN1VisibleString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1VisibleString instance, or null
     */
    public static ASN1VisibleString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1VisibleString)
        {
            return (ASN1VisibleString)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1VisibleString)
            {
                return (ASN1VisibleString)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1VisibleString)TYPE.fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a Visible String from a tagged object.
     *
     * @param taggedObject the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return an ASN1VisibleString instance, or null
     */
    public static ASN1VisibleString getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1VisibleString)TYPE.getContextInstance(taggedObject, explicit);
    }

    final byte[] contents;

    ASN1VisibleString(String string)
    {
        this.contents = Strings.toByteArray(string);
    }

    ASN1VisibleString(byte[] contents, boolean clone)
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
        out.writeEncodingDL(withTag, BERTags.VISIBLE_STRING, contents);
    }

    final boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1VisibleString))
        {
            return false;
        }

        ASN1VisibleString that = (ASN1VisibleString)other;

        return Arrays.areEqual(this.contents, that.contents);
    }

    public final int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    static ASN1VisibleString createPrimitive(byte[] contents)
    {
        return new DERVisibleString(contents, false);
    }
}
