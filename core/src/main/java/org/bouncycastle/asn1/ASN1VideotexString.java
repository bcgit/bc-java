package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public abstract class ASN1VideotexString
    extends ASN1Primitive
    implements ASN1String
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1VideotexString.class, BERTags.VIDEOTEX_STRING)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * return a Videotex String from the passed in object
     *
     * @param obj an ASN1VideotexString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1VideotexString instance, or null.
     */
    public static ASN1VideotexString getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1VideotexString)
        {
            return (ASN1VideotexString)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1VideotexString)
            {
                return (ASN1VideotexString)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1VideotexString)TYPE.fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return a Videotex String from a tagged object.
     *
     * @param taggedObject the tagged object holding the object we want
     * @param explicit     true if the object is meant to be explicitly tagged false
     *                     otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return an ASN1VideotexString instance, or null.
     */
    public static ASN1VideotexString getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1VideotexString)TYPE.getContextInstance(taggedObject, explicit);
    }

    final byte[] contents;

    /**
     * basic constructor - with bytes.
     * @param string the byte encoding of the characters making up the string.
     */
    ASN1VideotexString(byte[] contents, boolean clone)
    {
        this.contents = clone ? Arrays.clone(contents) : contents;
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
        out.writeEncodingDL(withTag, BERTags.VIDEOTEX_STRING, contents);
    }

    final boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1VideotexString))
        {
            return false;
        }

        ASN1VideotexString that = (ASN1VideotexString)other;

        return Arrays.areEqual(this.contents, that.contents);
    }

    public final int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    public final String getString()
    {
        return Strings.fromByteArray(contents);
    }

    static ASN1VideotexString createPrimitive(byte[] contents)
    {
        return new DERVideotexString(contents, false);
    }
}
