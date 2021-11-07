package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public abstract class ASN1UTF8String
    extends ASN1Primitive
    implements ASN1String
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1UTF8String.class, BERTags.UTF8_STRING)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    /**
     * Return a UTF8 string from the passed in object.
     *
     * @param obj an ASN1UTF8String or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1UTF8String instance, or null
     */
    public static ASN1UTF8String getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1UTF8String)
        {
            return (ASN1UTF8String)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1UTF8String)
            {
                return (ASN1UTF8String)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1UTF8String)TYPE.fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an UTF8 String from a tagged object.
     * 
     * @param taggedObject the tagged object holding the object we want
     * @param explicit     true if the object is meant to be explicitly tagged false
     *                     otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a DERUTF8String instance, or null
     */
    public static ASN1UTF8String getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1UTF8String)TYPE.getContextInstance(taggedObject, explicit);
    }

    final byte[] contents;

    ASN1UTF8String(String string)
    {
        this(Strings.toUTF8ByteArray(string), false);
    }

    ASN1UTF8String(byte[] contents, boolean clone)
    {
        this.contents = clone ? Arrays.clone(contents) : contents;
    }

    public final String getString()
    {
        return Strings.fromUTF8ByteArray(contents);
    }

    // TODO Not sure this is useful unless all ASN.1 types have a meaningful one
    public String toString()
    {
        return getString();
    }

    public final int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    final boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1UTF8String))
        {
            return false;
        }

        ASN1UTF8String that = (ASN1UTF8String)other;

        return Arrays.areEqual(this.contents, that.contents);
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
        out.writeEncodingDL(withTag, BERTags.UTF8_STRING, contents);
    }

    static ASN1UTF8String createPrimitive(byte[] contents)
    {
        return new DERUTF8String(contents, false);
    }
}
