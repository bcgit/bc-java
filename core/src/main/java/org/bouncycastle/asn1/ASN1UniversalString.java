package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * ASN.1 UniversalString object - encodes UNICODE (ISO 10646) characters using 32-bit format. In Java we
 * have no way of representing this directly so we rely on byte arrays to carry these.
 */
public abstract class ASN1UniversalString
    extends ASN1Primitive
    implements ASN1String
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1UniversalString.class, BERTags.UNIVERSAL_STRING)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    private static final char[]  table = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /**
     * Return a Universal String from the passed in object.
     *
     * @param obj an ASN1UniversalString or an object that can be converted into
     *            one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1UniversalString instance, or null
     */
    public static ASN1UniversalString getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1UniversalString)
        {
            return (ASN1UniversalString)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1UniversalString)
            {
                return (ASN1UniversalString)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1UniversalString)TYPE.fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a Universal String from a tagged object.
     *
     * @param taggedObject      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a ASN1UniversalString instance, or null
     */
    public static ASN1UniversalString getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1UniversalString)TYPE.getContextInstance(taggedObject, explicit);
    }

    final byte[] contents;

    ASN1UniversalString(byte[] contents, boolean clone)
    {
        this.contents = clone ? Arrays.clone(contents) : contents;
    }

    public final String getString()
    {
        int dl = contents.length;
        StringBuffer buf = new StringBuffer(3 + 2 * (ASN1OutputStream.getLengthOfDL(dl) + dl));
        buf.append("#1C");
        encodeHexDL(buf, dl);

        for (int i = 0; i < dl; ++i)
        {
            encodeHexByte(buf, contents[i]);
        }

        return buf.toString();
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
        out.writeEncodingDL(withTag, BERTags.UNIVERSAL_STRING, contents);
    }

    final boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1UniversalString))
        {
            return false;
        }

        ASN1UniversalString that = (ASN1UniversalString)other;

        return Arrays.areEqual(this.contents, that.contents);
    }

    public final int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    static ASN1UniversalString createPrimitive(byte[] contents)
    {
        return new DERUniversalString(contents, false);
    }

    private static void encodeHexByte(StringBuffer buf, int i)
    {
        buf.append(table[(i >>> 4) & 0xF]);
        buf.append(table[i & 0xF]);
    }

    private static void encodeHexDL(StringBuffer buf, int dl)
    {
        if (dl < 128)
        {
            encodeHexByte(buf, dl);
            return;
        }

        byte[] stack = new byte[5];
        int pos = 5;

        do
        {
            stack[--pos] = (byte)dl;
            dl >>>= 8;
        }
        while (dl != 0);

        int count = stack.length - pos;
        stack[--pos] = (byte)(0x80 | count);

        do
        {
            encodeHexByte(buf, stack[pos++]);
        }
        while (pos < stack.length);
    }
}
