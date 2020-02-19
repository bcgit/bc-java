package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * DER BMPString object encodes BMP (<i>Basic Multilingual Plane</i>) subset
 * (aka UCS-2) of UNICODE (ISO 10646) characters in codepoints 0 to 65535.
 * <p>
 * At ISO-10646:2011 the term "BMP" has been withdrawn, and replaced by
 * term "UCS-2".
 * </p>
 */
public class DERBMPString
    extends ASN1Primitive
    implements ASN1String
{
    private final char[]  string;

    /**
     * Return a BMP String from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERBMPString instance, or null.
     */
    public static DERBMPString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERBMPString)
        {
            return (DERBMPString)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERBMPString)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a BMP String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *              be converted.
     * @return a DERBMPString instance.
     */
    public static DERBMPString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERBMPString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERBMPString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * Basic constructor - byte encoded string.
     * @param string the encoded BMP STRING to wrap.
     */
    DERBMPString(
        byte[]   string)
    {
        if (string == null)
        {
            throw new NullPointerException("'string' cannot be null");
        }

        int byteLen = string.length;
        if (0 != (byteLen & 1))
        {
            throw new IllegalArgumentException("malformed BMPString encoding encountered");
        }

        int charLen = byteLen / 2;
        char[] cs = new char[charLen];

        for (int i = 0; i != charLen; i++)
        {
            cs[i] = (char)((string[2 * i] << 8) | (string[2 * i + 1] & 0xff));
        }

        this.string = cs;
    }

    DERBMPString(char[] string)
    {
        if (string == null)
        {
            throw new NullPointerException("'string' cannot be null");
        }

        this.string = string;
    }

    /**
     * Basic constructor
     * @param string a String to wrap as a BMP STRING.
     */
    public DERBMPString(
        String   string)
    {
        if (string == null)
        {
            throw new NullPointerException("'string' cannot be null");
        }

        this.string = string.toCharArray();
    }

    public String getString()
    {
        return new String(string);
    }

    public String toString()
    {
        return getString();
    }

    public int hashCode()
    {
        return Arrays.hashCode(string);
    }

    protected boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERBMPString))
        {
            return false;
        }

        DERBMPString  s = (DERBMPString)o;

        return Arrays.areEqual(string, s.string);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length * 2) + (string.length * 2);
    }

    void encode(
        ASN1OutputStream out, boolean withTag)
        throws IOException
    {
        int count = string.length;
        if (withTag)
        {
            out.write(BERTags.BMP_STRING);
        }
        out.writeLength(count * 2);

        byte[] buf = new byte[8];

        int i = 0, limit = count & -4;
        while (i < limit)
        {
            char c0 = string[i], c1 = string[i + 1], c2 = string[i + 2], c3 = string[i + 3];
            i += 4;

            buf[0] = (byte)(c0 >> 8);
            buf[1] = (byte)c0;
            buf[2] = (byte)(c1 >> 8);
            buf[3] = (byte)c1;
            buf[4] = (byte)(c2 >> 8);
            buf[5] = (byte)c2;
            buf[6] = (byte)(c3 >> 8);
            buf[7] = (byte)c3;

            out.write(buf, 0, 8);
        }
        if (i < count)
        {
            int bufPos = 0;
            do
            {
                char c0 = string[i];
                i += 1;

                buf[bufPos++] = (byte)(c0 >> 8);
                buf[bufPos++] = (byte)c0;
            }
            while (i < count);

            out.write(buf, 0, bufPos);
        }
    }
}
