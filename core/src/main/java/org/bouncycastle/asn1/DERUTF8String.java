package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * DER UTF8String object.
 */
public class DERUTF8String
    extends ASN1Primitive
    implements ASN1String
{
    private final byte[]  string;

    /**
     * Return an UTF8 string from the passed in object.
     *
     * @param obj a DERUTF8String or an object that can be converted into one.
     * @exception IllegalArgumentException
     *                if the object cannot be converted.
     * @return a DERUTF8String instance, or null
     */
    public static DERUTF8String getInstance(Object obj)
    {
        if (obj == null || obj instanceof DERUTF8String)
        {
            return (DERUTF8String)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERUTF8String)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: "
                + obj.getClass().getName());
    }

    /**
     * Return an UTF8 String from a tagged object.
     * 
     * @param obj
     *            the tagged object holding the object we want
     * @param explicit
     *            true if the object is meant to be explicitly tagged false
     *            otherwise.
     * @exception IllegalArgumentException
     *                if the tagged object cannot be converted.
     * @return a DERUTF8String instance, or null
     */
    public static DERUTF8String getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERUTF8String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERUTF8String(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /*
     * Basic constructor - byte encoded string.
     */
    DERUTF8String(byte[] string)
    {
        this.string = string;
    }

    /**
     * Basic constructor
     *
     * @param string the string to be carried in the UTF8String object,
     */
    public DERUTF8String(String string)
    {
        this.string = Strings.toUTF8ByteArray(string);
    }

    public String getString()
    {
        return Strings.fromUTF8ByteArray(string);
    }

    public String toString()
    {
        return getString();
    }

    public int hashCode()
    {
        return Arrays.hashCode(string);
    }

    boolean asn1Equals(ASN1Primitive o)
    {
        if (!(o instanceof DERUTF8String))
        {
            return false;
        }

        DERUTF8String s = (DERUTF8String)o;

        return Arrays.areEqual(string, s.string);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
        throws IOException
    {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    void encode(ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.UTF8_STRING, string);
    }
}
