package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * DER UTF8String object.
 * <p>
 * <hr>
 * See {@link ASN1String} for X.690 encoding rules of Strings.
 */
public class DERUTF8String
    extends ASN1Primitive
    implements ASN1String
{
    private byte[]  string;

    /**
     * Return a UTF8 string from the passed in object.
     * 
     * @exception IllegalArgumentException
     *                if the object cannot be converted.
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
     * Return a UTF8 String from a tagged object.
     * 
     * @param obj
     *            the tagged object holding the object we want
     * @param explicit
     *            true if the object is meant to be explicitly tagged false
     *            otherwise.
     * @exception IllegalArgumentException
     *                if the tagged object cannot be converted.
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

    /**
     * Basic constructor - byte encoded string.
     */
    DERUTF8String(byte[] string)
    {
        this.string = string;
    }

    /**
     * Basic constructor
     */
    public DERUTF8String(String string)
    {
        this.string = Strings.toUTF8ByteArray(string);
    }

    public String getString()
    {
        return Strings.fromUTF8ByteArray(string);
    }

    // @Override
    public String toString()
    {
        return getString();
    }

    // @Override
    public int hashCode()
    {
        return Arrays.hashCode(string);
    }

    // @Override
    boolean asn1Equals(ASN1Primitive o)
    {
        if (!(o instanceof DERUTF8String))
        {
            return false;
        }

        DERUTF8String s = (DERUTF8String)o;

        return Arrays.areEqual(string, s.string);
    }

    // @Override
    boolean isConstructed()
    {
        return false;
    }

    // @Override
    int encodedLength()
        throws IOException
    {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    // @Override
    void encode(ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.UTF8_STRING, string);
    }
}
