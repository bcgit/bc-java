package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * DER T61String (also the teletex string)
 */
public class DERT61String
    extends ASN1Primitive
    implements ASN1String
{
    private byte[] string;

    /**
     * return a T61 string from the passed in object.
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DERT61String getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERT61String)
        {
            return (DERT61String)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERT61String)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an T61 String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static DERT61String getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERT61String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERT61String(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * basic constructor - with bytes.
     */
    DERT61String(
        byte[]   string)
    {
        this.string = string;
    }

    /**
     * basic constructor - with string.
     */
    public DERT61String(
        String   string)
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

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.T61_STRING, string);
    }
    
    public byte[] getOctets()
    {
        return Arrays.clone(string);
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERT61String))
        {
            return false;
        }

        return Arrays.areEqual(string, ((DERT61String)o).string);
    }
    
    public int hashCode()
    {
        return Arrays.hashCode(string);
    }
}
