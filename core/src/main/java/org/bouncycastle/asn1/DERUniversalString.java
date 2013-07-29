package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * DER UniversalString object encodes UNICODE (ISO 10646) characters using 32-bit format.
 * ("UCS-32" in big-endian order.)
 * <p>
 * <hr>
 * See {@link ASN1String} for X.690 encoding rules of Strings.
 */
public class DERUniversalString
    extends ASN1Primitive
    implements ASN1String
{
    private static final char[]  table = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    private byte[] string;
    
    /**
     * Return a Universal String from the passed in object.
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DERUniversalString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERUniversalString)
        {
            return (DERUniversalString)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERUniversalString)fromByteArray((byte[])obj);
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
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static DERUniversalString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERUniversalString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERUniversalString(((ASN1OctetString)o).getOctets());
        }
    }

    /**
     * Basic constructor - byte encoded string.
     * The input material must be encoded per UCS-32-BE.
     */
    public DERUniversalString(
        byte[]   string)
    {
        this.string = string;
    }

    public String getString()
    {
        StringBuffer    buf = new StringBuffer("#");
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        ASN1OutputStream            aOut = new ASN1OutputStream(bOut);
        
        try
        {
            aOut.writeObject(this);
        }
        catch (IOException e)
        {
           throw new RuntimeException("internal error encoding BitString");
        }
        
        byte[]    string = bOut.toByteArray();
        
        for (int i = 0; i != string.length; i++)
        {
            buf.append(table[(string[i] >>> 4) & 0xf]);
            buf.append(table[string[i] & 0xf]);
        }
        
        return buf.toString();
    }

    @Override
    public String toString()
    {
        return getString();
    }

    /**
     * Get the UniversalString's UCS-32-BE  encoded content as an array of bytes.
     */
    public byte[] getOctets()
    {
        return string;
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    @Override
    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.UNIVERSAL_STRING, this.getOctets());
    }
    
    @Override
    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERUniversalString))
        {
            return false;
        }

        return Arrays.areEqual(string, ((DERUniversalString)o).string);
    }
    
    @Override
    public int hashCode()
    {
        return Arrays.hashCode(string);
    }
}
