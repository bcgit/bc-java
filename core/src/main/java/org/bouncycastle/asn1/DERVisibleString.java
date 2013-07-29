package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * DER VisibleString object encoding ISO 646 (ASCII) character code points 32 to 126.
 * (That is: ASCII without control codes.)
 * <p>
 * Explicit character set escape sequences are not allowed.
 * <p>
 * <hr>
 * See {@link ASN1String} for X.690 encoding rules of Strings.
 */
public class DERVisibleString
    extends ASN1Primitive
    implements ASN1String
{
    private byte[]  string;

    /**
     * Return a Visible String from the passed in object.
     * <p>
     * Acceptable inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> DERVisibleString object
     * <li> byte[] containing value of DERVisibleString.
     * </ul>
     *
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static DERVisibleString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERVisibleString)
        {
            return (DERVisibleString)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERVisibleString)fromByteArray((byte[])obj);
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
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static DERVisibleString getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERVisibleString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERVisibleString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * Basic constructor - byte encoded string.
     */
    DERVisibleString(
        byte[]   string)
    {
        this.string = string;
    }

    /**
     * Basic constructor
     */
    public DERVisibleString(
        String   string)
    {
        this.string = Strings.toByteArray(string);
    }

    public String getString()
    {
        return Strings.fromByteArray(string);
    }

    @Override
    public String toString()
    {
        return getString();
    }

    public byte[] getOctets()
    {
        return Arrays.clone(string);
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
        out.writeEncoded(BERTags.VISIBLE_STRING, this.string);
    }
    
    @Override
    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERVisibleString))
        {
            return false;
        }

        return Arrays.areEqual(string, ((DERVisibleString)o).string);
    }
    
    @Override
    public int hashCode()
    {
        return Arrays.hashCode(string);
    }
}
