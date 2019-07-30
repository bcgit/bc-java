package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * ASN.1 GENERAL-STRING data type.
 * <p>
 * This is an 8-bit encoded ISO 646 (ASCII) character set
 * with optional escapes to other character sets.
 * </p>
 */
public class DERGeneralString 
    extends ASN1Primitive
    implements ASN1String
{
    private final byte[] string;

    /**
     * Return a GeneralString from the given object.
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERBMPString instance, or null.
     */
    public static DERGeneralString getInstance(
        Object obj) 
    {
        if (obj == null || obj instanceof DERGeneralString) 
        {
            return (DERGeneralString) obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (DERGeneralString)fromByteArray((byte[])obj);
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
     * Return a GeneralString from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *              be converted.
     * @return a DERGeneralString instance.
     */
    public static DERGeneralString getInstance(
        ASN1TaggedObject obj, 
        boolean explicit) 
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERGeneralString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERGeneralString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    DERGeneralString(byte[] string)
    {
        this.string = string;
    }

    /**
     * Construct a GeneralString from the passed in String.
     *
     * @param string the string to be contained in this object.
     */
    public DERGeneralString(String string) 
    {
        this.string = Strings.toByteArray(string);
    }

    /**
     * Return a Java String representation of our contained String.
     *
     * @return a Java String representing our contents.
     */
    public String getString() 
    {
        return Strings.fromByteArray(string);
    }

    public String toString()
    {
        return getString();
    }

    /**
     * Return a byte array representation of our contained String.
     *
     * @return a byte array representing our contents.
     */
    public byte[] getOctets() 
    {
        return Arrays.clone(string);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncoded(withTag, BERTags.GENERAL_STRING, string);
    }

    public int hashCode() 
    {
        return Arrays.hashCode(string);
    }
    
    boolean asn1Equals(ASN1Primitive o)
    {
        if (!(o instanceof DERGeneralString)) 
        {
            return false;
        }
        DERGeneralString s = (DERGeneralString)o;

        return Arrays.areEqual(string, s.string);
    }
}
