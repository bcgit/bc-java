package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * ASN.1 GENERAL-STRING data type.
 * <p>
 * This is an 8-bit encoded ISO 646 (ASCII) character set
 * with optional escapes to other character sets.
 * <p>
 * <hr>
 * See {@link ASN1String} for X.690 encoding rules of Strings.
 */

public class DERGeneralString 
    extends ASN1Primitive
    implements ASN1String
{
    private byte[] string;

    /**
     * Return a GENERAL STRING from the passed in object
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link DERGeneralString} object
     * <li> A byte[] with DER form of DERGeneralString.
     * </ul>
     *
     * @param obj object to be converted.
     * @return converted value.
     * @exception IllegalArgumentException if the object cannot be converted.
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
     * Tagged form of GENERAL STRING data.
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
            return new DERGeneralString(((ASN1OctetString)o).getOctets());
        }
    }

    DERGeneralString(byte[] string)
    {
        this.string = string;
    }

    /**
     * Convert supplies Java String to a byte[] using
     * <p>
     * Note: This is equivalent of Java converting using ISO-8859-1 charset;
     * except it does not notice encoding errors, and just truncates chars
     * at 8 bits.
     */
    public DERGeneralString(String string) 
    {
        this.string = Strings.toByteArray(string);
    }

    /**
     * Convert the GENERAL STRING content to a String.
     * <p>
     * Note: This is roughly equivalent of Java converting using ISO-8859-1 charset.
     */
    public String getString() 
    {
        return Strings.fromByteArray(string);
    }

    /**
     * This calls getString() method.
     */
    @Override
    public String toString()
    {
        return getString();
    }

    /**
     * Get the content as byte[]
     */
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
    void encode(ASN1OutputStream out)
        throws IOException 
    {
        out.writeEncoded(BERTags.GENERAL_STRING, string);
    }
    
    @Override
    public int hashCode() 
    {
        return Arrays.hashCode(string);
    }
    
    // Working equals() is at super-class

    @Override
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
