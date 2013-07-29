package org.bouncycastle.asn1;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * Internal facade of ASN.1 Boolean objects, use {@link ASN1Boolean}.getInstance() methods instead.
 */
public class DERBoolean
    extends ASN1Primitive
{
    private static final byte[] TRUE_VALUE = new byte[] { (byte)0xff };
    private static final byte[] FALSE_VALUE = new byte[] { 0 };

    private byte[]         value;

    /** ASN1Boolean.FALSE value literal; byte code 0x00 */
    public static final ASN1Boolean FALSE = new ASN1Boolean(false);

    /** ASN1Boolean.TRUE value literal; byte code 0xFF */
    public static final ASN1Boolean TRUE  = new ASN1Boolean(true);


    /**
     * Return an instance of boolean from the passed in object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link ASN1Boolean} object
     * <li> {@link DERBoolean} object
     * </ul>
     * <p>
     *
     * @param obj object to be converted.
     * @return converted value.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1Boolean getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1Boolean)
        {
            return (ASN1Boolean)obj;
        }

        if (obj instanceof DERBoolean)
        {
            return ((DERBoolean)obj).isTrue() ? DERBoolean.TRUE : DERBoolean.FALSE;
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a ASN1Boolean from the passed in boolean.
     */
    public static ASN1Boolean getInstance(
        boolean  value)
    {
        return (value ? TRUE : FALSE);
    }

    /**
     * Return a ASN1Boolean from the passed in boolean.
     */
    public static ASN1Boolean getInstance(
        int value)
    {
        return (value != 0 ? TRUE : FALSE);
    }

    /**
     * Return a Boolean from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static ASN1Boolean getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERBoolean)
        {
            return getInstance(o);
        }
        else
        {
            return ASN1Boolean.fromOctetString(((ASN1OctetString)o).getOctets());
        }
    }
    
    DERBoolean(
        byte[]       value)
    {
        if (value.length != 1)
        {
            throw new IllegalArgumentException("byte value should have 1 byte in it");
        }

        if (value[0] == 0)
        {
            this.value = FALSE_VALUE;
        }
        else if (value[0] == 0xff)
        {
            this.value = TRUE_VALUE;
        }
        else
        {
            this.value = Arrays.clone(value);
        }
    }

    /**
     * @deprecated use getInstance(boolean) method.
     * @param value
     */
    public DERBoolean(
        boolean     value)
    {
        this.value = (value) ? TRUE_VALUE : FALSE_VALUE;
    }

    /**
     * @return true when encoded value is not zero.
     */
    public boolean isTrue()
    {
        return (value[0] != 0);
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 3;
    }

    @Override
    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.BOOLEAN, value);
    }
    
    @Override
    protected boolean asn1Equals(
        ASN1Primitive  o)
    {
        if ((o == null) || !(o instanceof DERBoolean))
        {
            return false;
        }

        return (value[0] == ((DERBoolean)o).value[0]);
    }
    
    /**
     * @return code value of 0 (false) or -1 (true).
     */
    @Override
    public int hashCode()
    {
        return value[0];
    }


    /**
     * @return String literal "TRUE" or "FALSE".
     */
    @Override
    public String toString()
    {
      return (value[0] != 0) ? "TRUE" : "FALSE";
    }

    /**
     * Internal tool for parsing byte[] values
     */
    static ASN1Boolean fromOctetString(byte[] value)
    {
        if (value.length != 1)
        {
            throw new IllegalArgumentException("byte value should have 1 byte in it");
        }

        if (value[0] == 0)
        {
            return FALSE;
        }
        else if (value[0] == 0xff)
        {
            return TRUE;
        }
        else
        {
            return new ASN1Boolean(value);
        }
    }
}
