package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Public facade of ASN.1 Boolean data.
 * <p>
 * Use following to place a new instance of ASN.1 Boolean in your data:
 * <ul>
 * <li> ASN1Boolean.TRUE literal</li>
 * <li> ASN1Boolean.FALSE literal</li>
 * <li> {@link ASN1Boolean#getInstance(boolean) ASN1Boolean.getInstance(boolean)}</li>
 * <li> {@link ASN1Boolean#getInstance(int) ASN1Boolean.getInstance(int)}</li>
 * </ul>
 */
public class ASN1Boolean
    extends ASN1Primitive
{
    private static final byte FALSE_VALUE = 0x00;
    private static final byte TRUE_VALUE = (byte)0xFF;

    public static final ASN1Boolean FALSE = new ASN1Boolean(FALSE_VALUE);
    public static final ASN1Boolean TRUE  = new ASN1Boolean(TRUE_VALUE);

    private final byte value;

    /**
     * Return a boolean from the passed in object.
     *
     * @param obj an ASN1Boolean or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1Boolean instance.
     */
    public static ASN1Boolean getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1Boolean)
        {
            return (ASN1Boolean)obj;
        }

        if (obj instanceof byte[])
        {
            byte[] enc = (byte[])obj;
            try
            {
                return (ASN1Boolean)fromByteArray(enc);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct boolean from byte[]: " + e.getMessage());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an ASN1Boolean from the passed in boolean.
     * @param value true or false depending on the ASN1Boolean wanted.
     * @return an ASN1Boolean instance.
     */
    public static ASN1Boolean getInstance(boolean value)
    {
        return value ? TRUE : FALSE;
    }

    /**
     * Return an ASN1Boolean from the passed in value.
     * @param value non-zero (true) or zero (false) depending on the ASN1Boolean wanted.
     * @return an ASN1Boolean instance.
     */
    public static ASN1Boolean getInstance(int value)
    {
        return value != 0 ? TRUE : FALSE;
    }

    /**
     * Return a Boolean from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return an ASN1Boolean instance.
     */
    public static ASN1Boolean getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof ASN1Boolean)
        {
            return getInstance(o);
        }
        else
        {
            return ASN1Boolean.fromOctetString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    private ASN1Boolean(byte value)
    {
        this.value = value;
    }

    public boolean isTrue()
    {
        return value != FALSE_VALUE;
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 3;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncoded(withTag, BERTags.BOOLEAN, value);
    }

    boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1Boolean))
        {
            return false;
        }

        ASN1Boolean that = (ASN1Boolean)other;

        return this.isTrue() == that.isTrue();
    }

    public int hashCode()
    {
        return isTrue() ? 1 : 0;
    }

    ASN1Primitive toDERObject()
    {
        return isTrue() ? TRUE : FALSE;
    }

    public String toString()
    {
      return isTrue() ? "TRUE" : "FALSE";
    }

    static ASN1Boolean fromOctetString(byte[] value)
    {
        if (value.length != 1)
        {
            throw new IllegalArgumentException("BOOLEAN value should have 1 byte in it");
        }

        byte b = value[0];
        switch (b)
        {
        case FALSE_VALUE:   return FALSE;
        case TRUE_VALUE:    return TRUE;
        default:            return new ASN1Boolean(b);
        }
    }
}
