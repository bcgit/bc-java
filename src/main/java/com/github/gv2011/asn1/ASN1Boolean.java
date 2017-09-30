package com.github.gv2011.asn1;

import static com.github.gv2011.util.bytes.ByteUtils.newBytes;


import com.github.gv2011.util.bytes.Bytes;

/**
 * Public facade of ASN.1 Boolean data.
 * <p>
 * Use following to place a new instance of ASN.1 Boolean in your dataset:
 * <ul>
 * <li> ASN1Boolean.TRUE literal</li>
 * <li> ASN1Boolean.FALSE literal</li>
 * <li> {@link ASN1Boolean#getInstance(boolean) ASN1Boolean.getInstance(boolean)}</li>
 * <li> {@link ASN1Boolean#getInstance(int) ASN1Boolean.getInstance(int)}</li>
 * </ul>
 * </p>
 */
public class ASN1Boolean
    extends ASN1Primitive
{
    private static final Bytes TRUE_VALUE = newBytes(new byte[] { (byte)0xff });
    private static final Bytes FALSE_VALUE = newBytes(new byte[] { 0 });

    private final Bytes         value;

    public static final ASN1Boolean FALSE = new ASN1Boolean(false);
    public static final ASN1Boolean TRUE  = new ASN1Boolean(true);

    /**
     * return a boolean from the passed in object.
     *
     * @param obj an ASN1Boolean or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1Boolean instance.
     */
    public static ASN1Boolean getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof ASN1Boolean)
        {
            return (ASN1Boolean)obj;
        }

        if (obj instanceof Bytes)
        {
            final Bytes enc = (Bytes)obj;
            return (ASN1Boolean)fromByteArray(enc);
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an ASN1Boolean from the passed in boolean.
     * @param value true or false depending on the ASN1Boolean wanted.
     * @return an ASN1Boolean instance.
     */
    public static ASN1Boolean getInstance(
        final boolean  value)
    {
        return (value ? TRUE : FALSE);
    }

    /**
     * return an ASN1Boolean from the passed in value.
     * @param value non-zero (true) or zero (false) depending on the ASN1Boolean wanted.
     * @return an ASN1Boolean instance.
     */
    public static ASN1Boolean getInstance(
        final int value)
    {
        return (value != 0 ? TRUE : FALSE);
    }

    /**
     * return a Boolean from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return an ASN1Boolean instance.
     */
    public static ASN1Boolean getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof ASN1Boolean)
        {
            return getInstance(o);
        }
        else
        {
            return ASN1Boolean.fromOctetString(((ASN1OctetString)o).getOctets());
        }
    }

    ASN1Boolean(
        final Bytes value)
    {
        if (value.size() != 1)
        {
            throw new IllegalArgumentException("byte value should have 1 byte in it");
        }

        if (value.get(0) == 0)
        {
            this.value = FALSE_VALUE;
        }
        else if ((value.get(0) & 0xff) == 0xff)
        {
            this.value = TRUE_VALUE;
        }
        else
        {
            this.value = value;
        }
    }

    /**
     * @deprecated use getInstance(boolean) method.
     * @param value true or false.
     */
    @Deprecated
    public ASN1Boolean(
        final boolean     value)
    {
        this.value = (value) ? TRUE_VALUE : FALSE_VALUE;
    }

    public boolean isTrue()
    {
        return (value.get(0) != 0);
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
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.BOOLEAN, value);
    }

    @Override
    protected boolean asn1Equals(
        final ASN1Primitive  o)
    {
        if (o instanceof ASN1Boolean)
        {
            return (value.get(0) == ((ASN1Boolean)o).value.get(0));
        }

        return false;
    }

    @Override
    public int hashCode()
    {
        return value.get(0);
    }


    @Override
    public String toString()
    {
      return (value.get(0) != 0) ? "TRUE" : "FALSE";
    }

    static ASN1Boolean fromOctetString(final Bytes value)
    {
        if (value.size() != 1)
        {
            throw new IllegalArgumentException("BOOLEAN value should have 1 byte in it");
        }

        if (value.get(0) == 0)
        {
            return FALSE;
        }
        else if ((value.get(0) & 0xff) == 0xff)
        {
            return TRUE;
        }
        else
        {
            return new ASN1Boolean(value);
        }
    }
}
