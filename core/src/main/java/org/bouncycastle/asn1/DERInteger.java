package org.bouncycastle.asn1;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.util.Arrays;

/**
 * This is ASN.1 INTEGER internal facade.
 */
public class DERInteger
    extends ASN1Primitive
{
    byte[]      bytes;

    /**
     * Return an integer from the passed in object
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link ASN1Integer} object
     * <li> {@link DERInteger} object
     * <li> A byte[] with DER form of ASN1Integer.
     * </ul>
     *
     * @param obj object to be converted.
     * @return converted value.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1Integer getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof ASN1Integer)
        {
            return (ASN1Integer)obj;
        }
        if (obj instanceof DERInteger)
        {
            return new ASN1Integer((((DERInteger)obj).getValue()));
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1Integer)fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return an Integer from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     */
    public static ASN1Integer getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERInteger)
        {
            return getInstance(o);
        }
        else
        {
            return new ASN1Integer(ASN1OctetString.getInstance(obj.getObject()).getOctets());
        }
    }

    /**
     * @deprecated use ASN1Integer constructor
     */
    public DERInteger(
        long         value)
    {
        bytes = BigInteger.valueOf(value).toByteArray();
    }

    /**
     * @deprecated use ASN1Integer constructor
     */
    public DERInteger(
        BigInteger   value)
    {
        bytes = value.toByteArray();
    }

    /**
     * @deprecated use ASN1Integer constructor
     */
    public DERInteger(
        byte[]   bytes)
    {
        this.bytes = bytes;
    }

    /**
     * Get BigInteger representation of ASN.1 Integer,
     * if leading byte's highest bit is set, the BigInteger value will be <b>negative</b>.
     */
    public BigInteger getValue()
    {
        return new BigInteger(bytes);
    }

    /**
     * In some cases positive values get crammed into a space,
     * that's not quite big enough...  That is, the encoder has
     * failed to realize that ASN1Integer has sign in the leading
     * byte's highest bit.
     */
    public BigInteger getPositiveValue()
    {
        return new BigInteger(1, bytes);
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(bytes.length) + bytes.length;
    }

    @Override
    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.INTEGER, bytes);
    }
    
    @Override
    public int hashCode()
    {
         int     value = 0;
 
         for (int i = 0; i != bytes.length; i++)
         {
             value ^= (bytes[i] & 0xff) << (i % 4);
         }
 
         return value;
    }

    boolean asn1Equals(
        ASN1Primitive  o)
    {
        if (!(o instanceof DERInteger))
        {
            return false;
        }

        DERInteger other = (DERInteger)o;

        return Arrays.areEqual(bytes, other.bytes);
    }

    @Override
    public String toString()
    {
      return getValue().toString();
    }
}
