package com.github.gv2011.asn1;

import java.io.IOException;

/**
 * A NULL object - use DERNull.INSTANCE for populating structures.
 */
public abstract class ASN1Null
    extends ASN1Primitive
{
    /**
     * Return an instance of ASN.1 NULL from the passed in object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link ASN1Null} object
     * <li> a byte[] containing ASN.1 NULL object
     * </ul>
     * </p>
     *
     * @param o object to be converted.
     * @return an instance of ASN1Null, or null.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1Null getInstance(final Object o)
    {
        if (o instanceof ASN1Null)
        {
            return (ASN1Null)o;
        }

        if (o != null)
        {
            try
            {
                return ASN1Null.getInstance(ASN1Primitive.fromByteArray((byte[])o));
            }
            catch (final IOException e)
            {
                throw new IllegalArgumentException("failed to construct NULL from byte[]: " + e.getMessage());
            }
            catch (final ClassCastException e)
            {
                throw new IllegalArgumentException("unknown object in getInstance(): " + o.getClass().getName());
            }
        }

        return null;
    }

    @Override
    public int hashCode()
    {
        return -1;
    }

    @Override
    boolean asn1Equals(
        final ASN1Primitive o)
    {
        if (!(o instanceof ASN1Null))
        {
            return false;
        }

        return true;
    }

    @Override
    abstract void encode(ASN1OutputStream out);

    @Override
    public String toString()
    {
         return "NULL";
    }
}
