package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Public facade of ASN.1 NULL object.
 * <p>
 * Use following to instantiate this in your structures:
 * <ul>
 * <li> DERNull.INSTANCE
 * </ul>
 */
public abstract class ASN1Null
    extends ASN1Primitive
{
    /**
     * @deprecated use DERNull.INSTANCE
     */
    public ASN1Null()
    {
    }

    /**
     * Return an instance of ASN.1 NULL from the passed in object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link ASN1Null} object
     * <li> a byte[] containing ASN.1 NULL object
     * </ul>
     * <p>
     *
     * @param o object to be converted.
     * @return converted value.
     * @exception IllegalArgumentException if the object cannot be converted.
     */

    public static ASN1Null getInstance(Object o)
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
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct NULL from byte[]: " + e.getMessage());
            }
            catch (ClassCastException e)
            {
                throw new IllegalArgumentException("unknown object in getInstance(): " + o.getClass().getName());
            }
        }

        return null;
    }

    public int hashCode()
    {
        return -1;
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof ASN1Null))
        {
            return false;
        }
        
        return true;
    }

    abstract void encode(ASN1OutputStream out)
        throws IOException;

    public String toString()
    {
         return "NULL";
    }
}
