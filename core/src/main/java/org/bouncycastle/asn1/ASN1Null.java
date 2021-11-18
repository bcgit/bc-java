package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A NULL object - use DERNull.INSTANCE for populating structures.
 */
public abstract class ASN1Null
    extends ASN1Primitive
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Null.class, BERTags.NULL)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

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
                return (ASN1Null)TYPE.fromByteArray((byte[])o);
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("failed to construct NULL from byte[]: " + e.getMessage());
            }
        }

        return null;
    }

    public static ASN1Null getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1Null)TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1Null()
    {
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

    public String toString()
    {
         return "NULL";
    }

    static ASN1Null createPrimitive(byte[] contents)
    {
        if (0 != contents.length)
        {
            throw new IllegalStateException("malformed NULL encoding encountered");
        }
        return DERNull.INSTANCE;
    }
}
