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
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Boolean.class, BERTags.BOOLEAN)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets());
        }
    };

    private static final byte FALSE_VALUE = 0x00;
    private static final byte TRUE_VALUE = (byte)0xFF;

    public static final ASN1Boolean FALSE = new ASN1Boolean(FALSE_VALUE);
    public static final ASN1Boolean TRUE  = new ASN1Boolean(TRUE_VALUE);

    public static ASN1Boolean fromContents(byte contents)
    {
        return createPrimitive(contents);
    }

    public static ASN1Boolean fromContents(byte[] contents)
    {
        if (contents == null)
        {
            throw new NullPointerException("'contents' cannot be null");
        }

        return createPrimitive(contents);
    }

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
                return (ASN1Boolean)TYPE.fromByteArray(enc);
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
     * @param taggedObject the tagged object holding the object we want
     * @param declaredExplicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return an ASN1Boolean instance.
     */
    public static ASN1Boolean getInstance(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return (ASN1Boolean)TYPE.getContextTagged(taggedObject, declaredExplicit);
    }

    public static ASN1Boolean getTagged(ASN1TaggedObject taggedObject, boolean declaredExplicit)
    {
        return (ASN1Boolean)TYPE.getTagged(taggedObject, declaredExplicit);
    }

    private final byte contents;

    private ASN1Boolean(byte contents)
    {
        this.contents = contents;
    }

    public boolean isFalse()
    {
        return contents == FALSE_VALUE;
    }

    public boolean isTrue()
    {
        return contents != FALSE_VALUE;
    }

    boolean encodeConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, 1);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.BOOLEAN, contents);
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

    private static void checkContentsLength(int contentsLength)
    {
        if (contentsLength != 1)
        {
            throw new IllegalArgumentException("BOOLEAN value should have 1 byte in it");
        }
    }

    static ASN1Boolean createPrimitive(DefiniteLengthInputStream defIn) throws IOException
    {
        checkContentsLength(defIn.getRemaining());
        return createPrimitive((byte)defIn.read());
    }

    private static ASN1Boolean createPrimitive(byte[] contents)
    {
        checkContentsLength(contents.length);
        return createPrimitive(contents[0]);
    }

    private static ASN1Boolean createPrimitive(byte b)
    {
        return b == FALSE_VALUE ? FALSE : b == TRUE_VALUE ? TRUE : new ASN1Boolean(b);
    }
}
