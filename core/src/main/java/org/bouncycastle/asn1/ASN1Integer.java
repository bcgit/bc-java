package org.bouncycastle.asn1;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/**
 * Class representing the ASN.1 INTEGER type.
 */
public class ASN1Integer
    extends ASN1Primitive
{
    private final byte[] bytes;

    /**
     * Return an integer from the passed in object.
     *
     * @param obj an ASN1Integer or an object that can be converted into one.
     * @return an ASN1Integer instance.
     * @throws IllegalArgumentException if the object cannot be converted.
     */
    public static ASN1Integer getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof ASN1Integer)
        {
            return (ASN1Integer)obj;
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
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @return an ASN1Integer instance.
     * @throws IllegalArgumentException if the tagged object cannot
     * be converted.
     */
    public static ASN1Integer getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof ASN1Integer)
        {
            return getInstance(o);
        }
        else
        {
            return new ASN1Integer(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * Construct an INTEGER from the passed in long value.
     *
     * @param value the long representing the value desired.
     */
    public ASN1Integer(
        long value)
    {
        bytes = BigInteger.valueOf(value).toByteArray();
    }

    /**
     * Construct an INTEGER from the passed in BigInteger value.
     *
     * @param value the BigInteger representing the value desired.
     */
    public ASN1Integer(
        BigInteger value)
    {
        bytes = value.toByteArray();
    }

    /**
     * Construct an INTEGER from the passed in byte array.
     *
     * <p>
     * <b>NB: Strict Validation applied by default.</b>
     * </p>
     * <p>
     * It has turned out that there are still a few applications that struggle with
     * the ASN.1 BER encoding rules for an INTEGER as described in:
     *
     * https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
     * Section 8.3.2.
     * </p>
     * <p>
     * Users can set the 'org.bouncycastle.asn1.allow_unsafe_integer' to 'true'
     * and a looser validation will be applied. Users must recognise that this is
     * not ideal and may pave the way for an exploit based around a faulty encoding
     * in the future.
     * </p>
     *
     * @param bytes the byte array representing a 2's complement encoding of a BigInteger.
     */
    public ASN1Integer(
        byte[] bytes)
    {
        this(bytes, true);
    }

    ASN1Integer(byte[] bytes, boolean clone)
    {
        // Apply loose validation, see note in public constructor ANS1Integer(byte[])
        if (!Properties.isOverrideSet("org.bouncycastle.asn1.allow_unsafe_integer"))
        {
            if (isMalformed(bytes))
            {                           
                throw new IllegalArgumentException("malformed integer");
            }
        }
        this.bytes = (clone) ? Arrays.clone(bytes) : bytes;
    }

    /**
     * Apply the correct validation for an INTEGER primitive following the BER rules.
     *
     * @param bytes The raw encoding of the integer.
     * @return true if the (in)put fails this validation.
     */
    static boolean isMalformed(byte[] bytes)
    {
        if (bytes.length > 1)
        {
            if (bytes[0] == 0 && (bytes[1] & 0x80) == 0)
            {
                return true;
            }
            if (bytes[0] == (byte)0xff && (bytes[1] & 0x80) != 0)
            {
                return true;
            }
        }

        return false;
    }

    public BigInteger getValue()
    {
        return new BigInteger(bytes);
    }

    /**
     * in some cases positive values get crammed into a space,
     * that's not quite big enough...
     *
     * @return the BigInteger that results from treating this ASN.1 INTEGER as unsigned.
     */
    public BigInteger getPositiveValue()
    {
        return new BigInteger(1, bytes);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(bytes.length) + bytes.length;
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.INTEGER, bytes);
    }

    public int hashCode()
    {
        int value = 0;

        for (int i = 0; i != bytes.length; i++)
        {
            value ^= (bytes[i] & 0xff) << (i % 4);
        }

        return value;
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof ASN1Integer))
        {
            return false;
        }

        ASN1Integer other = (ASN1Integer)o;

        return Arrays.areEqual(bytes, other.bytes);
    }

    public String toString()
    {
        return getValue().toString();
    }

}
