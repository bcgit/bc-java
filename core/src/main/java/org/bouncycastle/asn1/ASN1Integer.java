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
    static final int SIGN_EXT_SIGNED = 0xFFFFFFFF;
    static final int SIGN_EXT_UNSIGNED = 0xFF;

    private final byte[] bytes;
    private final int start;

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
    public ASN1Integer(long value)
    {
        this.bytes = BigInteger.valueOf(value).toByteArray();
        this.start = 0;
    }

    /**
     * Construct an INTEGER from the passed in BigInteger value.
     *
     * @param value the BigInteger representing the value desired.
     */
    public ASN1Integer(BigInteger value)
    {
        this.bytes = value.toByteArray();
        this.start = 0;
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
    public ASN1Integer(byte[] bytes)
    {
        this(bytes, true);
    }

    ASN1Integer(byte[] bytes, boolean clone)
    {
        if (isMalformed(bytes))
        {                           
            throw new IllegalArgumentException("malformed integer");
        }

        this.bytes = clone ? Arrays.clone(bytes) : bytes;
        this.start = signBytesToSkip(bytes); 
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

    public BigInteger getValue()
    {
        return new BigInteger(bytes);
    }

    public boolean hasValue(BigInteger x)
    {
        return null != x
            // Fast check to avoid allocation
            && intValue(bytes, start, SIGN_EXT_SIGNED) == x.intValue()
            && getValue().equals(x);
    }

    public int intPositiveValueExact()
    {
        int count = bytes.length - start;
        if (count > 4 || (count == 4 && 0 != (bytes[start] & 0x80)))
        {
            throw new ArithmeticException("ASN.1 Integer out of positive int range");
        }

        return intValue(bytes, start, SIGN_EXT_UNSIGNED);
    }

    public int intValueExact()
    {
        int count = bytes.length - start;
        if (count > 4)
        {
            throw new ArithmeticException("ASN.1 Integer out of int range");
        }

        return intValue(bytes, start, SIGN_EXT_SIGNED); 
    }

    public long longValueExact()
    {
        int count = bytes.length - start;
        if (count > 8)
        {
            throw new ArithmeticException("ASN.1 Integer out of long range");
        }

        return longValue(bytes, start, SIGN_EXT_SIGNED);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(bytes.length) + bytes.length;
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncoded(withTag, BERTags.INTEGER, bytes);
    }

    public int hashCode()
    {
        return Arrays.hashCode(bytes);
    }

    boolean asn1Equals(ASN1Primitive o)
    {
        if (!(o instanceof ASN1Integer))
        {
            return false;
        }

        ASN1Integer other = (ASN1Integer)o;

        return Arrays.areEqual(this.bytes, other.bytes);
    }

    public String toString()
    {
        return getValue().toString();
    }

    static int intValue(byte[] bytes, int start, int signExt)
    {
        int length = bytes.length;
        int pos = Math.max(start, length - 4);

        int val = bytes[pos] & signExt;
        while (++pos < length)
        {
            val = (val << 8) | (bytes[pos] & SIGN_EXT_UNSIGNED);
        }
        return val;
    }

    static long longValue(byte[] bytes, int start, int signExt)
    {
        int length = bytes.length;
        int pos = Math.max(start, length - 8);

        long val = bytes[pos] & signExt;
        while (++pos < length)
        {
            val = (val << 8) | (bytes[pos] & SIGN_EXT_UNSIGNED);
        }
        return val;
    }

    /**
     * Apply the correct validation for an INTEGER primitive following the BER rules.
     *
     * @param bytes The raw encoding of the integer.
     * @return true if the (in)put fails this validation.
     */
    static boolean isMalformed(byte[] bytes)
    {
        switch (bytes.length)
        {
        case 0:
            return true;
        case 1:
            return false;
        default:
            return bytes[0] == (bytes[1] >> 7)
                // Apply loose validation, see note in public constructor ASN1Integer(byte[])
                && !Properties.isOverrideSet("org.bouncycastle.asn1.allow_unsafe_integer");
        }
    }

    static int signBytesToSkip(byte[] bytes)
    {
        int pos = 0, last = bytes.length - 1;
        while (pos < last
            && bytes[pos] == (bytes[pos + 1] >> 7))
        {
            ++pos;
        }
        return pos;
    }
}
