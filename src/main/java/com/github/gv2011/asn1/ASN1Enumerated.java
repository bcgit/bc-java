package com.github.gv2011.asn1;

import static com.github.gv2011.util.bytes.ByteUtils.fromBigInteger;

import java.math.BigInteger;

import com.github.gv2011.util.bytes.Bytes;

/**
 * Class representing the ASN.1 ENUMERATED type.
 */
public class ASN1Enumerated
    extends ASN1Primitive
{
    private final Bytes bytes;

    /**
     * return an enumerated from the passed in object
     *
     * @param obj an ASN1Enumerated or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1Enumerated instance, or null.
     */
    public static ASN1Enumerated getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof ASN1Enumerated)
        {
            return (ASN1Enumerated)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (ASN1Enumerated)fromByteArray((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an Enumerated from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return an ASN1Enumerated instance, or null.
     */
    public static ASN1Enumerated getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof ASN1Enumerated)
        {
            return getInstance(o);
        }
        else
        {
            return fromOctetString(((ASN1OctetString)o).getOctets());
        }
    }

    public ASN1Enumerated(final int value){
      this(BigInteger.valueOf(value));
    }

    public ASN1Enumerated(final BigInteger value){
      bytes = fromBigInteger(value);
    }

    /**
     * Constructor from encoded BigInteger.
     *
     * @param bytes the value of this enumerated as an encoded BigInteger (signed).
     */
    public ASN1Enumerated(final Bytes bytes){
      this.bytes = bytes;
    }

    public BigInteger getValue(){
      return new BigInteger(bytes.toByteArray());
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(bytes.size()) + bytes.size();
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.ENUMERATED, bytes);
    }

    @Override
    boolean asn1Equals(
        final ASN1Primitive  o)
    {
        if (!(o instanceof ASN1Enumerated))
        {
            return false;
        }

        final ASN1Enumerated other = (ASN1Enumerated)o;

        return bytes.equals(other.bytes);
    }

    @Override
    public int hashCode(){
      return bytes.hashCode();
    }

    private static ASN1Enumerated[] cache = new ASN1Enumerated[12];

    static ASN1Enumerated fromOctetString(final Bytes enc)
    {
        if (enc.size() > 1)
        {
            return new ASN1Enumerated(enc);
        }

        if (enc.size() == 0)
        {
            throw new IllegalArgumentException("ENUMERATED has zero length");
        }
        final int value = enc.getByte(0) & 0xff;

        if (value >= cache.length)
        {
            return new ASN1Enumerated(enc);
        }

        ASN1Enumerated possibleMatch = cache[value];

        if (possibleMatch == null)
        {
            possibleMatch = cache[value] = new ASN1Enumerated(enc);
        }

        return possibleMatch;
    }
}
