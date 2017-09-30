package com.github.gv2011.asn1;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.util.bytes.Bytes;

/**
 * DER T61String (also the teletex string) - a "modern" encapsulation that uses UTF-8. If at all possible, avoid this one! It's only for emergencies.
 * Use UTF8String instead.
 * @deprecated don't use this class, introduced in error, it will be removed.
 */
@Deprecated
public class DERT61UTF8String
    extends ASN1PrimitiveBytes
    implements ASN1String
{

    /**
     * return a T61 string from the passed in object. UTF-8 Encoding is assumed in this case.
     *
     * @param obj a DERT61UTF8String or an object that can be converted into one.
     * @throws IllegalArgumentException if the object cannot be converted.
     * @return a DERT61UTF8String instance, or null
     */
    public static DERT61UTF8String getInstance(
        final Object obj)
    {
        if (obj instanceof DERT61String)
        {
            return new DERT61UTF8String(((DERT61String)obj).getOctets());
        }

        if (obj == null || obj instanceof DERT61UTF8String)
        {
            return (DERT61UTF8String)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return new DERT61UTF8String(((DERT61String)fromByteArray((Bytes)obj)).getOctets());
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an T61 String from a tagged object. UTF-8 encoding is assumed in this case.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws IllegalArgumentException if the tagged object cannot
     * be converted.
     * @return a DERT61UTF8String instance, or null
     */
    public static DERT61UTF8String getInstance(
        final ASN1TaggedObject obj,
        final boolean explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERT61String || o instanceof DERT61UTF8String)
        {
            return getInstance(o);
        }
        else
        {
            return new DERT61UTF8String(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    /**
     * basic constructor - string encoded as a sequence of bytes.
     */
    public DERT61UTF8String(final Bytes string){
      super(string);
    }

    /**
     * basic constructor - with string UTF8 conversion assumed.
     */
    public DERT61UTF8String( final String string)
    {
        this(Strings.toUTF8ByteArray(string));
    }

    /**
     * Decode the encoded string and return it, UTF8 assumed.
     *
     * @return the decoded String
     */
    @Override
    public String getString()
    {
        return Strings.fromUTF8ByteArray(string);
    }

    @Override
    public String toString()
    {
        return getString();
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.T61_STRING, string);
    }

}
