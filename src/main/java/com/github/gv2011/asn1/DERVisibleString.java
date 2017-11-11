package com.github.gv2011.asn1;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.util.bytes.Bytes;

/**
 * DER VisibleString object encoding ISO 646 (ASCII) character code points 32 to 126.
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public final class DERVisibleString extends ASN1PrimitiveBytes implements ASN1String {

    /**
     * Return a Visible String from the passed in object.
     *
     * @param obj a DERVisibleString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERVisibleString instance, or null
     */
    public static DERVisibleString getInstance(
        final Object  obj)
    {
        if (obj == null || obj instanceof DERVisibleString)
        {
            return (DERVisibleString)obj;
        }

        if (obj instanceof Bytes)
        {
            try
            {
                return (DERVisibleString)fromBytes((Bytes)obj);
            }
            catch (final Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a Visible String from a tagged object.
     *
     * @param obj the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return a DERVisibleString instance, or null
     */
    public static DERVisibleString getInstance(
        final ASN1TaggedObject obj,
        final boolean          explicit)
    {
        final ASN1Primitive o = obj.getObject();

        if (explicit || o instanceof DERVisibleString)
        {
            return getInstance(o);
        }
        else
        {
            return new DERVisibleString(ASN1OctetString.getInstance(o).getOctets());
        }
    }

    DERVisibleString(final Bytes string){
      super(string);
    }

    public DERVisibleString(final String string){
      this(Strings.toByteArray(string));
    }

    @Override
    public String getString(){
      return Strings.fromByteArray(string);
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
        out.writeEncoded(BERTags.VISIBLE_STRING, string);
    }

}
