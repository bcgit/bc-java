package com.github.gv2011.asn1;

import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;

import java.io.IOException;

import com.github.gv2011.asn1.util.Encodable;
import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

/**
 * Base class for defining an ASN.1 object.
 */
public abstract class ASN1Object
    implements ASN1Encodable, Encodable
{
    /**
     * Return the default BER or DER encoding for this object.
     *
     * @return BER/DER byte encoded object.
     * @throws java.io.IOException on encoding error.
     */
    @Override
    public Bytes getEncoded()
    {
        final BytesBuilder bOut = newBytesBuilder();
        final ASN1OutputStream      aOut = new ASN1OutputStream(bOut);

        aOut.writeObject(this);

        return bOut.build();
    }

    /**
     * Return either the default for "BER" or a DER encoding if "DER" is specified.
     *
     * @param encoding name of encoding to use.
     * @return byte encoded object.
     * @throws IOException on encoding error.
     */
    public Bytes getEncoded(
        final String encoding)
    {
        if (encoding.equals(ASN1Encoding.DER)) return getDerEncoded();
        else if (encoding.equals(ASN1Encoding.DL))
        {
            final BytesBuilder   bOut = newBytesBuilder();
            final DLOutputStream dOut = new DLOutputStream(bOut);

            dOut.writeObject(this);

            return bOut.build();
        }

        return this.getEncoded();
    }

    public final Bytes getDerEncoded(){
      final BytesBuilder bOut = newBytesBuilder();
      final DEROutputStream dOut = new DEROutputStream(bOut);
      dOut.writeObject(this);
      return bOut.build();
    }

    @Override
    public int hashCode()
    {
        return toASN1Primitive().hashCode();
    }

    @Override
    public boolean equals(
        final Object  o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof ASN1Encodable))
        {
            return false;
        }

        final ASN1Encodable other = (ASN1Encodable)o;

        return toASN1Primitive().equals(other.toASN1Primitive());
    }

    /**
     * @deprecated use toASN1Primitive()
     * @return the underlying primitive type.
     */
    @Deprecated
    public ASN1Primitive toASN1Object()
    {
        return toASN1Primitive();
    }

    /**
     * Return true if obj is a byte array and represents an object with the given tag value.
     *
     * @param obj object of interest.
     * @param tagValue tag value to check for.
     * @return  true if obj is a byte encoding starting with the given tag value, false otherwise.
     */
    protected static boolean hasEncodedTagValue(final Object obj, final int tagValue)
    {
        return (obj instanceof byte[]) && ((byte[])obj)[0] == tagValue;
    }

    /**
     * Method providing a primitive representation of this object suitable for encoding.
     * @return a primitive representation of this object.
     */
    @Override
    public abstract ASN1Primitive toASN1Primitive();
}
