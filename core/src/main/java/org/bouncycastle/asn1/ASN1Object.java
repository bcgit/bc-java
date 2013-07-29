package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Basic abstract ASN.1 Object.
 * <p>
 * This supplies basic Object-like things:
 * <ul>
 * <li> hashCode()
 * <li> equals()
 * </ul>
 * <p>
 * plus ASN1Object things:
 * <ul>
 * <li> getEncoded() (two forms)
 * <li> toASN1Primitive()
 * </ul>
 */


public abstract class ASN1Object
    implements ASN1Encodable
{
    /**
     * Return the default BER or DER encoding for this object.
     *
     * @return BER/DER byte encoded object.
     * @throws java.io.IOException on encoding error.
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream      aOut = new ASN1OutputStream(bOut);

        aOut.writeObject(this);

        return bOut.toByteArray();
    }

    /**
     * Return either the default for "BER" or a DER encoding if "DER" is specified.
     *
     * @param encoding name of encoding to use.
     * @return byte encoded object.
     * @throws IOException on encoding error.
     */
    public byte[] getEncoded(
        String encoding)
        throws IOException
    {
        if (encoding.equals(ASN1Encoding.DER))
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            DEROutputStream         dOut = new DEROutputStream(bOut);

            dOut.writeObject(this);

            return bOut.toByteArray();
        }
        else if (encoding.equals(ASN1Encoding.DL))
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            DLOutputStream          dOut = new DLOutputStream(bOut);

            dOut.writeObject(this);

            return bOut.toByteArray();
        }

        return this.getEncoded();
    }

    /**
     * Stable hashCode() from ASN.1 object.
     */
    // @Override
    public int hashCode()
    {
        return this.toASN1Primitive().hashCode();
    }

    /**
     * ASN.1 object equality comparator - most commonly the comparison is about <i>similarity</i>.
     */
    // @Override
    public boolean equals(
        Object  o)
    {
        if (this == o)
        {
            return true;
        }

        if (!(o instanceof ASN1Encodable))
        {
            return false;
        }

        ASN1Encodable other = (ASN1Encodable)o;

        return this.toASN1Primitive().equals(other.toASN1Primitive());
    }

    /**
     * @deprecated use toASN1Primitive()
     * @return the underlying primitive type.
     */
    public ASN1Primitive toASN1Object()
    {
        return this.toASN1Primitive();
    }

    /**
     * Parser support tool.
     */
    protected static boolean hasEncodedTagValue(Object obj, int tagValue)
    {
        return (obj instanceof byte[]) && ((byte[])obj)[0] == tagValue;
    }

    /**
     * Supply serializers with {@link ASN1Primitive} form of data.
     */
    public abstract ASN1Primitive toASN1Primitive();
}
