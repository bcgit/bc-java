package com.github.gv2011.asn1;

import static com.github.gv2011.util.bytes.ByteUtils.newBytesBuilder;

import java.io.IOException;

import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

/**
 * A DER encoding version of an application specific object.
 */
public class DERApplicationSpecific
    extends ASN1ApplicationSpecific
{
    DERApplicationSpecific(
        final boolean isConstructed,
        final int     tag,
        final Bytes  octets)
    {
        super(isConstructed, tag, octets);
    }

    /**
     * Create an application specific object from the passed in data. This will assume
     * the data does not represent a constructed object.
     *
     * @param tag the tag number for this object.
     * @param octets the encoding of the object's body.
     */
    public DERApplicationSpecific(
        final int    tag,
        final Bytes octets)
    {
        this(false, tag, octets);
    }

    /**
     * Create an application specific object with a tagging of explicit/constructed.
     *
     * @param tag the tag number for this object.
     * @param object the object to be contained.
     */
    public DERApplicationSpecific(
        final int           tag,
        final ASN1Encodable object)
        throws IOException
    {
        this(true, tag, object);
    }

    /**
     * Create an application specific object with the tagging style given by the value of constructed.
     *
     * @param constructed true if the object is constructed.
     * @param tag the tag number for this object.
     * @param object the object to be contained.
     */
    public DERApplicationSpecific(
        final boolean      constructed,
        final int          tag,
        final ASN1Encodable object)
        throws IOException
    {
        super(constructed || object.toASN1Primitive().isConstructed(), tag, getEncoding(constructed, object));
    }

    private static Bytes getEncoding(final boolean explicit, final ASN1Encodable object)
        throws IOException
    {
        final Bytes data = object.toASN1Primitive().getEncoded(ASN1Encoding.DER);

        if (explicit)
        {
            return data;
        }
        else
        {
          // final int lenBytes = getLengthOfHeader(data);
          // final byte[] tmp = new byte[data.size() - lenBytes];
          // System.arraycopy(data, lenBytes, tmp, 0, tmp.length);
          return data.subList(getLengthOfHeader(data));
        }
    }

    /**
     * Create an application specific object which is marked as constructed
     *
     * @param tagNo the tag number for this object.
     * @param vec the objects making up the application specific object.
     */
    public DERApplicationSpecific(final int tagNo, final ASN1EncodableVector vec)
    {
        super(true, tagNo, getEncodedVector(vec));
    }

    private static Bytes getEncodedVector(final ASN1EncodableVector vec){
      final BytesBuilder bOut = newBytesBuilder();
      for (int i = 0; i != vec.size(); i++){
        ((ASN1Object)vec.get(i)).getEncoded(ASN1Encoding.DER).write(bOut);
      }
      return bOut.build();
    }

    /**
     * @see org.bouncycastle.asn1.ASN1Primitive#encode(org.bouncycastle.asn1.DEROutputStream)
     */
    @Override
    void encode(final ASN1OutputStream out)
    {
        int classBits = BERTags.APPLICATION;
        if (isConstructed)
        {
            classBits |= BERTags.CONSTRUCTED;
        }

        out.writeEncoded(classBits, tag, octets);
    }
}
