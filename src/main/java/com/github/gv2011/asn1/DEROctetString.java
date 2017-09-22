package com.github.gv2011.asn1;

import java.io.IOException;

/**
 * Carrier class for a DER encoding OCTET STRING
 */
public class DEROctetString
    extends ASN1OctetString
{
    /**
     * Base constructor.
     *
     * @param string the octets making up the octet string.
     */
    public DEROctetString(
        final byte[]  string)
    {
        super(string);
    }

    /**
     * Constructor from the encoding of an ASN.1 object.
     *
     * @param obj the object to be encoded.
     */
    public DEROctetString(
        final ASN1Encodable obj)
        throws IOException
    {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    @Override
    void encode(
        final ASN1OutputStream out)
    {
        out.writeEncoded(BERTags.OCTET_STRING, string);
    }

    static void encode(
        final DEROutputStream derOut,
        final byte[]          bytes)
        throws IOException
    {
        derOut.writeEncoded(BERTags.OCTET_STRING, bytes);
    }
}
