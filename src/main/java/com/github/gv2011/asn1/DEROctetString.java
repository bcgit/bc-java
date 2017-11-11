package com.github.gv2011.asn1;

import com.github.gv2011.util.bytes.Bytes;

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
        final Bytes  string)
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
    {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER));
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
        out.writeEncoded(BERTags.OCTET_STRING, string);
    }

    static void encode(
        final DEROutputStream derOut,
        final Bytes          bytes)
    {
        derOut.writeEncoded(BERTags.OCTET_STRING, bytes);
    }
}
