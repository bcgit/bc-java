package org.bouncycastle.asn1;

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
        byte[]  string)
    {
        super(string);
    }

    /**
     * Constructor from the encoding of an ASN.1 object.
     *
     * @param obj the object to be encoded.
     */
    public DEROctetString(
        ASN1Encodable obj)
        throws IOException
    {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.OCTET_STRING, string);
    }

    static void encode(
        DEROutputStream derOut,
        byte[]          bytes)
        throws IOException
    {
        derOut.writeEncoded(BERTags.OCTET_STRING, bytes);
    }
}
