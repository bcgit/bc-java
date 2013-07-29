package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * DER facade of ASN.1 OCTET-STRING data type.
 * <p>
 * <hr>
 *<hr>
 * See {@link ASN1OctetString} for X.690 encoding rules of OCTET-STRING objects.
 */

public class DEROctetString
    extends ASN1OctetString
{
    /**
     * @param string the octets making up the octet string.
     */
    public DEROctetString(
        byte[]  string)
    {
        super(string);
    }

    public DEROctetString(
        ASN1Encodable obj)
        throws IOException
    {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

    // @Override
    boolean isConstructed()
    {
        return false;
    }

    // @Override
    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    // @Override
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
