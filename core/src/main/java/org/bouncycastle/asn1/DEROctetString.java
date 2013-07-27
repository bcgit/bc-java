package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * DER facade of ASN.1 OCTET-STRING data type.
 * <p>
 * <hr>
 * <h2>X.690</h2>
 * <h3>10 Distinguished encoding rules</h3>
 * <h4>10.2 String encoding forms</h4>
 * For bitstring, octetstring and restricted character string types,
 * the constructed form of encoding shall not be used. 
 * (Contrast with 8.21.6.)
 * <p>
 * <h3>8: Basic encoding rules (with DER rules applied)</h3>
 * <h4>8.7 Encoding of an octetstring value</h4>
 * <p>
 * <b>8.7.1</b> The encoding of an octetstring value shall be primitive.
 * <p>
 * <b>8.7.2</b> The primitive encoding contains zero, one or more
 * contents octets equal in value to the octets in the data value, 
 * in the order they appear in the data value, and with the most
 * significant bit of an octet of the data value aligned with the 
 * most significant bit of an octet of the contents octets.
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
