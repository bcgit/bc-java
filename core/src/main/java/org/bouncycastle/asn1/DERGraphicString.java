package org.bouncycastle.asn1;

public class DERGraphicString
    extends ASN1GraphicString
{
    public DERGraphicString(byte[] octets)
    {
        this(octets, true);
    }

    DERGraphicString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
