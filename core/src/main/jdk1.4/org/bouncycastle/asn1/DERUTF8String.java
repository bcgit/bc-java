package org.bouncycastle.asn1;

/**
 * DER UTF8String object.
 */
public class DERUTF8String
    extends ASN1UTF8String
{
    /**
     * Basic constructor
     *
     * @param string the string to be carried in the UTF8String object,
     */
    public DERUTF8String(String string)
    {
        super(string);
    }

    DERUTF8String(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
