package org.bouncycastle.asn1;

/**
 * DER VisibleString object encoding ISO 646 (ASCII) character code points 32 to 126.
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public class DERVisibleString
    extends ASN1VisibleString
{
    /**
     * Basic constructor
     *
     * @param string the string to be carried in the VisibleString object,
     */
    public DERVisibleString(String string)
    {
        super(string);
    }

    DERVisibleString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
