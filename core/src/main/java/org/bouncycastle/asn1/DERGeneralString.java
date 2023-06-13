package org.bouncycastle.asn1;

/**
 * ASN.1 GENERAL-STRING data type.
 * <p>
 * This is an 8-bit encoded ISO 646 (ASCII) character set
 * with optional escapes to other character sets.
 * </p>
 */
public class DERGeneralString 
    extends ASN1GeneralString
{
    /**
     * Construct a GeneralString from the passed in String.
     *
     * @param string the string to be contained in this object.
     */
    public DERGeneralString(String string)
    {
        super(string);
    }

    DERGeneralString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
