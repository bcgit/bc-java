package org.bouncycastle.asn1;

/**
 * DER NumericString object - this is an ascii string of characters {0,1,2,3,4,5,6,7,8,9, }.
 * ASN.1 NUMERIC-STRING object.
 * <p>
 * This is an ASCII string of characters {0,1,2,3,4,5,6,7,8,9} + space.
 * <p>
 * See X.680 section 37.2.
 * <p>
 * Explicit character set escape sequences are not allowed.
 */
public class DERNumericString
    extends ASN1NumericString
{
    /**
     * Basic constructor -  without validation..
     */
    public DERNumericString(String string)
    {
        this(string, false);
    }

    /**
     * Constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws IllegalArgumentException if validate is true and the string
     * contains characters that should not be in a NumericString.
     */
    public DERNumericString(String string, boolean validate)
    {
        super(string, validate);
    }

    DERNumericString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
