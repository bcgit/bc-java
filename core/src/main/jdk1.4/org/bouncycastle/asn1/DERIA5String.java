package org.bouncycastle.asn1;

/**
 * DER IA5String object - this is a ISO 646 (ASCII) string encoding code points 0 to 127.
 * <p>
 * Explicit character set escape sequences are not allowed.
 * </p>
 */
public class DERIA5String
    extends ASN1IA5String
{
    /**
     * Basic constructor - without validation.
     * @param string the base string to use..
     */
    public DERIA5String(String string)
    {
        this(string, false);
    }

    /**
     * Constructor with optional validation.
     *
     * @param string the base string to wrap.
     * @param validate whether or not to check the string.
     * @throws IllegalArgumentException if validate is true and the string
     * contains characters that should not be in an IA5String.
     */
    public DERIA5String(String string, boolean validate)
    {
        super(string, validate);
    }

    DERIA5String(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
