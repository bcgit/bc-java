package org.bouncycastle.asn1;

/**
 * DER T61String (also the teletex string), try not to use this if you don't need to. The standard support the encoding for
 * this has been withdrawn.
 */
public class DERT61String
    extends ASN1T61String
{
    /**
     * Basic constructor - with string 8 bit assumed.
     *
     * @param string the string to be wrapped.
     */
    public DERT61String(String string)
    {
        super(string);
    }

    /**
     * Basic constructor - string encoded as a sequence of bytes.
     *
     * @param string the byte encoding of the string to be wrapped.
     */
    public DERT61String(byte[] string)
    {
        this(string, true);
    }

    DERT61String(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
