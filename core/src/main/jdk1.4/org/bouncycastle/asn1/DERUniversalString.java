package org.bouncycastle.asn1;

/**
 * DER UniversalString object - encodes UNICODE (ISO 10646) characters using 32-bit format. In Java we
 * have no way of representing this directly so we rely on byte arrays to carry these.
 */
public class DERUniversalString
    extends ASN1UniversalString
{
    /**
     * Basic constructor - byte encoded string.
     *
     * @param string the byte encoding of the string to be carried in the UniversalString object,
     */
    public DERUniversalString(byte[] string)
    {
        this(string, true);
    }

    DERUniversalString(byte[] contents, boolean clone)
    {
        super(contents, clone);
    }
}
