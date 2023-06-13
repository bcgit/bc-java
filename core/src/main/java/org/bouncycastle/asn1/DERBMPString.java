package org.bouncycastle.asn1;

/**
 * DER BMPString object encodes BMP (<i>Basic Multilingual Plane</i>) subset
 * (aka UCS-2) of UNICODE (ISO 10646) characters in codepoints 0 to 65535.
 * <p>
 * At ISO-10646:2011 the term "BMP" has been withdrawn, and replaced by
 * term "UCS-2".
 * </p>
 */
public class DERBMPString
    extends ASN1BMPString
{
    /**
     * Basic constructor
     * @param string a String to wrap as a BMP STRING.
     */
    public DERBMPString(String string)
    {
        super(string);
    }

    /**
     * Basic constructor - byte encoded string.
     * @param string the encoded BMP STRING to wrap.
     */
    DERBMPString(byte[] contents)
    {
        super(contents);
    }

    DERBMPString(char[] string)
    {
        super(string);
    }
}
