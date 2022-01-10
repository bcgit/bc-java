package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1OctetString;

public class HashedId32
    extends HashedId
{

    public HashedId32(byte[] string)
    {
        super(string);
        if (string.length != 32)
        {
            throw new IllegalArgumentException("hash id not 32 bytes");
        }
    }

    public static org.bouncycastle.oer.its.HashedId32 getInstance(Object src)
    {
        if (src instanceof org.bouncycastle.oer.its.HashedId32)
        {
            return (org.bouncycastle.oer.its.HashedId32)src;
        }
        byte[] octetString = ASN1OctetString.getInstance(src).getOctets();
        return new org.bouncycastle.oer.its.HashedId32(octetString);
    }
}
