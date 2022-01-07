package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1OctetString;

public class HashedId8
    extends HashedId
{
    public HashedId8(byte[] string)
    {
        super(string);
        if (string.length != 8)
        {
            throw new IllegalArgumentException("hash id not 8 bytes");
        }
    }

    public static org.bouncycastle.oer.its.HashedId8 getInstance(Object src)
    {
        if (src instanceof org.bouncycastle.oer.its.HashedId8)
        {
            return (org.bouncycastle.oer.its.HashedId8)src;
        }
        byte[] octetString = ASN1OctetString.getInstance(src).getOctets();
        return new org.bouncycastle.oer.its.HashedId8(octetString);
    }
}
