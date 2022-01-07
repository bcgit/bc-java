package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1OctetString;

public class HashedId3
    extends HashedId
{

    public HashedId3(byte[] string)
    {
        super(string);
        if (string.length != 3)
        {
            throw new IllegalArgumentException("hash id not 3 bytes");
        }
    }

    public static org.bouncycastle.oer.its.HashedId3 getInstance(Object src)
    {
        if (src instanceof org.bouncycastle.oer.its.HashedId3)
        {
            return (org.bouncycastle.oer.its.HashedId3)src;
        }
        byte[] octetString = ASN1OctetString.getInstance(src).getOctets();
        return new org.bouncycastle.oer.its.HashedId3(octetString);
    }
}
