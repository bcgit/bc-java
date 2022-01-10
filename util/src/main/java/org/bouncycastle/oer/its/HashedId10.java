package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1OctetString;

public class HashedId10
    extends HashedId
{

    public HashedId10(byte[] string)
    {
        super(string);
        if (string.length != 10)
        {
            throw new IllegalArgumentException("hash id not 10 bytes");
        }
    }

    public static org.bouncycastle.oer.its.HashedId10 getInstance(Object src)
    {
        if (src instanceof org.bouncycastle.oer.its.HashedId10)
        {
            return (org.bouncycastle.oer.its.HashedId10)src;
        }
        byte[] octetString = ASN1OctetString.getInstance(src).getOctets();
        return new org.bouncycastle.oer.its.HashedId10(octetString);
    }
}
