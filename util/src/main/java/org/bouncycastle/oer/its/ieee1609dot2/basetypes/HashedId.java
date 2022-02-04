package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.DEROctetString;

public class HashedId
    extends DEROctetString
{

    protected HashedId(byte[] string)
    {
        super(string);
    }

    public byte[] getHashBytes()
    {
        return getOctets();
    }
}
