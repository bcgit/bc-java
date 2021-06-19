package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.Arrays;

public class HashedId
    extends ASN1Object
{
    private final byte[] string;

    public HashedId(byte[] string)
    {
        this.string = Arrays.clone(string);
    }

    public static HashedId getInstance(Object src)
    {
        if (src instanceof HashedId)
        {
            return (HashedId)src;
        }

        byte[] octetString = ASN1OctetString.getInstance(src).getOctets();
        switch (octetString.length)
        {
        case 3:
        case 8:
        case 10:
        case 32:
            return new HashedId(octetString);
        default:
            throw new IllegalStateException("hash id of unsupported length, length was: " + octetString.length);
        }

    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(string);
    }
}
