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

    protected HashedId(byte[] string)
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
            return new HashedId3(octetString);
        case 8:
            return new HashedId8(octetString);
        case 10:
            return new HashedId10(octetString);
        case 32:
            return new HashedId32(octetString);
        default:
            throw new IllegalStateException("hash id of unsupported length, length was: " + octetString.length);
        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(string);
    }

    public static class HashedId3
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
    }

    public static class HashedId8
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
    }

    public static class HashedId10
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
    }

    public static class HashedId32
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
    }
}
