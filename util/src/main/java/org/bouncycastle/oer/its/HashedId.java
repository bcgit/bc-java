package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.Arrays;

class HashedId
    extends ASN1Object
{
    private final byte[] string;

    protected HashedId(byte[] string)
    {
        this.string = Arrays.clone(string);
    }


    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(string);
    }

}
