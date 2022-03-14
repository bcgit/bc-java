package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.Arrays;

public class BitmapSsp
    extends ASN1Object
{
    private final DEROctetString string;

    public BitmapSsp(byte[] string)
    {
        this.string = new DEROctetString(Arrays.clone(string));
    }

    public BitmapSsp(DEROctetString string)
    {
        this.string = string;
    }

    public static BitmapSsp getInstance(Object o)
    {
        if (o instanceof BitmapSsp)
        {
            return (BitmapSsp)o;
        }

        if (o != null)
        {
            return new BitmapSsp(DEROctetString.getInstance(o).getOctets());
        }

        return null;
    }

    public DEROctetString getString()
    {
        return string;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return string;
    }

}
