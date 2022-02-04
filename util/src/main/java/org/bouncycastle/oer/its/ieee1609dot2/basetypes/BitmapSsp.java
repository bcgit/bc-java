package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.DEROctetString;

public class BitmapSsp
    extends DEROctetString
{

    public BitmapSsp(byte[] string)
    {
        super(string);
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
}
