package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;

public class BitmapSsp
    extends DEROctetString
{

    public BitmapSsp(byte[] string)
    {
        super(string);
    }

    public BitmapSsp(ASN1Encodable obj)
        throws IOException
    {
        super(obj);
    }

    public static BitmapSsp getInstance(Object o)
    {
        if (o instanceof BitmapSsp)
        {
            return (BitmapSsp)o;
        }
        if (o instanceof ASN1Encodable)
        {
            try
            {
                return new BitmapSsp((ASN1Encodable)o);
            }
            catch (IOException e)
            {
                throw new RuntimeException(e.getMessage(), e);
            }
        }

        return null;
    }
}
