package org.bouncycastle.oer.its;

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
}
