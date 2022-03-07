package org.bouncycastle.oer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;

public class OERDecoder
{
    public static ASN1Encodable decode(byte[] src, Element e)
        throws IOException
    {
        return decode(new ByteArrayInputStream(src), e);
    }


    public static ASN1Encodable decode(InputStream src, Element e)
        throws IOException
    {
        OERInputStream oerInputStream = new OERInputStream(src);
        return oerInputStream.parse(e);
    }

}
