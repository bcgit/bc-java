package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class PKCS7TypedStream
    extends CMSTypedStream
{
    private final ASN1Encodable content;

    public PKCS7TypedStream(ASN1ObjectIdentifier oid, ASN1Encodable encodable)
        throws IOException
    {
        super(oid);

        content = encodable;
    }

    public ASN1Encodable getContent()
    {
        return content;
    }

    public InputStream getContentStream()
    {
        try
        {
            return getContentStream(content);
        }
        catch (IOException e)
        {
            throw new CMSRuntimeException("unable to convert content to stream: " + e.getMessage(), e);
        }
    }

    public void drain()
        throws IOException
    {
        getContentStream(content); // this will parse in the data
    }

    private InputStream getContentStream(ASN1Encodable encodable)
        throws IOException
    {
        byte[] encoded = encodable.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        int index = 1;

        while ((encoded[index] & 0xff) > 127)
        {
            index++;
        }

        index++;

        return new ByteArrayInputStream(encoded, index, encoded.length - index);
    }
}
