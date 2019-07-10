package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Stream that outputs encoding based on distinguished encoding rules.
 */
public class DEROutputStream
    extends ASN1OutputStream
{
    public DEROutputStream(
        OutputStream    os)
    {
        super(os);
    }

    public void writeObject(ASN1Encodable obj) throws IOException
    {
        if (obj != null)
        {
            obj.toASN1Primitive().toDERObject().encode(this);
        }
        else
        {
            throw new IOException("null object detected");
        }
    }

    public void writeObject(ASN1Primitive primitive) throws IOException
    {
        if (null == primitive)
        {
            throw new IOException("null object detected");
        }

        primitive.toDERObject().encode(this);
    }

    DEROutputStream getDERSubStream()
    {
        return this;
    }

    ASN1OutputStream getDLSubStream()
    {
        return this;
    }
}
