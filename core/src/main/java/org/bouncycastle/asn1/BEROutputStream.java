package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Encode output stream using BER indefinite length rules.
 */

public class BEROutputStream
    extends DEROutputStream
{
    public BEROutputStream(
        OutputStream    os)
    {
        super(os);
    }

    public void writeObject(
        Object    obj)
        throws IOException
    {
        if (obj == null)
        {
            writeNull();
        }
        else if (obj instanceof ASN1Primitive)
        {
            ((ASN1Primitive)obj).encode(this);
        }
        else if (obj instanceof ASN1Encodable)
        {
            ((ASN1Encodable)obj).toASN1Primitive().encode(this);
        }
        else
        {
            throw new IOException("object not BEREncodable");
        }
    }
}
