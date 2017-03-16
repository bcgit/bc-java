package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A class which writes indefinite and definite length objects,
 */
public class BEROutputStream
    extends DEROutputStream
{
    /**
     * Base constructor.
     *
     * @param os target output stream.
     */
    public BEROutputStream(
        OutputStream    os)
    {
        super(os);
    }

    /**
     * Write out an ASN.1 object.
     *
     * @param obj the object to be encoded.
     * @throws IOException if there is an issue on encoding or output of the object.
     */
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
