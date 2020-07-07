package org.bouncycastle.asn1;

import java.io.OutputStream;

/**
 * A class which writes indefinite and definite length objects. Objects which specify DER will be
 * encoded accordingly, but DL or BER objects will be encoded as defined.
 */
class BEROutputStream
    extends ASN1OutputStream
{
    /**
     * Base constructor.
     *
     * @param os
     *            target output stream.
     */
    BEROutputStream(OutputStream os)
    {
        super(os);
    }
}
