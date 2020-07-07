package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Stream that outputs encoding based on definite length.
 */
class DLOutputStream
    extends ASN1OutputStream
{
    DLOutputStream(OutputStream os)
    {
        super(os);
    }

    void writePrimitive(ASN1Primitive primitive, boolean withTag) throws IOException
    {
        primitive.toDLObject().encode(this, withTag);
    }

    ASN1OutputStream getDLSubStream()
    {
        return this;
    }
}
