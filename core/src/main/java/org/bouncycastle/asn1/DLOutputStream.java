package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Stream that outputs encoding based on definite length.
 * 
 * @deprecated Will be removed from public API.
 */
public class DLOutputStream
    extends ASN1OutputStream
{
    /**
     * @deprecated Use {@link ASN1OutputStream#create(OutputStream, String)} with
     *             {@link ASN1Encoding#DL} instead.
     */
    public DLOutputStream(OutputStream os)
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
