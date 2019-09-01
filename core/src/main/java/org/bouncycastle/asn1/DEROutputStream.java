package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Stream that outputs encoding based on distinguished encoding rules.
 * 
 * @deprecated Will be removed from public API.
 */
public class DEROutputStream
    extends ASN1OutputStream
{
    /**
     * @deprecated Use {@link ASN1OutputStream#create(OutputStream, String)} with
     *             {@link ASN1Encoding#DER} instead.
     */
    public DEROutputStream(OutputStream os)
    {
        super(os);
    }

    void writePrimitive(ASN1Primitive primitive, boolean withTag) throws IOException
    {
        primitive.toDERObject().encode(this, withTag);
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
