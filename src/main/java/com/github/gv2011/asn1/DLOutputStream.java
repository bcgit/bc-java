package com.github.gv2011.asn1;

import java.io.OutputStream;

/**
 * Stream that outputs encoding based on definite length.
 */
public class DLOutputStream
    extends ASN1OutputStream
{
    public DLOutputStream(
        final OutputStream os)
    {
        super(os);
    }

    @Override
    public void writeObject(
        final ASN1Encodable obj)
    {
        if (obj != null)
        {
            obj.toASN1Primitive().toDLObject().encode(this);
        }
        else
        {
            throw new RuntimeException("null object detected");
        }
    }
}
