package com.github.gv2011.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Stream that outputs encoding based on distinguished encoding rules.
 */
public class DEROutputStream
    extends ASN1OutputStream
{
    public DEROutputStream(
        final OutputStream    os)
    {
        super(os);
    }

    @Override
    public void writeObject(
        final ASN1Encodable obj)
    {
        if (obj != null)
        {
            obj.toASN1Primitive().toDERObject().encode(this);
        }
        else
        {
            throw new RuntimeException("null object detected");
        }
    }

    @Override
    ASN1OutputStream getDERSubStream()
    {
        return this;
    }

    @Override
    ASN1OutputStream getDLSubStream()
    {
        return this;
    }
}
