package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.Exceptions;

/**
 * Stream that outputs encoding based on distinguished encoding rules.
 */
class DEROutputStream
    extends DLOutputStream
{
    DEROutputStream(OutputStream os)
    {
        super(os);
    }

    DEROutputStream getDERSubStream()
    {
        return this;
    }

    void writeElements(ASN1Encodable[] elements)
        throws IOException
    {
        for (int i = 0, count = elements.length; i < count; ++i)
        {
            try
            {
                elements[i].toASN1Primitive().toDERObject().encode(this, true);
            }
            catch (DEREncodingException e)
            {
                throw Exceptions.ioException(e.getMessage(), e);
            }
        }
    }

    void writePrimitive(ASN1Primitive primitive, boolean withTag) throws IOException
    {
        try
        {
            primitive.toDERObject().encode(this, withTag);
        }
        catch (DEREncodingException e)
        {
            throw new IOException(e.getMessage(), e);
        }
    }

    void writePrimitives(ASN1Primitive[] primitives)
        throws IOException
    {
        int count = primitives.length;
        for (int i = 0; i < count; ++i)
        {
            try
            {
                primitives[i].toDERObject().encode(this, true);
            }
            catch (DEREncodingException e)
            {
                throw Exceptions.ioException(e.getMessage(), e);
            }
        }
    }
}
