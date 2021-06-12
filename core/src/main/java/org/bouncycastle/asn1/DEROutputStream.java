package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Stream that outputs encoding based on distinguished encoding rules.
 */
class DEROutputStream
    extends ASN1OutputStream
{
    DEROutputStream(OutputStream os)
    {
        super(os);
    }

    void writeElements(ASN1Encodable[] elements)
        throws IOException
    {
        int count = elements.length;
        for (int i = 0; i < count; ++i)
        {
            elements[i].toASN1Primitive().toDERObject().encode(this, true);
        }
    }

    void writePrimitive(ASN1Primitive primitive, boolean withTag) throws IOException
    {
        primitive.toDERObject().encode(this, withTag);
    }

    void writePrimitives(ASN1Primitive[] primitives)
        throws IOException
    {
        int count = primitives.length;
        for (int i = 0; i < count; ++i)
        {
            primitives[i].toDERObject().encode(this, true);
        }
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
