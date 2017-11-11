package com.github.gv2011.asn1;


import java.util.Enumeration;

import com.github.gv2011.util.bytes.Bytes;

class LazyConstructionEnumeration
    implements Enumeration<ASN1Encodable>
{
    private final ASN1InputStream aIn;
    private ASN1Primitive          nextObj;

    public LazyConstructionEnumeration(final Bytes encoded)
    {
        aIn = new ASN1InputStream(encoded, true);
        nextObj = readObject();
    }

    @Override
    public boolean hasMoreElements()
    {
        return nextObj != null;
    }

    @Override
    public ASN1Primitive nextElement()
    {
        final ASN1Primitive o = nextObj;

        nextObj = readObject();

        return o;
    }

    private ASN1Primitive readObject()
    {
            return aIn.readObject();
    }
}
