package com.github.gv2011.asn1;


import java.util.Enumeration;

import com.github.gv2011.util.bytes.Bytes;

class LazyConstructionEnumeration
    implements Enumeration<Object>
{
    private final ASN1InputStream aIn;
    private Object          nextObj;

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
    public Object nextElement()
    {
        final Object o = nextObj;

        nextObj = readObject();

        return o;
    }

    private Object readObject()
    {
            return aIn.readObject();
    }
}
