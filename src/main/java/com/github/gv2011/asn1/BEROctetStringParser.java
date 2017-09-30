package com.github.gv2011.asn1;

import java.io.InputStream;

import com.github.gv2011.asn1.util.io.Streams;

public class BEROctetStringParser
    implements ASN1OctetStringParser
{
    private final ASN1StreamParser _parser;

    BEROctetStringParser(
        final ASN1StreamParser parser)
    {
        _parser = parser;
    }

    @Override
    public InputStream getOctetStream()
    {
        return new ConstructedOctetStream(_parser);
    }

    @Override
    public ASN1Primitive getLoadedObject()
    {
        return new BEROctetString(Streams.readAll(getOctetStream()));
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
            return getLoadedObject();
    }
}
