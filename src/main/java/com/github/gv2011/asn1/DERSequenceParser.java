package com.github.gv2011.asn1;

import java.io.IOException;

public class DERSequenceParser
    implements ASN1SequenceParser
{
    private final ASN1StreamParser _parser;

    DERSequenceParser(final ASN1StreamParser parser)
    {
        _parser = parser;
    }

    @Override
    public ASN1Encodable readObject()
        throws IOException
    {
        return _parser.readObject();
    }

    @Override
    public ASN1Primitive getLoadedObject()
    {
         return new DERSequence(_parser.readVector());
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
            return getLoadedObject();
    }
}
