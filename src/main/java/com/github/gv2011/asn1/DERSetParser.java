package com.github.gv2011.asn1;


public class DERSetParser
    implements ASN1SetParser
{
    private final ASN1StreamParser _parser;

    DERSetParser(final ASN1StreamParser parser)
    {
        _parser = parser;
    }

    @Override
    public ASN1Encodable readObject()
    {
        return _parser.readObject();
    }

    @Override
    public ASN1Primitive getLoadedObject()
    {
        return new DERSet(_parser.readVector(), false);
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
            return getLoadedObject();
    }
}
