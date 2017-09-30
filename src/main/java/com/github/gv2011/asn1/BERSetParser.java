package com.github.gv2011.asn1;


/**
 * Parser for indefinite-length SETs.
 */
public class BERSetParser
    implements ASN1SetParser
{
    private final ASN1StreamParser _parser;

    BERSetParser(final ASN1StreamParser parser)
    {
        _parser = parser;
    }

    /**
     * Read the next object in the SET.
     *
     * @return the next object in the SET, null if there are no more.
     * @throws IOException if there is an issue reading the underlying stream.
     */
    @Override
    public ASN1Encodable readObject()
    {
        return _parser.readObject();
    }

    /**
     * Return an in-memory, encodable, representation of the SET.
     *
     * @return a BERSet.
     * @throws IOException if there is an issue loading the data.
     */
    @Override
    public ASN1Primitive getLoadedObject()
    {
        return new BERSet(_parser.readVector());
    }

    /**
     * Return an BERSet representing this parser and its contents.
     *
     * @return an BERSet
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
            return getLoadedObject();
    }
}