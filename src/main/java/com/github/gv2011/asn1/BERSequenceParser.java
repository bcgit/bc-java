package com.github.gv2011.asn1;


/**
 * Parser for indefinite-length SEQUENCEs.
 */
public class BERSequenceParser
    implements ASN1SequenceParser
{
    private final ASN1StreamParser _parser;

    BERSequenceParser(final ASN1StreamParser parser)
    {
        _parser = parser;
    }

    /**
     * Read the next object in the SEQUENCE.
     *
     * @return the next object in the SEQUENCE, null if there are no more.
     * @throws IOException if there is an issue reading the underlying stream.
     */
    @Override
    public ASN1Encodable readObject()
    {
        return _parser.readObject();
    }

    /**
     * Return an in-memory, encodable, representation of the SEQUENCE.
     *
     * @return a BERSequence.
     * @throws IOException if there is an issue loading the data.
     */
    @Override
    public ASN1Primitive getLoadedObject()
    {
        return new BERSequence(_parser.readVector());
    }

    /**
     * Return an BERSequence representing this parser and its contents.
     *
     * @return an BERSequence
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
            return getLoadedObject();
    }
}
