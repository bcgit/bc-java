package com.github.gv2011.asn1;


/**
 * Parser DER EXTERNAL tagged objects.
 */
public class DERExternalParser
    implements ASN1Encodable, InMemoryRepresentable
{
    private final ASN1StreamParser _parser;

    /**
     * Base constructor.
     *
     * @param parser the underlying parser to read the DER EXTERNAL from.
     */
    public DERExternalParser(final ASN1StreamParser parser)
    {
        _parser = parser;
    }

    public ASN1Encodable readObject()
    {
        return _parser.readObject();
    }

    /**
     * Return an in-memory, encodable, representation of the EXTERNAL object.
     *
     * @return a DERExternal.
     * @throws IOException if there is an issue loading the data.
     */
    @Override
    public ASN1Primitive getLoadedObject()
    {
        try
        {
            return new DERExternal(_parser.readVector());
        }
        catch (final IllegalArgumentException e)
        {
            throw new ASN1Exception(e.getMessage(), e);
        }
    }

    /**
     * Return an DERExternal representing this parser and its contents.
     *
     * @return an DERExternal
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (final IllegalArgumentException ioe)
        {
            throw new ASN1ParsingException("unable to get DER object", ioe);
        }
    }
}