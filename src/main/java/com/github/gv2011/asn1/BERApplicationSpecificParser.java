package com.github.gv2011.asn1;


/**
 * A parser for indefinite-length application specific objects.
 */
public class BERApplicationSpecificParser
    implements ASN1ApplicationSpecificParser
{
    private final int tag;
    private final ASN1StreamParser parser;

    BERApplicationSpecificParser(final int tag, final ASN1StreamParser parser)
    {
        this.tag = tag;
        this.parser = parser;
    }

    /**
     * Return the object contained in this application specific object,
     * @return the contained object.
     * @throws IOException if the underlying stream cannot be read, or does not contain an ASN.1 encoding.
     */
    @Override
    public ASN1Encodable readObject(){
        return parser.readObject();
    }

    /**
     * Return an in-memory, encodable, representation of the application specific object.
     *
     * @return a BERApplicationSpecific.
     * @throws IOException if there is an issue loading the data.
     */
    @Override
    public ASN1Primitive getLoadedObject(){
         return new BERApplicationSpecific(tag, parser.readVector());
    }

    /**
     * Return a BERApplicationSpecific representing this parser and its contents.
     *
     * @return a BERApplicationSpecific
     */
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return getLoadedObject();
    }
}
