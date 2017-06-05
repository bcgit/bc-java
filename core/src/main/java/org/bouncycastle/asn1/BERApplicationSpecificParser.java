package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A parser for indefinite-length ASN.1 ApplicationSpecific objects.
 */
public class BERApplicationSpecificParser
    implements ASN1ApplicationSpecificParser
{
    private final int tag;
    private final ASN1StreamParser parser;

    BERApplicationSpecificParser(int tag, ASN1StreamParser parser)
    {
        this.tag = tag;
        this.parser = parser;
    }

    /**
     * Return the object contained in this application specific object,
     * @return the contained object.
     * @throws IOException if the underlying stream cannot be read, or does not contain an ASN.1 encoding.
     */
    public ASN1Encodable readObject()
        throws IOException
    {
        return parser.readObject();
    }

    /**
     * Return an in-memory, encodable, representation of the application specific object.
     *
     * @return a BERApplicationSpecific.
     * @throws IOException if there is an issue loading the data.
     */
    public ASN1Primitive getLoadedObject()
        throws IOException
    {
         return new BERApplicationSpecific(tag, parser.readVector());
    }

    /**
     * Return a BERApplicationSpecific representing this parser and its contents.
     *
     * @return a BERApplicationSpecific
     */
    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException e)
        {
            throw new ASN1ParsingException(e.getMessage(), e);
        }
    }
}
