package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A parser for indefinite-length ASN.1 Private objects.
 */
public class BERPrivateParser
    implements ASN1PrivateParser
{
    private final int tag;
    private final ASN1StreamParser parser;

    BERPrivateParser(int tag, ASN1StreamParser parser)
    {
        this.tag = tag;
        this.parser = parser;
    }

    /**
     * Return the object contained in this private object,
     * @return the contained object.
     * @throws IOException if the underlying stream cannot be read, or does not contain an ASN.1 encoding.
     */
    public ASN1Encodable readObject()
        throws IOException
    {
        return parser.readObject();
    }

    /**
     * Return an in-memory, encodable, representation of the private object.
     *
     * @return a BERPrivate.
     * @throws IOException if there is an issue loading the data.
     */
    public ASN1Primitive getLoadedObject()
        throws IOException
    {
         return new BERPrivate(tag, parser.readVector());
    }

    /**
     * Return a BERPrivate representing this parser and its contents.
     *
     * @return a BERPrivate
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
