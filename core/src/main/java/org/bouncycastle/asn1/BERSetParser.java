package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Parser for indefinite-length SETs.
 */
public class BERSetParser
    implements ASN1SetParser
{
    private ASN1StreamParser _parser;

    BERSetParser(ASN1StreamParser parser)
    {
        this._parser = parser;
    }

    /**
     * Read the next object in the SET.
     *
     * @return the next object in the SET, null if there are no more.
     * @throws IOException if there is an issue reading the underlying stream.
     */
    public ASN1Encodable readObject()
        throws IOException
    {
        return _parser.readObject();
    }

    /**
     * Return an in-memory, encodable, representation of the SET.
     *
     * @return a BERSet.
     * @throws IOException if there is an issue loading the data.
     */
    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return new BERSet(_parser.readVector());
    }

    /**
     * Return an BERSet representing this parser and its contents.
     *
     * @return an BERSet
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