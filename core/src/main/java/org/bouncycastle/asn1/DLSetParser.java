package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Parser class for DL SETs.
 *
 * TODO The class is only publicly visible to support 'instanceof' checks; provide an alternative
 */
public class DLSetParser
    implements ASN1SetParser
{
    private ASN1StreamParser _parser;

    DLSetParser(ASN1StreamParser parser)
    {
        this._parser = parser;
    }

    /**
     * Return the next object in the SET.
     *
     * @return next object in SET.
     * @throws IOException if there is an issue loading the object.
     */
    public ASN1Encodable readObject()
        throws IOException
    {
        return _parser.readObject();
    }

    /**
     * Return an in memory, encodable, representation of the SET.
     *
     * @return a DLSet.
     * @throws IOException if there is an issue loading the data.
     */
    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return new DLSet(_parser.readVector());
    }

    /**
     * Return a DLSet representing this parser and its contents.
     *
     * @return a DLSet
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
