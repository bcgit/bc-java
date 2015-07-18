package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Parser for indefinite-length SEQUENCEs.
 */
public class BERSequenceParser
    implements ASN1SequenceParser
{
    private ASN1StreamParser _parser;

    BERSequenceParser(ASN1StreamParser parser)
    {
        this._parser = parser;
    }

    /**
     * Read the next object in the SEQUENCE.
     *
     * @return the next object in the SEQUENCE, null if there are no more.
     * @throws IOException if there is an issue reading the underlying stream.
     */
    public ASN1Encodable readObject()
        throws IOException
    {
        return _parser.readObject();
    }

    /**
     * Return an in-memory, encodable, representation of the SEQUENCE.
     *
     * @return a BERSequence.
     * @throws IOException if there is an issue loading the data.
     */
    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return new BERSequence(_parser.readVector());
    }

    /**
     * Return an BERSequence representing this parser and its contents.
     *
     * @return an BERSequence
     */
    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e.getMessage());
        }
    }
}
