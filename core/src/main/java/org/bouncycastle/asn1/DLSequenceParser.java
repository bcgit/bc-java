package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Parser class for DL SEQUENCEs.
 *
 * TODO The class is only publicly visible to support 'instanceof' checks; provide an alternative
 */
public class DLSequenceParser
    implements ASN1SequenceParser
{
    private ASN1StreamParser _parser;

    DLSequenceParser(ASN1StreamParser parser)
    {
        this._parser = parser;
    }

    /**
     * Return the next object in the SEQUENCE.
     *
     * @return next object in SEQUENCE.
     * @throws IOException if there is an issue loading the object.
     */
    public ASN1Encodable readObject()
        throws IOException
    {
        return _parser.readObject();
    }

    /**
     * Return an in memory, encodable, representation of the SEQUENCE.
     *
     * @return a DLSequence.
     * @throws IOException if there is an issue loading the data.
     */
    public ASN1Primitive getLoadedObject()
        throws IOException
    {
         return new DLSequence(_parser.readVector());
    }

    /**
     * Return a DLSequence representing this parser and its contents.
     *
     * @return a DLSequence.
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
