package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * @deprecated Use DLSequenceParser instead
 */
public class DERSequenceParser
    implements ASN1SequenceParser
{
    private ASN1StreamParser _parser;

    DERSequenceParser(ASN1StreamParser parser)
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
     * @return a DERSequence.
     * @throws IOException if there is an issue loading the data.
     */
    public ASN1Primitive getLoadedObject()
        throws IOException
    {
         return new DLSequence(_parser.readVector());
    }

    /**
     * Return a DERSequence representing this parser and its contents.
     *
     * @return a DERSequence.
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
