package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * Parser DER EXTERNAL tagged objects.
 */
public class DERExternalParser
    implements ASN1Encodable, InMemoryRepresentable
{
    private ASN1StreamParser _parser;

    /**
     * Base constructor.
     *
     * @param parser the underlying parser to read the DER EXTERNAL from.
     */
    public DERExternalParser(ASN1StreamParser parser)
    {
        this._parser = parser;
    }

    public ASN1Encodable readObject()
        throws IOException
    {
        return _parser.readObject();
    }

    /**
     * Return an in-memory, encodable, representation of the EXTERNAL object.
     *
     * @return a DERExternal.
     * @throws IOException if there is an issue loading the data.
     */
    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        try
        {
            return new DLExternal(_parser.readVector());
        }
        catch (IllegalArgumentException e)
        {
            throw new ASN1Exception(e.getMessage(), e);
        }
    }

    /**
     * Return an DERExternal representing this parser and its contents.
     *
     * @return an DERExternal
     */
    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException ioe)
        {
            throw new ASN1ParsingException("unable to get DER object", ioe);
        }
        catch (IllegalArgumentException ioe)
        {
            throw new ASN1ParsingException("unable to get DER object", ioe);
        }
    }
}