package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

/**
 * Parser for DER encoded OCTET STRINGS
 */
public class DEROctetStringParser
    implements ASN1OctetStringParser
{
    private DefiniteLengthInputStream stream;

    DEROctetStringParser(
        DefiniteLengthInputStream stream)
    {
        this.stream = stream;
    }

    /**
     * Return an InputStream representing the contents of the OCTET STRING.
     *
     * @return an InputStream with its source as the OCTET STRING content.
     */
    public InputStream getOctetStream()
    {
        return stream;
    }

    /**
     * Return an in-memory, encodable, representation of the OCTET STRING.
     *
     * @return a DEROctetString.
     * @throws IOException if there is an issue loading the data.
     */
    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return new DEROctetString(stream.toByteArray());
    }

    /**
     * Return an DEROctetString representing this parser and its contents.
     *
     * @return an DEROctetString
     */
    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException e)
        {
            throw new ASN1ParsingException("IOException converting stream to byte array: " + e.getMessage(), e);
        }
    }
}
