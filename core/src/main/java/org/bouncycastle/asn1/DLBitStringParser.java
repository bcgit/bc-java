package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

/**
 * Parser for a DL encoded BIT STRING.
 * 
 * @deprecated Check for 'ASN1BitStringParser' instead 
 */
public class DLBitStringParser
    implements ASN1BitStringParser
{
    private final DefiniteLengthInputStream stream;
    private int padBits = 0;

    DLBitStringParser(
        DefiniteLengthInputStream stream)
    {
        this.stream = stream;
    }

    public InputStream getBitStream() throws IOException
    {
        return getBitStream(false);
    }

    public InputStream getOctetStream() throws IOException
    {
        return getBitStream(true);
    }

    public int getPadBits()
    {
        return padBits;
    }

    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return ASN1BitString.createPrimitive(stream.toByteArray());
    }

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

    private InputStream getBitStream(boolean octetAligned) throws IOException
    {
        int length = stream.getRemaining();
        if (length < 1)
        {
            throw new IllegalStateException("content octets cannot be empty");
        }

        padBits = stream.read();
        if (padBits > 0)
        {
            if (length < 2)
            {
                throw new IllegalStateException("zero length data with non-zero pad bits");
            }
            if (padBits > 7)
            {
                throw new IllegalStateException("pad bits cannot be greater than 7 or less than 0");
            }
            if (octetAligned)
            {
                throw new IOException("expected octet-aligned bitstring, but found padBits: " + padBits);
            }
        }

        return stream;
    }
}
