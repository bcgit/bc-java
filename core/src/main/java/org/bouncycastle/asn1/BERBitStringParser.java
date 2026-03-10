package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.io.Streams;

/**
 * A parser for indefinite-length BIT STRINGs.
 * 
 * @deprecated Check for 'ASN1BitStringParser' instead 
 */
@Deprecated
public class BERBitStringParser
    implements ASN1BitStringParser
{
    private final ASN1StreamParser parser;

    private ConstructedBitStream _bitStream;

    BERBitStringParser(ASN1StreamParser parser)
    {
        this.parser = parser;
    }

    public InputStream getOctetStream() throws IOException
    {
        this._bitStream = new ConstructedBitStream(parser, true);
        return _bitStream;
    }

    public InputStream getBitStream() throws IOException
    {
        this._bitStream = new ConstructedBitStream(parser, false);
        return _bitStream;
    }

    public int getPadBits()
    {
        return _bitStream.getPadBits();
    }

    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return parse(parser);
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

    static BERBitString parse(ASN1StreamParser sp) throws IOException
    {
        ConstructedBitStream bitStream = new ConstructedBitStream(sp, false);
        byte[] data = Streams.readAll(bitStream);
        int padBits = bitStream.getPadBits();
        return new BERBitString(data, padBits);
    }
}
