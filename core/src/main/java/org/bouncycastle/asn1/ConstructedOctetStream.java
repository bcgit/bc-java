package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

class ConstructedOctetStream
    extends InputStream
{
    private final ASN1StreamParser _parser;

    private boolean                _first = true;
    private InputStream            _currentStream;

    ConstructedOctetStream(
        ASN1StreamParser parser)
    {
        _parser = parser;
    }

    public int read(byte[] b, int off, int len) throws IOException
    {
        if (_currentStream == null)
        {
            if (!_first)
            {
                return -1;
            }

            ASN1OctetStringParser next = getNextParser();
            if (next == null)
            {
                return -1;
            }

            _first = false;
            _currentStream = next.getOctetStream();
        }

        int totalRead = 0;

        for (;;)
        {
            int numRead = _currentStream.read(b, off + totalRead, len - totalRead);

            if (numRead >= 0)
            {
                totalRead += numRead;

                if (totalRead == len)
                {
                    return totalRead;
                }
            }
            else
            {
                ASN1OctetStringParser next = getNextParser();
                if (next == null)
                {
                    _currentStream = null;
                    return totalRead < 1 ? -1 : totalRead;
                }

                _currentStream = next.getOctetStream();
            }
        }
    }

    public int read()
        throws IOException
    {
        if (_currentStream == null)
        {
            if (!_first)
            {
                return -1;
            }

            ASN1OctetStringParser next = getNextParser();
            if (next == null)
            {
                return -1;
            }

            _first = false;
            _currentStream = next.getOctetStream();
        }

        for (;;)
        {
            int b = _currentStream.read();

            if (b >= 0)
            {
                return b;
            }

            ASN1OctetStringParser next = getNextParser();
            if (next == null)
            {
                _currentStream = null;
                return -1;
            }

            _currentStream = next.getOctetStream();
        }
    }

    private ASN1OctetStringParser getNextParser() throws IOException
    {
        ASN1Encodable asn1Obj = _parser.readObject();
        if (asn1Obj == null)
        {
            return null;
        }

        if (asn1Obj instanceof ASN1OctetStringParser)
        {
            return (ASN1OctetStringParser)asn1Obj;
        }

        throw new IOException("unknown object encountered: " + asn1Obj.getClass());
    }
}
