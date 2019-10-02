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

            ASN1Encodable asn1Obj = _parser.readObject();
            if (asn1Obj == null)
            {
                return -1;
            }

            if (!(asn1Obj instanceof ASN1OctetStringParser))
            {
                throw new IOException("unknown object encountered: " + asn1Obj.getClass());
            }

            ASN1OctetStringParser s = (ASN1OctetStringParser)asn1Obj;

            _first = false;
            _currentStream = s.getOctetStream();
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
                ASN1Encodable asn1Obj = _parser.readObject();

                if (asn1Obj == null)
                {
                    _currentStream = null;
                    return totalRead < 1 ? -1 : totalRead;
                }

                if (!(asn1Obj instanceof ASN1OctetStringParser))
                {
                    throw new IOException("unknown object encountered: " + asn1Obj.getClass());
                }

                ASN1OctetStringParser aos = (ASN1OctetStringParser)asn1Obj;

                _currentStream = aos.getOctetStream();
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

            ASN1Encodable asn1Obj = _parser.readObject();
    
            if (asn1Obj == null)
            {
                return -1;
            }

            if (!(asn1Obj instanceof ASN1OctetStringParser))
            {
                throw new IOException("unknown object encountered: " + asn1Obj.getClass());
            }

            ASN1OctetStringParser s = (ASN1OctetStringParser)asn1Obj;

            _first = false;
            _currentStream = s.getOctetStream();
        }

        for (;;)
        {
            int b = _currentStream.read();

            if (b >= 0)
            {
                return b;
            }

            ASN1Encodable asn1Obj = _parser.readObject();

            if (asn1Obj == null)
            {
                _currentStream = null;
                return -1;
            }

            if (!(asn1Obj instanceof ASN1OctetStringParser))
            {
                throw new IOException("unknown object encountered: " + asn1Obj.getClass());
            }

            ASN1OctetStringParser s = (ASN1OctetStringParser)asn1Obj;

            _currentStream = s.getOctetStream();
        }
    }
}
