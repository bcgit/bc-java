package com.github.gv2011.asn1;

import static com.github.gv2011.util.ex.Exceptions.call;

import java.io.InputStream;

class ConstructedOctetStream
    extends InputStream
{
    private final ASN1StreamParser _parser;

    private boolean                _first = true;
    private InputStream            _currentStream;

    ConstructedOctetStream(
        final ASN1StreamParser parser)
    {
        _parser = parser;
    }

    @Override
    public int read(final byte[] b, final int off, final int len)
    {
        if (_currentStream == null)
        {
            if (!_first)
            {
                return -1;
            }

            final ASN1OctetStringParser s = (ASN1OctetStringParser)_parser.readObject();

            if (s == null)
            {
                return -1;
            }

            _first = false;
            _currentStream = s.getOctetStream();
        }

        int totalRead = 0;

        for (;;)
        {
            final int tr = totalRead;
            final int numRead = call(()->_currentStream.read(b, off + tr, len - tr));

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
                final ASN1OctetStringParser aos = (ASN1OctetStringParser)_parser.readObject();

                if (aos == null)
                {
                    _currentStream = null;
                    return totalRead < 1 ? -1 : totalRead;
                }

                _currentStream = aos.getOctetStream();
            }
        }
    }

    @Override
    public int read()
    {
        if (_currentStream == null)
        {
            if (!_first)
            {
                return -1;
            }

            final ASN1OctetStringParser s = (ASN1OctetStringParser)_parser.readObject();

            if (s == null)
            {
                return -1;
            }

            _first = false;
            _currentStream = s.getOctetStream();
        }

        for (;;)
        {
            final int b = call(_currentStream::read);

            if (b >= 0)
            {
                return b;
            }

            final ASN1OctetStringParser s = (ASN1OctetStringParser)_parser.readObject();

            if (s == null)
            {
                _currentStream = null;
                return -1;
            }

            _currentStream = s.getOctetStream();
        }
    }
}
