package com.github.gv2011.asn1;

import static com.github.gv2011.util.ex.Exceptions.call;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

class IndefiniteLengthInputStream
    extends LimitedInputStream
{
    private int _b1;
    private int _b2;
    private boolean _eofReached = false;
    private boolean _eofOn00 = true;

    IndefiniteLengthInputStream(
        final InputStream in,
        final int         limit) {
        super(in, limit);

        _b1 = call(in::read);
        _b2 = call(in::read);

        if (_b2 < 0)
        {
            // Corrupted stream
            throw new ASN1Exception();
        }

        checkForEof();
    }

    void setEofOn00(
        final boolean eofOn00)
    {
        _eofOn00 = eofOn00;
        checkForEof();
    }

    private boolean checkForEof()
    {
        if (!_eofReached && _eofOn00 && (_b1 == 0x00 && _b2 == 0x00))
        {
            _eofReached = true;
            setParentEofDetect(true);
        }
        return _eofReached;
    }

    @Override
    public int read(final byte[] b, final int off, final int len)
        throws IOException
    {
        // Only use this optimisation if we aren't checking for 00
        if (_eofOn00 || len < 3)
        {
            return super.read(b, off, len);
        }

        if (_eofReached)
        {
            return -1;
        }

        final int numRead = _in.read(b, off + 2, len - 2);

        if (numRead < 0)
        {
            // Corrupted stream
            throw new EOFException();
        }

        b[off] = (byte)_b1;
        b[off + 1] = (byte)_b2;

        _b1 = _in.read();
        _b2 = _in.read();

        if (_b2 < 0)
        {
            // Corrupted stream
            throw new EOFException();
        }

        return numRead + 2;
    }

    @Override
    public int read()
        throws IOException
    {
        if (checkForEof())
        {
            return -1;
        }

        final int b = _in.read();

        if (b < 0)
        {
            // Corrupted stream
            throw new EOFException();
        }

        final int v = _b1;

        _b1 = _b2;
        _b2 = b;

        return v;
    }
}
