package com.github.gv2011.asn1;

import static com.github.gv2011.util.bytes.ByteUtils.emptyBytes;
import static com.github.gv2011.util.bytes.ByteUtils.newBytes;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import com.github.gv2011.asn1.util.io.Streams;
import com.github.gv2011.util.bytes.Bytes;

class DefiniteLengthInputStream
        extends LimitedInputStream
{
    private static final Bytes EMPTY_BYTES = emptyBytes();

    private final int _originalLength;
    private int _remaining;

    DefiniteLengthInputStream(
        final InputStream in,
        final int         length)
    {
        super(in, length);

        if (length < 0)
        {
            throw new IllegalArgumentException("negative lengths not allowed");
        }

        _originalLength = length;
        _remaining = length;

        if (length == 0)
        {
            setParentEofDetect(true);
        }
    }

    @Override
    int getRemaining()
    {
        return _remaining;
    }

    @Override
    public int read()
        throws IOException
    {
        if (_remaining == 0)
        {
            return -1;
        }

        final int b = _in.read();

        if (b < 0)
        {
            throw new EOFException("DEF length " + _originalLength + " object truncated by " + _remaining);
        }

        if (--_remaining == 0)
        {
            setParentEofDetect(true);
        }

        return b;
    }

    @Override
    public int read(final byte[] buf, final int off, final int len)
        throws IOException
    {
        if (_remaining == 0)
        {
            return -1;
        }

        final int toRead = Math.min(len, _remaining);
        final int numRead = _in.read(buf, off, toRead);

        if (numRead < 0)
        {
            throw new EOFException("DEF length " + _originalLength + " object truncated by " + _remaining);
        }

        if ((_remaining -= numRead) == 0)
        {
            setParentEofDetect(true);
        }

        return numRead;
    }

    Bytes toByteArray(){
        if (_remaining == 0)
        {
            return EMPTY_BYTES;
        }

        final byte[] bytes = new byte[_remaining];
        if ((_remaining -= Streams.readFully(_in, bytes)) != 0)
        {
            throw new ASN1ParsingException("DEF length " + _originalLength + " object truncated by " + _remaining);
        }
        setParentEofDetect(true);
        return newBytes(bytes);
    }
}
