package org.bouncycastle.asn1;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.io.Streams;

/**
 * Parse data stream of expected ASN.1 data expecting definite-length encoding..
 */
class DefiniteLengthInputStream
        extends LimitedInputStream
{
    private static final byte[] EMPTY_BYTES = new byte[0];

    private final int _originalLength;

    private int _remaining;

    DefiniteLengthInputStream(
        InputStream in,
        int         length,
        int         limit)
    {
        super(in, limit);

        if (length < 0)
        {
            throw new IllegalArgumentException("negative lengths not allowed");
        }

        this._originalLength = length;
        this._remaining = length;

        if (length == 0)
        {
            setParentEofDetect(true);
        }
    }

    int getRemaining()
    {
        return _remaining;
    }

    public int read()
        throws IOException
    {
        if (_remaining == 0)
        {
            return -1;
        }

        int b = _in.read();

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

    public int read(byte[] buf, int off, int len)
        throws IOException
    {
        if (_remaining == 0)
        {
            return -1;
        }

        int toRead = Math.min(len, _remaining);
        int numRead = _in.read(buf, off, toRead);

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

    void readAllIntoByteArray(byte[] buf)
        throws IOException
    {
        if (_remaining != buf.length)
        {
            throw new IllegalArgumentException("buffer length not right for data");
        }

        if (_remaining == 0)
        {
            return;
        }

        // make sure it's safe to do this!
        int limit = getLimit();
        if (_remaining >= limit)
        {
            throw new IOException("corrupted stream - out of bounds length found: " + _remaining + " >= " + limit);
        }

        if ((_remaining -= Streams.readFully(_in, buf)) != 0)
        {
            throw new EOFException("DEF length " + _originalLength + " object truncated by " + _remaining);
        }
        setParentEofDetect(true);
    }

    byte[] toByteArray()
        throws IOException
    {
        if (_remaining == 0)
        {
            return EMPTY_BYTES;
        }

        // make sure it's safe to do this!
        int limit = getLimit();
        if (_remaining >= limit)
        {
            throw new IOException("corrupted stream - out of bounds length found: " + _remaining + " >= " + limit);
        }

        byte[] bytes = new byte[_remaining];
        if ((_remaining -= Streams.readFully(_in, bytes)) != 0)
        {
            throw new EOFException("DEF length " + _originalLength + " object truncated by " + _remaining);
        }
        setParentEofDetect(true);
        return bytes;
    }
}
