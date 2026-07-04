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

    private final long _originalLength;

    private long _remaining;

    DefiniteLengthInputStream(
        InputStream in,
        long        length,
        int         limit)
    {
        super(in, limit);

        if (length <= 0)
        {
            if (length < 0)
            {
                throw new IllegalArgumentException("negative lengths not allowed");
            }

            setParentEofDetect(true);
        }

        this._originalLength = length;
        this._remaining = length;
    }

    /**
     * Only valid on the materialization path, where lengths are bounded by
     * what a Java array can hold; the streaming path uses
     * {@link #getLongRemaining()}.
     */
    int getRemaining()
    {
        if (_remaining > Integer.MAX_VALUE)
        {
            throw new IllegalStateException("definite-length too large for int: " + _remaining);
        }
        return (int)_remaining;
    }

    long getLongRemaining()
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

        int toRead = (int)Math.min(len, _remaining);
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
        if (_remaining == 0)
        {
            return;
        }

        StreamUtil.checkLength(_remaining, (long)getLimit());

        if (_remaining > buf.length)
        {
            throw new IllegalArgumentException("buffer length insufficient for data");
        }
        if ((_remaining -= Streams.readFully(_in, buf, 0, (int)_remaining)) != 0)
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

        StreamUtil.checkLength(_remaining, (long)getLimit());

        // Read through this stream (not _in) so Streams.readLenBytesFully grows the buffer as bytes
        // arrive - avoiding the eager new byte[_remaining] that let a short crafted header drive a
        // heap-sized allocation before any data was read (CWE-789) - while read(byte[], int, int)
        // above keeps the _remaining / parent-EOF bookkeeping and reports a truncated stream with the
        // established "DEF length ... object truncated by ..." EOFException.
        return Streams.readLenBytesFully(this, (int)_remaining);
    }
}
