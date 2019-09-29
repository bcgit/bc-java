package org.bouncycastle.asn1;

import java.io.InputStream;

/**
 * Internal use stream that allows reading of a limited number of bytes from a wrapped stream.
 */
abstract class LimitedInputStream
        extends InputStream
{
    protected final InputStream _in;
    private int _limit;
    private int _length;

    LimitedInputStream(
        InputStream in,
        int         limit,
        int         length)
    {
        this._in = in;
        this._limit = limit;
        this._length = length;
    }

    int getLimit()
    {
        return _limit;
    }

    int getRemaining()
    {
        // TODO: maybe one day this can become more accurate
        return _length;
    }
    
    protected void setParentEofDetect(boolean on)
    {
        if (_in instanceof IndefiniteLengthInputStream)
        {
            ((IndefiniteLengthInputStream)_in).setEofOn00(on);
        }
    }
}
