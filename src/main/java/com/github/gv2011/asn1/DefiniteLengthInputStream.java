package com.github.gv2011.asn1;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


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
