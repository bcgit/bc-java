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
