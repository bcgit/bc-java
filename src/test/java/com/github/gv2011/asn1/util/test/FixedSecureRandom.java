package com.github.gv2011.asn1.util.test;

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


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

public class FixedSecureRandom
    extends SecureRandom
{
    private static final long serialVersionUID = -1677267764422600352L;

    private final byte[]       _data;

    private int          _index;
    private int          _intPad;

    public FixedSecureRandom(final byte[] value)
    {
        this(false, new byte[][] { value });
    }

    public FixedSecureRandom(
        final byte[][] values)
    {
        this(false, values);
    }

    /**
     * Pad the data on integer boundaries. This is necessary for the classpath project's BigInteger
     * implementation.
     */
    public FixedSecureRandom(
        final boolean intPad,
        final byte[] value)
    {
        this(intPad, new byte[][] { value });
    }

    /**
     * Pad the data on integer boundaries. This is necessary for the classpath project's BigInteger
     * implementation.
     */
    public FixedSecureRandom(
        final boolean intPad,
        final byte[][] values)
    {
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        for (int i = 0; i != values.length; i++)
        {
            try
            {
                bOut.write(values[i]);
            }
            catch (final IOException e)
            {
                throw new IllegalArgumentException("can't save value array.");
            }
        }

        _data = bOut.toByteArray();

        if (intPad)
        {
            _intPad = _data.length % 4;
        }
    }

    @Override
    public void nextBytes(final byte[] bytes)
    {
        System.arraycopy(_data, _index, bytes, 0, bytes.length);

        _index += bytes.length;
    }

    //
    // classpath's implementation of SecureRandom doesn't currently go back to nextBytes
    // when next is called. We can't override next as it's a final method.
    //
    @Override
    public int nextInt()
    {
        int val = 0;

        val |= nextValue() << 24;
        val |= nextValue() << 16;

        if (_intPad == 2)
        {
            _intPad--;
        }
        else
        {
            val |= nextValue() << 8;
        }

        if (_intPad == 1)
        {
            _intPad--;
        }
        else
        {
            val |= nextValue();
        }

        return val;
    }

    //
    // classpath's implementation of SecureRandom doesn't currently go back to nextBytes
    // when next is called. We can't override next as it's a final method.
    //
    @Override
    public long nextLong()
    {
        long val = 0;

        val |= (long)nextValue() << 56;
        val |= (long)nextValue() << 48;
        val |= (long)nextValue() << 40;
        val |= (long)nextValue() << 32;
        val |= (long)nextValue() << 24;
        val |= (long)nextValue() << 16;
        val |= (long)nextValue() << 8;
        val |= nextValue();

        return val;
    }

    public boolean isExhausted()
    {
        return _index == _data.length;
    }

    private int nextValue()
    {
        return _data[_index++] & 0xff;
    }
}
