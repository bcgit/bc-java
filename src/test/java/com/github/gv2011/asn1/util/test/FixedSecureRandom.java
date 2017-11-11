package com.github.gv2011.asn1.util.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

public class FixedSecureRandom extends SecureRandom{
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
