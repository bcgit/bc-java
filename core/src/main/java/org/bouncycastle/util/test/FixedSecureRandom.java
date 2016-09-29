package org.bouncycastle.util.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.SecureRandom;

import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

/**
 * A secure random that returns pre-seeded data to calls of nextBytes() or generateSeed().
 */
public class FixedSecureRandom
    extends SecureRandom
{
    private static java.math.BigInteger REGULAR = new java.math.BigInteger("01020304ffffffff0506070811111111", 16);
    private static java.math.BigInteger ANDROID = new java.math.BigInteger("1111111105060708ffffffff01020304", 16);
    private static java.math.BigInteger CLASSPATH = new java.math.BigInteger("3020104ffffffff05060708111111", 16);

    private static final boolean isAndroidStyle;
    private static final boolean isClasspathStyle;
    private static final boolean isRegularStyle;

    static
    {
        java.math.BigInteger check1 = new java.math.BigInteger(128, new RandomChecker());
        java.math.BigInteger check2 = new java.math.BigInteger(120, new RandomChecker());

        isAndroidStyle = check1.equals(ANDROID);
        isRegularStyle = check1.equals(REGULAR);
        isClasspathStyle = check2.equals(CLASSPATH);
    }

    private byte[]       _data;
    private int          _index;

    /**
     * Base class for sources of fixed "Randomness"
     */
    public static class Source
    {
        byte[] data;

        Source(byte[] data)
        {
            this.data = data;
        }
    }

    /**
     * Data Source - in this case we just expect requests for byte arrays.
     */
    public static class Data
        extends Source
    {
        public Data(byte[] data)
        {
            super(data);
        }
    }

    /**
     * BigInteger Source - in this case we expect requests for data that will be used
     * for BigIntegers. The FixedSecureRandom will attempt to compensate for platform differences here.
     */
    public static class BigInteger
        extends Source
    {
        public BigInteger(byte[] data)
        {
            super(data);
        }

        public BigInteger(int bitLength, byte[] data)
        {
            super(expandToBitLength(bitLength, data));
        }

        public BigInteger(String hexData)
        {
            this(Hex.decode(hexData));
        }

        public BigInteger(int bitLength, String hexData)
        {
            super(expandToBitLength(bitLength, Hex.decode(hexData)));
        }
    }

    public FixedSecureRandom(byte[] value)
    {
        this(new Source[] { new Data(value) });
    }

    public FixedSecureRandom(
        byte[][] values)
    {
        this(buildDataArray(values));
    }

    private static Data[] buildDataArray(byte[][] values)
    {
        Data[] res = new Data[values.length];

        for (int i = 0; i != values.length; i++)
        {
            res[i] = new Data(values[i]);
        }

        return res;
    }

    public FixedSecureRandom(
        Source[] sources)
    {
        super(null, new DummyProvider());   // to prevent recursion in provider creation

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        if (isRegularStyle)
        {
            if (isClasspathStyle)
            {
                for (int i = 0; i != sources.length; i++)
                {
                    try
                    {
                        if (sources[i] instanceof BigInteger)
                        {
                            byte[] data = sources[i].data;
                            int len = data.length - (data.length % 4);
                            for (int w = data.length - len - 1; w >= 0; w--)
                            {
                                bOut.write(data[w]);
                            }
                            for (int w = data.length - len; w < data.length; w += 4)
                            {
                                bOut.write(data, w, 4);
                            }
                        }
                        else
                        {
                            bOut.write(sources[i].data);
                        }
                    }
                    catch (IOException e)
                    {
                        throw new IllegalArgumentException("can't save value source.");
                    }
                }
            }
            else
            {
                for (int i = 0; i != sources.length; i++)
                {
                    try
                    {
                        bOut.write(sources[i].data);
                    }
                    catch (IOException e)
                    {
                        throw new IllegalArgumentException("can't save value source.");
                    }
                }
            }
        }
        else if (isAndroidStyle)
        {
            for (int i = 0; i != sources.length; i++)
            {
                try
                {
                    if (sources[i] instanceof BigInteger)
                    {
                        byte[] data = sources[i].data;
                        int len = data.length - (data.length % 4);
                        for (int w = 0; w < len; w += 4)
                        {
                            bOut.write(data, data.length - (w + 4), 4);
                        }
                        if (data.length - len != 0)
                        {
                            for (int w = 0; w != 4 - (data.length - len); w++)
                            {
                                bOut.write(0);
                            }
                        }
                        for (int w = 0; w != data.length - len; w++)
                        {
                            bOut.write(data[len + w]);
                        }
                    }
                    else
                    {
                        bOut.write(sources[i].data);
                    }
                }
                catch (IOException e)
                {
                    throw new IllegalArgumentException("can't save value source.");
                }
            }
        }
        else
        {
            throw new IllegalStateException("Unrecognized BigInteger implementation");
        }

        _data = bOut.toByteArray();
    }

    public void nextBytes(byte[] bytes)
    {
        System.arraycopy(_data, _index, bytes, 0, bytes.length);

        _index += bytes.length;
    }

    public byte[] generateSeed(int numBytes)
    {
        byte[] bytes = new byte[numBytes];

        this.nextBytes(bytes);

        return bytes;
    }

    //
    // classpath's implementation of SecureRandom doesn't currently go back to nextBytes
    // when next is called. We can't override next as it's a final method.
    //
    public int nextInt()
    {
        int val = 0;
        
        val |= nextValue() << 24;
        val |= nextValue() << 16;
        val |= nextValue() << 8;
        val |= nextValue();

        return val;
    }
    
    //
    // classpath's implementation of SecureRandom doesn't currently go back to nextBytes
    // when next is called. We can't override next as it's a final method.
    //
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
        val |= (long)nextValue();
        
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

    private static class RandomChecker
        extends SecureRandom
    {
        RandomChecker()
        {
            super(null, new DummyProvider());       // to prevent recursion in provider creation
        }

        byte[] data = Hex.decode("01020304ffffffff0506070811111111");
        int    index = 0;

        public void nextBytes(byte[] bytes)
        {
            System.arraycopy(data, index, bytes, 0, bytes.length);

            index += bytes.length;
        }
    }

    private static byte[] expandToBitLength(int bitLength, byte[] v)
    {
        if ((bitLength + 7) / 8 > v.length)
        {
            byte[] tmp = new byte[(bitLength + 7) / 8];

            System.arraycopy(v, 0, tmp, tmp.length - v.length, v.length);
            if (isAndroidStyle)
            {
                if (bitLength % 8 != 0)
                {
                    int i = Pack.bigEndianToInt(tmp, 0);
                    Pack.intToBigEndian(i << (8 - (bitLength % 8)), tmp, 0);
                }
            }

            return tmp;
        }
        else
        {
            if (isAndroidStyle && bitLength < (v.length * 8))
            {
                if (bitLength % 8 != 0)
                {
                    int i = Pack.bigEndianToInt(v, 0);
                    Pack.intToBigEndian(i << (8 - (bitLength % 8)), v, 0);
                }
            }
        }

        return v;
    }

    private static class DummyProvider
        extends Provider
    {
        DummyProvider()
        {
            super("BCFIPS_FIXED_RNG", 1.0, "BCFIPS Fixed Secure Random Provider");
        }
    }
}
