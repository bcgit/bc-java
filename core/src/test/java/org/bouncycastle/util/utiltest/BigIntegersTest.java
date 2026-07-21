package org.bouncycastle.util.utiltest;

import java.math.BigInteger;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.IPAddress;
import org.bouncycastle.util.encoders.Hex;

public class BigIntegersTest
    extends TestCase
{
    public String getName()
    {
        return "BigIntegers";
    }

    public void testAsUnsignedByteArray()
    {
        BigInteger a = new BigInteger(1, Hex.decode("ff12345678"));

        byte[] a5 = BigIntegers.asUnsignedByteArray(a);

        Assert.assertEquals(5, a5.length);
        Assert.assertTrue(Arrays.areEqual(a5, Hex.decode("ff12345678")));

        BigInteger b = new BigInteger(1, Hex.decode("0f12345678"));

        byte[] b5 = BigIntegers.asUnsignedByteArray(b);

        Assert.assertEquals(5, b5.length);
        Assert.assertTrue(Arrays.areEqual(b5, Hex.decode("0f12345678")));
    }

    public void testFixedLengthUnsignedByteArray()
    {
        BigInteger a = new BigInteger(1, Hex.decode("ff12345678"));

        byte[] a5 = BigIntegers.asUnsignedByteArray(5, a);

        Assert.assertEquals(5, a5.length);
        Assert.assertTrue(Arrays.areEqual(a5, Hex.decode("ff12345678")));

        byte[] a6 = BigIntegers.asUnsignedByteArray(6, a);

        Assert.assertEquals(6, a6.length);
        Assert.assertEquals(0, a6[0]);
        Assert.assertTrue(Arrays.areEqual(a6, Hex.decode("00ff12345678")));

        BigInteger b = new BigInteger(1, Hex.decode("0f12345678"));

        byte[] b5 = BigIntegers.asUnsignedByteArray(5, b);

        Assert.assertEquals(5, b5.length);
        Assert.assertTrue(Arrays.areEqual(b5, Hex.decode("0f12345678")));

        byte[] b6 = BigIntegers.asUnsignedByteArray(6, b);

        Assert.assertEquals(6, b6.length);
        Assert.assertEquals(0, b6[0]);
        Assert.assertTrue(Arrays.areEqual(b6, Hex.decode("000f12345678")));

        BigInteger c = new BigInteger(1, Hex.decode("ff123456789a"));

        try
        {
            byte[] c5 = BigIntegers.asUnsignedByteArray(5, c);

            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            // ignore
        }

        BigInteger d = new BigInteger(1, Hex.decode("0f123456789a"));
        try
        {
            byte[] c5 = BigIntegers.asUnsignedByteArray(5, d);

            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            // ignore
        }
    }

    public void testByteValueExact()
    {
        Assert.assertEquals(Byte.MAX_VALUE, BigIntegers.byteValueExact(BigInteger.valueOf(Byte.MAX_VALUE)));
        Assert.assertEquals(Byte.MIN_VALUE, BigIntegers.byteValueExact(BigInteger.valueOf(Byte.MIN_VALUE)));
        Assert.assertEquals((byte)0, BigIntegers.byteValueExact(BigInteger.ZERO));

        expectByteValueError(BigInteger.valueOf(Byte.MAX_VALUE + 1));
        expectByteValueError(BigInteger.valueOf(Byte.MIN_VALUE - 1));
    }

    public void testShortValueExact()
    {
        Assert.assertEquals(Short.MAX_VALUE, BigIntegers.shortValueExact(BigInteger.valueOf(Short.MAX_VALUE)));
        Assert.assertEquals(Short.MIN_VALUE, BigIntegers.shortValueExact(BigInteger.valueOf(Short.MIN_VALUE)));
        Assert.assertEquals((short)0, BigIntegers.shortValueExact(BigInteger.ZERO));

        expectShortValueError(BigInteger.valueOf(Short.MAX_VALUE + 1));
        expectShortValueError(BigInteger.valueOf(Short.MIN_VALUE - 1));
    }

    public void testIntValueExact()
    {
        Assert.assertEquals(Integer.MAX_VALUE, BigIntegers.intValueExact(BigInteger.valueOf(Integer.MAX_VALUE)));
        Assert.assertEquals(Integer.MIN_VALUE, BigIntegers.intValueExact(BigInteger.valueOf(Integer.MIN_VALUE)));
        Assert.assertEquals(0, BigIntegers.intValueExact(BigInteger.ZERO));

        expectIntValueError(BigInteger.valueOf(Integer.MAX_VALUE + 1L));
        expectIntValueError(BigInteger.valueOf(Integer.MIN_VALUE - 1L));
    }

    public void testLongValueExact()
    {
        Assert.assertEquals(Long.MAX_VALUE, BigIntegers.longValueExact(BigInteger.valueOf(Long.MAX_VALUE)));
        Assert.assertEquals(Long.MIN_VALUE, BigIntegers.longValueExact(BigInteger.valueOf(Long.MIN_VALUE)));
        Assert.assertEquals(0L, BigIntegers.longValueExact(BigInteger.ZERO));

        expectLongValueError(BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE));
        expectLongValueError(BigInteger.valueOf(Long.MIN_VALUE).subtract(BigInteger.ONE));
    }

    private void expectByteValueError(BigInteger x)
    {
        try
        {
            BigIntegers.byteValueExact(x);

            fail("no exception thrown");
        }
        catch (ArithmeticException e)
        {
            // ignore
        }
    }

    private void expectShortValueError(BigInteger x)
    {
        try
        {
            BigIntegers.shortValueExact(x);

            fail("no exception thrown");
        }
        catch (ArithmeticException e)
        {
            // ignore
        }
    }

    private void expectIntValueError(BigInteger x)
    {
        try
        {
            BigIntegers.intValueExact(x);

            fail("no exception thrown");
        }
        catch (ArithmeticException e)
        {
            // ignore
        }
    }

    private void expectLongValueError(BigInteger x)
    {
        try
        {
            BigIntegers.longValueExact(x);

            fail("no exception thrown");
        }
        catch (ArithmeticException e)
        {
            // ignore
        }
    }
}
