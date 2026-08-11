package org.bouncycastle.util.utiltest;

import java.math.BigInteger;
import java.security.SecureRandom;

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

    public void testModAdd()
    {
        BigInteger[] moduli = new BigInteger[]
        {
            // q of the RFC 6509 SAKKE parameter set: 1022 bits, so a sum of two values below it
            // can pass the bit length of the modulus without carrying out of its top word
            new BigInteger(
                "265EAEC7C2958FF69971846636B4195E905B0338672D20986FA6B8D62CF8068B" +
                "BD02AAC9F8BF03C6C8A1CC354C69672C39E46CE7FDF222864D5B49FD2999A9B4" +
                "389B1921CC9AD335144AB173595A07386DABFD2A0C614AA0A9F3CF14870F026A" +
                "A7E535ABD5A5C7C7FF38FA08E2615F6C203177C42B1EB3A1D99B601EBFAA17FB", 16),
            // SM9's N, whose bit length is exactly 256, so the sum does carry out of the top word
            new BigInteger("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D", 16),
            BigInteger.ONE,
            BigInteger.valueOf(3),
            BigInteger.valueOf(4),
            BigInteger.ONE.shiftLeft(32),
            BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(31).add(BigInteger.ONE)
        };

        SecureRandom random = new SecureRandom();

        for (int i = 0; i != moduli.length; i++)
        {
            BigInteger m = moduli[i];
            BigInteger last = m.subtract(BigInteger.ONE);

            checkModAdd(m, BigInteger.ZERO, BigInteger.ZERO);
            checkModAdd(m, BigInteger.ZERO, last);
            checkModAdd(m, last, BigInteger.ZERO);
            checkModAdd(m, last, last);
            checkModAdd(m, last.shiftRight(1), last);

            if (m.compareTo(BigInteger.valueOf(2)) > 0)
            {
                // the sum is exactly m, the one case the conditional subtraction has to take
                checkModAdd(m, BigInteger.ONE, last);
                checkModAdd(m, last, BigInteger.ONE);
            }

            for (int j = 0; j != 200; j++)
            {
                checkModAdd(m, new BigInteger(m.bitLength() + 8, random).mod(m),
                    new BigInteger(m.bitLength() + 8, random).mod(m));
            }
        }

        // an operand outside [0, M) is rejected rather than reduced: reducing it is the
        // variable-time step modAdd exists to avoid, so it cannot quietly do it for the caller
        BigInteger q = moduli[0];
        expectModAddError(q, q, BigInteger.ONE);
        expectModAddError(q, BigInteger.ONE, q);
        expectModAddError(q, BigInteger.ONE.negate(), BigInteger.ONE);
        expectModAddError(q, BigInteger.ONE, BigInteger.ONE.negate());

        try
        {
            BigIntegers.modAdd(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO);

            fail("no exception thrown");
        }
        catch (ArithmeticException e)
        {
            // ignore
        }
    }

    private void checkModAdd(BigInteger m, BigInteger x, BigInteger y)
    {
        BigInteger z = BigIntegers.modAdd(m, x, y);

        Assert.assertEquals("m=" + m.toString(16) + " x=" + x.toString(16) + " y=" + y.toString(16),
            x.add(y).mod(m), z);
        Assert.assertTrue("not reduced: " + z.toString(16), z.signum() >= 0 && z.compareTo(m) < 0);
    }

    public void testModMult()
    {
        BigInteger[] moduli = new BigInteger[]
        {
            // SM9's N and P-256's order, both exactly 256 bits, so the accumulator's top word is
            // in play; and the 1022-bit SAKKE q, which leaves it slack
            new BigInteger("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D", 16),
            new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
            new BigInteger(
                "265EAEC7C2958FF69971846636B4195E905B0338672D20986FA6B8D62CF8068B" +
                "BD02AAC9F8BF03C6C8A1CC354C69672C39E46CE7FDF222864D5B49FD2999A9B4" +
                "389B1921CC9AD335144AB173595A07386DABFD2A0C614AA0A9F3CF14870F026A" +
                "A7E535ABD5A5C7C7FF38FA08E2615F6C203177C42B1EB3A1D99B601EBFAA17FB", 16),
            BigInteger.ONE,
            BigInteger.valueOf(3),
            BigInteger.valueOf(5),
            BigInteger.valueOf(0xFFFFFFFFL),
            BigInteger.ONE.shiftLeft(32).add(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE),
            BigInteger.ONE.shiftLeft(127).subtract(BigInteger.ONE)
        };

        SecureRandom random = new SecureRandom();

        for (int i = 0; i != moduli.length; i++)
        {
            BigInteger m = moduli[i];
            BigInteger last = m.subtract(BigInteger.ONE);

            checkModMult(m, BigInteger.ZERO, BigInteger.ZERO);
            checkModMult(m, BigInteger.ZERO, last);
            checkModMult(m, last, BigInteger.ZERO);
            checkModMult(m, last, last);

            if (m.compareTo(BigInteger.ONE) > 0)
            {
                checkModMult(m, BigInteger.ONE, last);
                checkModMult(m, last, BigInteger.ONE);
                checkModMult(m, last.shiftRight(1), last.shiftRight(1));
            }

            for (int j = 0; j != 200; j++)
            {
                BigInteger x = new BigInteger(m.bitLength() + 8, random).mod(m);
                BigInteger y = new BigInteger(m.bitLength() + 8, random).mod(m);

                checkModMult(m, x, y);

                // x * x^-1 is 1, which pins the Montgomery factor rather than just the product.
                // Some of the moduli above are composite, so check x is a unit before inverting it.
                if (x.signum() != 0 && m.compareTo(BigInteger.ONE) > 0 && x.gcd(m).equals(BigInteger.ONE))
                {
                    Assert.assertEquals("m=" + m.toString(16) + " x=" + x.toString(16),
                        BigInteger.ONE, BigIntegers.modMult(m, x, BigIntegers.modOddInverse(m, x)));
                }
            }
        }

        BigInteger q = moduli[1];
        expectModMultError(q, q, BigInteger.ONE);
        expectModMultError(q, BigInteger.ONE, q);
        expectModMultError(q, BigInteger.ONE.negate(), BigInteger.ONE);
        expectModMultError(q, BigInteger.ONE, BigInteger.ONE.negate());

        // Montgomery form needs R coprime to the modulus, so an even one has no representation
        expectModMultError(BigInteger.valueOf(4), BigInteger.ONE, BigInteger.ONE);
    }

    private void checkModMult(BigInteger m, BigInteger x, BigInteger y)
    {
        BigInteger z = BigIntegers.modMult(m, x, y);

        Assert.assertEquals("m=" + m.toString(16) + " x=" + x.toString(16) + " y=" + y.toString(16),
            x.multiply(y).mod(m), z);
        Assert.assertTrue("not reduced: " + z.toString(16), z.signum() >= 0 && z.compareTo(m) < 0);
    }

    private void expectModMultError(BigInteger m, BigInteger x, BigInteger y)
    {
        try
        {
            BigIntegers.modMult(m, x, y);

            fail("no exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            // ignore
        }
    }

    private void expectModAddError(BigInteger m, BigInteger x, BigInteger y)
    {
        try
        {
            BigIntegers.modAdd(m, x, y);

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
