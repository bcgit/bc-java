package org.bouncycastle.crypto.bls;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;

/**
 * The package-private {@link Fp} against {@link BigInteger} arithmetic mod p. Random values reach
 * most of it, but not the corners the bounds in its javadoc are about: wide values at the edge of
 * the 2^768 range {@link Fp#reduceWide} accepts, and multiples of p, the values for which its
 * quotient estimate falls one short and the second of its two candidates is kept.
 */
public class FpTest
    extends TestCase
{
    private static final BigInteger P = Fp.Q;
    private static final BigInteger R = BigInteger.ONE.shiftLeft(384);
    private static final BigInteger R_INV = R.modInverse(P);
    private static final BigInteger WIDE_LIMIT = BigInteger.ONE.shiftLeft(768);

    private static final BigInteger[] EDGE = {
        BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(2), P.subtract(BigInteger.ONE),
        P.subtract(BigInteger.valueOf(2)), P.shiftRight(1), P.shiftRight(1).add(BigInteger.ONE),
        BigInteger.ONE.shiftLeft(380), R.mod(P), R.mod(P).subtract(BigInteger.ONE) };

    private final SecureRandom random = new SecureRandom();

    public void testFieldOperations()
    {
        for (int i = 0; i < EDGE.length; ++i)
        {
            for (int j = 0; j < EDGE.length; ++j)
            {
                checkFieldOperations(EDGE[i], EDGE[j]);
            }
        }
        for (int i = 0; i < 2000; ++i)
        {
            checkFieldOperations(randomElement(), randomElement());
        }
    }

    private void checkFieldOperations(BigInteger x, BigInteger y)
    {
        int[] xe = element(x), ye = element(y);
        assertEquals(x, Fp.toBigInteger(xe, 0));
        assertEquals(mont(x), limbs(xe));

        int[] z = new int[Fp.SIZE];
        Fp.mul(xe, 0, ye, 0, z, 0);
        checkElement(x.multiply(y).mod(P), z);
        Fp.sqr(xe, 0, z, 0);
        checkElement(x.multiply(x).mod(P), z);
        Fp.add(xe, 0, ye, 0, z, 0);
        checkElement(x.add(y).mod(P), z);
        Fp.sub(xe, 0, ye, 0, z, 0);
        checkElement(x.subtract(y).mod(P), z);
        Fp.neg(xe, 0, z, 0);
        checkElement(x.negate().mod(P), z);
        assertEquals(x.signum() == 0, Fp.isZero(xe, 0));
        assertEquals(x.equals(y), Fp.eq(xe, 0, ye, 0));

        // in place
        int[] t = (int[])xe.clone();
        Fp.mul(t, 0, ye, 0, t, 0);
        checkElement(x.multiply(y).mod(P), t);

        int[] zz = new int[Fp.WIDE];
        Fp.mulWide(xe, 0, ye, 0, zz, 0);
        assertEquals(mont(x).multiply(mont(y)), wideValue(zz));
        Fp.reduceWide(zz, 0, z, 0);
        checkElement(x.multiply(y).mod(P), z);
        Fp.sqrWide(xe, 0, zz, 0);
        assertEquals(mont(x).multiply(mont(x)), wideValue(zz));
    }

    /**
     * isZero and eq look at every limb: forms that differ in one limb only, which random values
     * practically never are.
     */
    public void testEveryLimbCounts()
    {
        int[] zero = new int[Fp.SIZE];
        for (int i = 0; i < Fp.SIZE; ++i)
        {
            int[] e = new int[Fp.SIZE];
            e[i] = 1;
            assertFalse("limb " + i, Fp.isZero(e, 0));
            assertFalse("limb " + i, Fp.eq(e, 0, zero, 0));
            assertFalse("limb " + i, Fp.eq(zero, 0, e, 0));
            for (int j = 0; j < i; ++j)
            {
                int[] f = new int[Fp.SIZE];
                f[j] = 1;
                assertFalse("limbs " + i + ", " + j, Fp.eq(e, 0, f, 0));
            }
        }
    }

    public void testWideArithmetic()
    {
        for (int i = 0; i < 2000; ++i)
        {
            BigInteger a = randomWide(766), b = randomWide(766), c = randomWide(766);
            int[] zz = new int[Fp.WIDE];
            Fp.addWide(wide(a), 0, wide(b), 0, zz, 0);
            assertEquals(a.add(b), wideValue(zz));
            Fp.subWide(wide(a), 0, wide(b), 0, zz, 0);
            assertEquals(a.subtract(b), wideValue(zz));
            Fp.subWide2(wide(a), 0, wide(b), 0, wide(c), 0, zz, 0);
            assertEquals(a.subtract(b).subtract(c), wideValue(zz));
        }
    }

    public void testReduceWide()
    {
        BigInteger max = WIDE_LIMIT.subtract(BigInteger.ONE);
        BigInteger[] corners = { BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE.negate(), max, max.negate(),
            WIDE_LIMIT.negate(), R, R.negate(), R.subtract(BigInteger.ONE), P.multiply(P), P.multiply(R) };
        for (int i = 0; i < corners.length; ++i)
        {
            checkReduceWide(corners[i]);
        }
        for (int i = 0; i < 2000; ++i)
        {
            checkReduceWide(randomWide(768));
            checkReduceWide(randomWide(1 + random.nextInt(768)));
            // a multiple of p, whose quotient the estimate underestimates
            BigInteger multiple = P.multiply(new BigInteger(1 + random.nextInt(386), random));
            checkReduceWide(random.nextBoolean() ? multiple : multiple.negate());
        }
    }

    private void checkReduceWide(BigInteger xx)
    {
        int[] z = new int[Fp.SIZE];
        Fp.reduceWide(wide(xx), 0, z, 0);
        checkElement(xx.multiply(R_INV).multiply(R_INV).mod(P), z);
    }

    public void testReduceWideBound()
    {
        BigInteger[] outside = { WIDE_LIMIT, WIDE_LIMIT.negate().subtract(BigInteger.ONE), WIDE_LIMIT.shiftLeft(5) };
        for (int i = 0; i < outside.length; ++i)
        {
            try
            {
                Fp.reduceWide(wide(outside[i]), 0, new int[Fp.SIZE], 0);
                fail("wide value " + outside[i].toString(16) + " accepted");
            }
            catch (IllegalStateException e)
            {
                assertEquals("wide value out of range", e.getMessage());
            }
        }
    }

    public void testInverse()
    {
        for (int i = 0; i < 200; ++i)
        {
            BigInteger x = i < EDGE.length ? EDGE[i] : randomElement();
            if (x.signum() == 0)
            {
                continue;
            }
            int[] z = new int[Fp.SIZE];
            Fp.inv(element(x), 0, z, 0);
            checkElement(x.modInverse(P), z);
        }
        try
        {
            Fp.inv(new int[Fp.SIZE], 0, new int[Fp.SIZE], 0);
            fail("0 inverted");
        }
        catch (ArithmeticException e)
        {
            // expected
        }
    }

    public void testEncoding()
    {
        byte[] buf = new byte[48];
        int[] z = new int[Fp.SIZE];
        for (int i = 0; i < 200; ++i)
        {
            BigInteger x = i < EDGE.length ? EDGE[i] : randomElement();
            Fp.encode(element(x), 0, buf, 0);
            assertEquals(x, new BigInteger(1, buf));
            assertTrue(Fp.decode(buf, 0, z, 0));
            checkElement(x, z);
        }
        assertFalse(Fp.decode(bytes(P), 0, z, 0));
        assertFalse(Fp.decode(bytes(R.subtract(BigInteger.ONE)), 0, z, 0));
        assertTrue(Fp.decode(bytes(P.subtract(BigInteger.ONE)), 0, z, 0));

        // fromBigInteger reduces its argument
        Fp.fromBigInteger(P.add(BigInteger.valueOf(5)), z, 0);
        checkElement(BigInteger.valueOf(5), z);
        Fp.fromBigInteger(BigInteger.valueOf(-5), z, 0);
        checkElement(P.subtract(BigInteger.valueOf(5)), z);
    }

    // z holds the element v: its form is v R mod p, fully reduced
    private static void checkElement(BigInteger v, int[] z)
    {
        assertEquals(mont(v), limbs(z));
    }

    private BigInteger randomElement()
    {
        return new BigInteger(381, random).mod(P);
    }

    private BigInteger randomWide(int bits)
    {
        BigInteger v = new BigInteger(bits, random);
        return random.nextBoolean() ? v : v.negate();
    }

    private static BigInteger mont(BigInteger v)
    {
        return v.multiply(R).mod(P);
    }

    private static int[] element(BigInteger v)
    {
        int[] z = new int[Fp.SIZE];
        Fp.fromBigInteger(v, z, 0);
        return z;
    }

    private static BigInteger limbs(int[] x)
    {
        BigInteger r = BigInteger.ZERO;
        for (int i = Fp.SIZE - 1; i >= 0; --i)
        {
            r = r.shiftLeft(32).add(BigInteger.valueOf(x[i] & 0xFFFFFFFFL));
        }
        return r;
    }

    // a wide value from an integer: its two's complement in twenty-five limbs
    private static int[] wide(BigInteger v)
    {
        int[] zz = new int[Fp.WIDE];
        for (int i = 0; i < Fp.WIDE; ++i)
        {
            zz[i] = v.shiftRight(32 * i).intValue();
        }
        return zz;
    }

    private static BigInteger wideValue(int[] zz)
    {
        BigInteger r = BigInteger.valueOf(zz[Fp.WIDE - 1]);
        for (int i = Fp.WIDE - 2; i >= 0; --i)
        {
            r = r.shiftLeft(32).add(BigInteger.valueOf(zz[i] & 0xFFFFFFFFL));
        }
        return r;
    }

    private static byte[] bytes(BigInteger v)
    {
        byte[] b = new byte[48];
        byte[] e = v.toByteArray();
        int n = Math.min(e.length, 48);
        System.arraycopy(e, e.length - n, b, 48 - n, n);
        return b;
    }
}
