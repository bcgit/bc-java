package org.bouncycastle.pqc.math.ntru.polynomial.test;

import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.LongPolynomial2;
import org.bouncycastle.util.Arrays;

public class LongPolynomial2Test
    extends TestCase
{
    public void testMult()
    {
        IntegerPolynomial i1 = new IntegerPolynomial(new int[]{1368, 2047, 672, 871, 1662, 1352, 1099, 1608});
        IntegerPolynomial i2 = new IntegerPolynomial(new int[]{1729, 1924, 806, 179, 1530, 1381, 1695, 60});
        LongPolynomial2 a = new LongPolynomial2(i1);
        LongPolynomial2 b = new LongPolynomial2(i2);
        IntegerPolynomial c1 = i1.mult(i2, 2048);
        IntegerPolynomial c2 = a.mult(b).toIntegerPolynomial();
        assertTrue(Arrays.areEqual(c1.coeffs, c2.coeffs));

        // test 10 random polynomials
        Random rng = new Random();
        for (int i = 0; i < 10; i++)
        {
            int N = 2 + rng.nextInt(2000);
            i1 = PolynomialGenerator.generateRandom(N, 2048);
            i2 = PolynomialGenerator.generateRandom(N, 2048);
            a = new LongPolynomial2(i1);
            b = new LongPolynomial2(i2);
            c1 = i1.mult(i2);
            c1.modPositive(2048);
            c2 = a.mult(b).toIntegerPolynomial();
            assertTrue(Arrays.areEqual(c1.coeffs, c2.coeffs));
        }
    }

    public void testSubAnd()
    {
        IntegerPolynomial i1 = new IntegerPolynomial(new int[]{1368, 2047, 672, 871, 1662, 1352, 1099, 1608});
        IntegerPolynomial i2 = new IntegerPolynomial(new int[]{1729, 1924, 806, 179, 1530, 1381, 1695, 60});
        LongPolynomial2 a = new LongPolynomial2(i1);
        LongPolynomial2 b = new LongPolynomial2(i2);
        a.subAnd(b, 2047);
        i1.sub(i2);
        i1.modPositive(2048);
        assertTrue(Arrays.areEqual(a.toIntegerPolynomial().coeffs, i1.coeffs));
    }

    public void testMult2And()
    {
        IntegerPolynomial i1 = new IntegerPolynomial(new int[]{1368, 2047, 672, 871, 1662, 1352, 1099, 1608});
        LongPolynomial2 i2 = new LongPolynomial2(i1);
        i2.mult2And(2047);
        i1.mult(2);
        i1.modPositive(2048);
        assertTrue(Arrays.areEqual(i1.coeffs, i2.toIntegerPolynomial().coeffs));
    }
}