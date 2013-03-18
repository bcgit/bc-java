package org.bouncycastle.pqc.math.ntru.polynomial.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.LongPolynomial5;
import org.bouncycastle.util.Arrays;

public class LongPolynomial5Test
    extends TestCase
{
    public void testMult()
    {
        testMult(new int[]{2}, new int[]{-1});
        testMult(new int[]{2, 0}, new int[]{-1, 0});
        testMult(new int[]{2, 0, 3}, new int[]{-1, 0, 1});
        testMult(new int[]{2, 0, 3, 1}, new int[]{-1, 0, 1, 1});
        testMult(new int[]{2, 0, 3, 1, 2}, new int[]{-1, 0, 1, 1, 0});
        testMult(new int[]{2, 0, 3, 1, 1, 5}, new int[]{1, -1, 1, 1, 0, 1});
        testMult(new int[]{2, 0, 3, 1, 1, 5, 1, 4}, new int[]{1, 0, 1, 1, -1, 1, 0, -1});
        testMult(new int[]{1368, 2047, 672, 871, 1662, 1352, 1099, 1608}, new int[]{1, 0, 1, 1, -1, 1, 0, -1});

        // test random polynomials
        SecureRandom rng = new SecureRandom();
        for (int i = 0; i < 10; i++)
        {
            int[] coeffs1 = new int[rng.nextInt(2000) + 1];
            int[] coeffs2 = DenseTernaryPolynomial.generateRandom(coeffs1.length, rng).coeffs;
            testMult(coeffs1, coeffs2);
        }
    }

    private void testMult(int[] coeffs1, int[] coeffs2)
    {
        IntegerPolynomial i1 = new IntegerPolynomial(coeffs1);
        IntegerPolynomial i2 = new IntegerPolynomial(coeffs2);

        LongPolynomial5 a = new LongPolynomial5(i1);
        DenseTernaryPolynomial b = new DenseTernaryPolynomial(i2);
        IntegerPolynomial c1 = i1.mult(i2, 2048);
        IntegerPolynomial c2 = a.mult(b).toIntegerPolynomial();
        assertEqualsMod(c1.coeffs, c2.coeffs, 2048);
    }

    private void assertEqualsMod(int[] arr1, int[] arr2, int m)
    {
        assertEquals(arr1.length, arr2.length);
        for (int i = 0; i < arr1.length; i++)
        {
            assertEquals((arr1[i] + m) % m, (arr2[i] + m) % m);
        }
    }

    public void testToIntegerPolynomial()
    {
        int[] coeffs = new int[]{2, 0, 3, 1, 1, 5, 1, 4};
        LongPolynomial5 p = new LongPolynomial5(new IntegerPolynomial(coeffs));
        assertTrue(Arrays.areEqual(coeffs, p.toIntegerPolynomial().coeffs));
    }
}