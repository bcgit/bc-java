package org.bouncycastle.pqc.math.ntru.polynomial.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.pqc.math.ntru.polynomial.BigIntPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;

public class SparseTernaryPolynomialTest
    extends TestCase
{

    /**
     * tests mult(IntegerPolynomial) and mult(BigIntPolynomial)
     */
    public void testMult()
    {
        SecureRandom random = new SecureRandom();
        SparseTernaryPolynomial p1 = SparseTernaryPolynomial.generateRandom(1000, 500, 500, random);
        IntegerPolynomial p2 = DenseTernaryPolynomial.generateRandom(1000, random);

        IntegerPolynomial prod1 = p1.mult(p2);
        IntegerPolynomial prod2 = p1.mult(p2);
        assertEquals(prod1, prod2);

        BigIntPolynomial p3 = new BigIntPolynomial(p2);
        BigIntPolynomial prod3 = p1.mult(p3);

        assertEquals(new BigIntPolynomial(prod1), prod3);
    }

    public void testFromToBinary()
        throws IOException
    {
        SecureRandom random = new SecureRandom();
        SparseTernaryPolynomial poly1 = SparseTernaryPolynomial.generateRandom(1000, 100, 101, random);
        ByteArrayInputStream poly1Stream = new ByteArrayInputStream(poly1.toBinary());
        SparseTernaryPolynomial poly2 = SparseTernaryPolynomial.fromBinary(poly1Stream, 1000, 100, 101);
        assertEquals(poly1, poly2);
    }
}