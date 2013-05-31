package org.bouncycastle.pqc.math.ntru.polynomial.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyGenerationParameters;
import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.ProductFormPolynomial;

public class ProductFormPolynomialTest
    extends TestCase
{
    private NTRUEncryptionKeyGenerationParameters params;
    private int N;
    private int df1;
    private int df2;
    private int df3;
    private int q;

    public void setUp()
    {
        params = NTRUEncryptionKeyGenerationParameters.APR2011_439_FAST;
        N = params.N;
        df1 = params.df1;
        df2 = params.df2;
        df3 = params.df3;
        q = params.q;
    }

    public void testFromToBinary()
        throws Exception
    {
        ProductFormPolynomial p1 = ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3 - 1, new SecureRandom());
        byte[] bin1 = p1.toBinary();
        ProductFormPolynomial p2 = ProductFormPolynomial.fromBinary(bin1, N, df1, df2, df3, df3 - 1);
        assertEquals(p1, p2);
    }

    public void testMult()
    {
        ProductFormPolynomial p1 = ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3 - 1, new SecureRandom());
        IntegerPolynomial p2 = PolynomialGenerator.generateRandom(N, q);
        IntegerPolynomial p3 = p1.mult(p2);
        IntegerPolynomial p4 = p1.toIntegerPolynomial().mult(p2);
        assertEquals(p3, p4);
    }
}