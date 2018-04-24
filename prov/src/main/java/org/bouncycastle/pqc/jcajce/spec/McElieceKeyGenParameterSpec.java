package org.bouncycastle.pqc.jcajce.spec;

import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2;

/**
 * This class provides a specification for the parameters that are used by the
 * McEliece, McElieceCCA2, and Niederreiter key pair generators.
 */
public class McElieceKeyGenParameterSpec
    implements AlgorithmParameterSpec
{

    /**
     * The default extension degree
     */
    public static final int DEFAULT_M = 11;

    /**
     * The default error correcting capability.
     */
    public static final int DEFAULT_T = 50;

    /**
     * extension degree of the finite field GF(2^m)
     */
    private int m;

    /**
     * error correction capability of the code
     */
    private int t;

    /**
     * length of the code
     */
    private int n;

    /**
     * the field polynomial
     */
    private int fieldPoly;

    /**
     * Constructor. Set the default parameters: extension degree.
     */
    public McElieceKeyGenParameterSpec()
    {
        this(DEFAULT_M, DEFAULT_T);
    }

    /**
     * Constructor.
     *
     * @param keysize the length of a Goppa code
     * @throws IllegalArgumentException if <tt>keysize &lt; 1</tt>.
     */
    public McElieceKeyGenParameterSpec(int keysize)
    {
        if (keysize < 1)
        {
            throw new IllegalArgumentException("key size must be positive");
        }
        m = 0;
        n = 1;
        while (n < keysize)
        {
            n <<= 1;
            m++;
        }
        t = n >>> 1;
        t /= m;
        fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m);
    }

    /**
     * Constructor.
     *
     * @param m degree of the finite field GF(2^m)
     * @param t error correction capability of the code
     * @throws InvalidParameterException if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>.
     */
    public McElieceKeyGenParameterSpec(int m, int t)
        throws InvalidParameterException
    {
        if (m < 1)
        {
            throw new IllegalArgumentException("m must be positive");
        }
        if (m > 32)
        {
            throw new IllegalArgumentException("m is too large");
        }
        this.m = m;
        n = 1 << m;
        if (t < 0)
        {
            throw new IllegalArgumentException("t must be positive");
        }
        if (t > n)
        {
            throw new IllegalArgumentException("t must be less than n = 2^m");
        }
        this.t = t;
        fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m);
    }

    /**
     * Constructor.
     *
     * @param m    degree of the finite field GF(2^m)
     * @param t    error correction capability of the code
     * @param poly the field polynomial
     * @throws IllegalArgumentException if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt> or
     * <tt>poly</tt> is not an irreducible field polynomial.
     */
    public McElieceKeyGenParameterSpec(int m, int t, int poly)
    {
        this.m = m;
        if (m < 1)
        {
            throw new IllegalArgumentException("m must be positive");
        }
        if (m > 32)
        {
            throw new IllegalArgumentException(" m is too large");
        }
        this.n = 1 << m;
        this.t = t;
        if (t < 0)
        {
            throw new IllegalArgumentException("t must be positive");
        }
        if (t > n)
        {
            throw new IllegalArgumentException("t must be less than n = 2^m");
        }
        if ((PolynomialRingGF2.degree(poly) == m)
            && (PolynomialRingGF2.isIrreducible(poly)))
        {
            this.fieldPoly = poly;
        }
        else
        {
            throw new IllegalArgumentException(
                "polynomial is not a field polynomial for GF(2^m)");
        }
    }

    /**
     * @return the extension degree of the finite field GF(2^m)
     */
    public int getM()
    {
        return m;
    }

    /**
     * @return the length of the code
     */
    public int getN()
    {
        return n;
    }

    /**
     * @return the error correction capability of the code
     */
    public int getT()
    {
        return t;
    }

    /**
     * @return the field polynomial
     */
    public int getFieldPoly()
    {
        return fieldPoly;
    }

}
