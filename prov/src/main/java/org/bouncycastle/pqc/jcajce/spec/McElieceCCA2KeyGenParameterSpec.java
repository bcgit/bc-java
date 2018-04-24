package org.bouncycastle.pqc.jcajce.spec;

import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2;

/**
 * This class provides a specification for the parameters that are used by the
 * McEliece, McElieceCCA2, and Niederreiter key pair generators.
 */
public class McElieceCCA2KeyGenParameterSpec
    implements AlgorithmParameterSpec
{
    public static final String SHA1 = "SHA-1";
    public static final String SHA224 = "SHA-224";
    public static final String SHA256 = "SHA-256";
    public static final String SHA384 = "SHA-384";
    public static final String SHA512 = "SHA-512";

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
    private final int m;

    /**
     * error correction capability of the code
     */
    private final int t;

    /**
     * length of the code
     */
    private final int n;

    /**
     * the field polynomial
     */
    private int fieldPoly;

    private final String digest;

    /**
     * Constructor. Set the default parameters: extension degree.
     */
    public McElieceCCA2KeyGenParameterSpec()
    {
        this(DEFAULT_M, DEFAULT_T, SHA256);
    }

    /**
     * Constructor.
     *
     * @param keysize the length of a Goppa code
     * @throws IllegalArgumentException if <tt>keysize &lt; 1</tt>.
     */
    public McElieceCCA2KeyGenParameterSpec(int keysize)
    {
        this(keysize, SHA256);
    }

    public McElieceCCA2KeyGenParameterSpec(int keysize, String digest)
    {
        if (keysize < 1)
        {
            throw new IllegalArgumentException("key size must be positive");
        }
        int m = 0;
        int n = 1;
        while (n < keysize)
        {
            n <<= 1;
            m++;
        }
        t = (n >>> 1) / m;

        this.m = m;
        this.n = n;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(m);
        this.digest = digest;
    }

    /**
     * Constructor.
     *
     * @param m degree of the finite field GF(2^m)
     * @param t error correction capability of the code
     * @throws InvalidParameterException if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>.
     */
    public McElieceCCA2KeyGenParameterSpec(int m, int t)
    {
        this(m, t, SHA256);
    }

    public McElieceCCA2KeyGenParameterSpec(int m, int t, String digest)
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
        this.digest = digest;
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
    public McElieceCCA2KeyGenParameterSpec(int m, int t, int poly)
    {
        this(m, t, poly, SHA256);
    }

    public McElieceCCA2KeyGenParameterSpec(int m, int t, int poly, String digest)
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
        this.digest = digest;
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

    /**
     * Return CCA-2 digest.
     */
    public String getDigest()
    {
        return digest;
    }
}
