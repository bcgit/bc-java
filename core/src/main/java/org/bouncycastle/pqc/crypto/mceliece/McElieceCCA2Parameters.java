package org.bouncycastle.pqc.crypto.mceliece;

public class McElieceCCA2Parameters
    extends McElieceParameters
{
    private final String digest;

    /**
     * Constructor. Set the default parameters: extension degree.
     */
    public McElieceCCA2Parameters()
    {
        this(DEFAULT_M, DEFAULT_T, "SHA-256");
    }

    public McElieceCCA2Parameters(String digest)
    {
        this(DEFAULT_M, DEFAULT_T, digest);
    }

    /**
     * Constructor.
     *
     * @param keysize the length of a Goppa code
     * @throws IllegalArgumentException if <tt>keysize &lt; 1</tt>.
     */
    public McElieceCCA2Parameters(int keysize)
    {
        this(keysize, "SHA-256");
    }

    /**
     * Constructor.
     *
     * @param keysize the length of a Goppa code
     * @param digest CCA2 mode digest
     * @throws IllegalArgumentException if <tt>keysize &lt; 1</tt>.
     */
    public McElieceCCA2Parameters(int keysize, String digest)
    {
        super(keysize);
        this.digest = digest;
    }

    /**
     * Constructor.
     *
     * @param m degree of the finite field GF(2^m)
     * @param t error correction capability of the code
     * @throws IllegalArgumentException if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>.
     */
    public McElieceCCA2Parameters(int m, int t)
    {
        this(m, t, "SHA-256");
    }

    /**
     * Constructor.
     *
     * @param m degree of the finite field GF(2^m)
     * @param t error correction capability of the code
     * @throws IllegalArgumentException if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>.
     */
    public McElieceCCA2Parameters(int m, int t, String digest)
    {
        super(m, t);
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
    public McElieceCCA2Parameters(int m, int t, int poly)
    {
        this(m, t, poly, "SHA-256");
    }

    /**
     * Constructor.
     *
     * @param m    degree of the finite field GF(2^m)
     * @param t    error correction capability of the code
     * @param poly the field polynomial
     * @param digest CCA2 mode digest
     * @throws IllegalArgumentException if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt> or
     * <tt>poly</tt> is not an irreducible field polynomial.
     */
    public McElieceCCA2Parameters(int m, int t, int poly, String digest)
    {
        super(m, t, poly);
        this.digest = digest;
    }

    /**
     * Return the CCA2 mode digest if set.
     *
     * @return the CCA2 digest to use, null if not present.
     */
    public String getDigest()
    {
        return digest;
    }
}
