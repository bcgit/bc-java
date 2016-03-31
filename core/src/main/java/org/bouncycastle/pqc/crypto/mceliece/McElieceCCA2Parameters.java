package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

public class McElieceCCA2Parameters
    extends McElieceParameters
{
    private Digest digest;

    /**
     * Constructor. Set the default parameters: extension degree.
     */
    public McElieceCCA2Parameters()
    {
        this(DEFAULT_M, DEFAULT_T, new SHA256Digest());
    }

    public McElieceCCA2Parameters(Digest digest)
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
        this(keysize, new SHA256Digest());
    }

    /**
     * Constructor.
     *
     * @param keysize the length of a Goppa code
     * @param digest CCA2 mode digest
     * @throws IllegalArgumentException if <tt>keysize &lt; 1</tt>.
     */
    public McElieceCCA2Parameters(int keysize, Digest digest)
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
        this(m, t, new SHA256Digest());
    }

    /**
     * Constructor.
     *
     * @param m degree of the finite field GF(2^m)
     * @param t error correction capability of the code
     * @throws IllegalArgumentException if <tt>m &lt; 1</tt> or <tt>m &gt; 32</tt> or
     * <tt>t &lt; 0</tt> or <tt>t &gt; n</tt>.
     */
    public McElieceCCA2Parameters(int m, int t, Digest digest)
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
        this(m, t, poly, new SHA256Digest());
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
    public McElieceCCA2Parameters(int m, int t, int poly, Digest digest)
    {
        super(m, t, poly);
        this.digest = digest;
    }

    /**
     * Return the CCA2 mode digest if set.
     *
     * @return the CCA2 digest to use, null if not present.
     */
    public Digest getDigest()
    {
        return digest;
    }
}
