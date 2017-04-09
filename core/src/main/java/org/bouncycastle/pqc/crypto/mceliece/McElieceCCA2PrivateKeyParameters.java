package org.bouncycastle.pqc.crypto.mceliece;


import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2m;

/**
 *
 *
 *
 */
public class McElieceCCA2PrivateKeyParameters
    extends McElieceCCA2KeyParameters
{
    // the length of the code
    private int n;

    // the dimension of the code
    private int k;

    // the finte field GF(2^m)
    private GF2mField field;

    // the irreducible Goppa polynomial
    private PolynomialGF2mSmallM goppaPoly;

    // the permutation
    private Permutation p;

    // the canonical check matrix
    private GF2Matrix h;

    // the matrix used to compute square roots in (GF(2^m))^t
    private PolynomialGF2mSmallM[] qInv;

    /**
     * Constructor.
     *
     * @param n      the length of the code
     * @param k      the dimension of the code
     * @param field  the finite field <tt>GF(2<sup>m</sup>)</tt>
     * @param gp     the irreducible Goppa polynomial
     * @param p      the permutation
     * @param digest name of digest algorithm
     */
    public McElieceCCA2PrivateKeyParameters(int n, int k, GF2mField field,
                                            PolynomialGF2mSmallM gp, Permutation p, String digest)
    {
        this(n, k, field, gp, GoppaCode.createCanonicalCheckMatrix(field, gp), p, digest);
    }
    
    /**
     * Constructor.
     *
     * @param n                         the length of the code
     * @param k                         the dimension of the code
     * @param field                     the finite field <tt>GF(2<sup>m</sup>)</tt>
     * @param gp                        the irreducible Goppa polynomial
     * @param canonicalCheckMatrix      the canonical check matrix
     * @param p                         the permutation
     * @param digest                    name of digest algorithm
     */
    public McElieceCCA2PrivateKeyParameters(int n, int k, GF2mField field, PolynomialGF2mSmallM gp, 
                                            GF2Matrix canonicalCheckMatrix, Permutation p, String digest)
    {
        super(true, digest);
        
        this.n = n;
        this.k = k;
        this.field = field;
        this.goppaPoly = gp;
        this.h = canonicalCheckMatrix;
        this.p = p;
        
        PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);

        // matrix for computing square roots in (GF(2^m))^t
        this.qInv = ring.getSquareRootMatrix();
    }

    /**
     * @return the length of the code
     */
    public int getN()
    {
        return n;
    }

    /**
     * @return the dimension of the code
     */
    public int getK()
    {
        return k;
    }

    /**
     * @return the degree of the Goppa polynomial (error correcting capability)
     */
    public int getT()
    {
        return goppaPoly.getDegree();
    }

    /**
     * @return the finite field
     */
    public GF2mField getField()
    {
        return field;
    }

    /**
     * @return the irreducible Goppa polynomial
     */
    public PolynomialGF2mSmallM getGoppaPoly()
    {
        return goppaPoly;
    }

    /**
     * @return the permutation P
     */
    public Permutation getP()
    {
        return p;
    }

    /**
     * @return the canonical check matrix H
     */
    public GF2Matrix getH()
    {
        return h;
    }

    /**
     * @return the matrix used to compute square roots in <tt>(GF(2^m))^t</tt>
     */
    public PolynomialGF2mSmallM[] getQInv()
    {
        return qInv;
    }
}
