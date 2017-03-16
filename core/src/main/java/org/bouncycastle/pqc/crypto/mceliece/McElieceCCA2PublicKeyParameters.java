package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

/**
 *
 *
 *
 */
public class McElieceCCA2PublicKeyParameters
    extends McElieceCCA2KeyParameters
{
    // the length of the code
    private int n;

    // the error correction capability of the code
    private int t;

    // the generator matrix
    private GF2Matrix matrixG;

    /**
     * Constructor.
     *  @param n      length of the code
     * @param t      error correction capability
     * @param matrix generator matrix
     * @param digest McElieceCCA2Parameters
     */
    public McElieceCCA2PublicKeyParameters(int n, int t, GF2Matrix matrix, String digest)
    {
        super(false, digest);

        this.n = n;
        this.t = t;
        this.matrixG = new GF2Matrix(matrix);
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
     * @return the generator matrix
     */
    public GF2Matrix getG()
    {
        return matrixG;
    }

    /**
     * @return the dimension of the code
     */
    public int getK()
    {
        return matrixG.getNumRows();
    }
}
