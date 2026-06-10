package org.bouncycastle.crypto.signers.mldsa;

class PolyVecMatrix
{
    private final PolyVec[] matrix;

    /**
     * Matrix of K rows, each row a PolyVec of length L.
     *
     * @param engine source engine for the matrix to be used by.
     */
    PolyVecMatrix(MLDSAEngine engine)
    {
        int K = engine.getDilithiumK();
        int L = engine.getDilithiumL();

        this.matrix = new PolyVec[K];
        for (int i = 0; i < K; i++)
        {
            matrix[i] = new PolyVec(engine, L);
        }
    }

    public void pointwiseMontgomery(PolyVec t, PolyVec v)
    {
        for (int i = 0; i < matrix.length; ++i)
        {
            t.getVectorIndex(i).pointwiseAccountMontgomery(matrix[i], v);
        }
    }

    public void expandMatrix(byte[] rho)
    {
        for (int i = 0; i < matrix.length; ++i)
        {
            matrix[i].uniformBlocks(rho, i << 8);
        }
    }
}
