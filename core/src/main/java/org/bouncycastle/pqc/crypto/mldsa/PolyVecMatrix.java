package org.bouncycastle.pqc.crypto.mldsa;

class PolyVecMatrix
{
    private final PolyVecL[] matrix;

    /**
     * PolyVecL Matrix of size K
     *
     * @param engine source engine for the matrix to be used by.
     */
    PolyVecMatrix(MLDSAEngine engine)
    {
        int K = engine.getDilithiumK();

        this.matrix = new PolyVecL[K];
        for (int i = 0; i < K; i++)
        {
            matrix[i] = new PolyVecL(engine);
        }
    }

    public void pointwiseMontgomery(PolyVecK t, PolyVecL v)
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

    private String addString()
    {
        String out = "[";
        for (int i = 0; i < matrix.length; i++)
        {
            out += "Outer Matrix " + i + " [";
            out += matrix[i].toString();
            if (i == matrix.length - 1)
            {
                out += "]\n";
                continue;
            }
            out += "],\n";
        }
        out += "]\n";
        return out;
    }

    public String toString(String name)
    {
        return name.concat(": \n" + this.addString());
    }
}
