package org.bouncycastle.pqc.crypto.picnic;

class KMatricesWithPointer
    extends KMatrices
{
    private int matrixPointer;
    public KMatricesWithPointer(KMatrices m)
    {
        super(m.getNmatrices(), m.getRows(), m.getColumns(), m.getData());
        this.matrixPointer = 0;

    }
    public int getMatrixPointer()
    {
        return matrixPointer;
    }

    public void setMatrixPointer(int matrixPointer)
    {
        this.matrixPointer = matrixPointer;
    }
}
