package org.bouncycastle.pqc.crypto.picnic;

class KMatrices
{
    private int nmatrices;
    private int rows;
    private int columns;
    private int[] data;

    public KMatrices(int nmatrices, int rows, int columns, int[] data)
    {
        this.nmatrices = nmatrices;
        this.rows = rows;
        this.columns = columns;
        this.data = data;
    }

    public int getNmatrices()
    {
        return nmatrices;
    }

    public int getSize()
    {
        return rows * columns;
    }

    public int getRows()
    {
        return rows;
    }

    public int getColumns()
    {
        return columns;
    }

    public int[] getData()
    {
        return data;
    }
}
