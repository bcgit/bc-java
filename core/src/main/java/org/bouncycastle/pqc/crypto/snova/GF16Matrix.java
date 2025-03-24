//package org.bouncycastle.pqc.crypto.snova;
//
//class GF16Matrix
//{
//    private final byte[][] data;
//    private final int rank;
//
//    public GF16Matrix(int rank)
//    {
//        this.rank = rank;
//        this.data = new byte[rank][rank];
//    }
//
//    public void set(int x, int y, byte value)
//    {
//        data[x][y] = (byte)(value & 0xF);
//    }
//
//    public byte get(int x, int y)
//    {
//        return data[x][y];
//    }
//
////    public void add(GF16Matrix other)
////    {
//////        for (int i = 0; i < size; i++)
//////        {
//////            for (int j = 0; j < size; j++)
//////            {
//////                data[i][j] = add(data[i][j], other.data[i][j]);
//////            }
//////        }
////    }
//
//    public void mul(GF16Matrix a, GF16Matrix b)
//    {
//        byte[][] temp = new byte[rank][rank];
//        for (int i = 0; i < rank; i++)
//        {
//            for (int j = 0; j < rank; j++)
//            {
//                byte sum = 0;
////                for (int k = 0; k < size; k++)
////                {
////                    sum = add(sum, mul(a.data[i][k], b.data[k][j]));
////                }
//                temp[i][j] = sum;
//            }
//        }
//        System.arraycopy(temp, 0, data, 0, temp.length);
//    }
//
//    public void scale(byte scalar)
//    {
////        for (int i = 0; i < size; i++)
////        {
////            for (int j = 0; j < size; j++)
////            {
////                data[i][j] = mul(data[i][j], scalar);
////            }
////        }
//    }
//
//    public void transpose()
//    {
//        byte[][] temp = new byte[rank][rank];
//        for (int i = 0; i < rank; i++)
//        {
//            for (int j = 0; j < rank; j++)
//            {
//                temp[j][i] = data[i][j];
//            }
//        }
//        System.arraycopy(temp, 0, data, 0, temp.length);
//    }
//
////    public void makeInvertible()
////    {
////        // Implementation of be_invertible_by_add_aS
////        GF16Matrix temp = new GF16Matrix(rank);
////        if (determinant() == 0)
////        {
////            for (byte a = 1; a < 16; a++)
////            {
////                temp.scale(a);
////                add(temp);
////                if (determinant() != 0)
////                {
////                    return;
////                }
////            }
////        }
////    }
//
////    private byte determinant()
////    {
////        // Simplified determinant calculation for small matrices
//////        if (rank == 2)
//////        {
//////            return add(mul(data[0][0], data[1][1]), mul(data[0][1], data[1][0]));
//////        }
////        // Add implementations for larger matrices as needed
////        throw new UnsupportedOperationException("Determinant for size " + rank + " not implemented");
////    }
//}