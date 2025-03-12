package org.bouncycastle.pqc.crypto.snova;

import org.bouncycastle.util.Arrays;

public class SnovaEngine
{
    private final SnovaParameters params;
    private final int l;
    private final int lsq;
    final byte[][] S;
    final int[][] xS;

    public SnovaEngine(SnovaParameters params)
    {
        this.params = params;
        this.l = params.getL();
        this.lsq = l * l;
        S = new byte[l][lsq];
        xS = new int[l][lsq];
        be_aI(S[0], (byte)1);
        beTheS(S[1]);
        for (int index = 2; index < l; ++index)
        {
            GF16Utils.gf16mMul(S[index - 1], S[1], S[index], l);
        }

        for (int index = 0; index < l; ++index)
        {
            for (int ij = 0; ij < lsq; ++ij)
            {
                xS[index][ij] = GF16Utils.gf16FromNibble(S[index][ij]);
            }
        }
    }

    public byte getGF16m(byte[] gf16m, int x, int y)
    {
        return gf16m[x * l + y];
    }

    public void setGF16m(byte[] gf16m, int x, int y, byte value)
    {
        gf16m[x * l + y] = value;
    }

    public void be_aI(byte[] target, byte a)
    {
        // Mask 'a' to ensure it's a valid 4-bit GF16 element
        a = (byte)(a & 0x0F);

        for (int i = 0; i < l; ++i)
        {
            for (int j = 0; j < l; ++j)
            {
                int index = i * l + j;
                target[index] = (i == j) ? a : (byte)0;
            }
        }
    }

    private void beTheS(byte[] target)
    {
        // Set all elements to 8 - (i + j) in GF16 (4-bit values)
        for (int i = 0; i < l; ++i)
        {
            for (int j = 0; j < l; ++j)
            {
                int value = 8 - (i + j);
                target[i * l + j] = (byte)(value & 0x0F);  // Mask to 4 bits
            }
        }

        // Special case for rank 5
        if (l == 5)
        {
            target[4 * 5 + 4] = (byte)(9 & 0x0F);  // Set (4,4) to 9
        }
    }

    // Constant-time GF16 matrix generation
    public void genAFqSCT(byte[] c, int cOff, byte[] ptMatrix)
    {
        int lsq = l * l;
        int[] xTemp = new int[lsq];

        // Initialize diagonal with c[0]
        int cX = GF16Utils.gf16FromNibble(c[cOff]);
        for (int ij = 0; ij < l; ij++)
        {
            xTemp[ij * l + ij] = cX;
        }

        // Process middle coefficients
        for (int i1 = 1; i1 < l - 1; i1++)
        {
            cX = GF16Utils.gf16FromNibble(c[cOff + i1]);
            for (int ij = 0; ij < lsq; ij++)
            {
                xTemp[ij] ^= cX * xS[i1][ij];
            }
        }

        // Handle last coefficient with constant-time selection
        int zero = GF16Utils.ctGF16IsNotZero(c[cOff + l - 1]);
        int val = zero * c[cOff + l - 1] + (1 - zero) * (15 + GF16Utils.ctGF16IsNotZero(c[cOff]) - c[cOff]);
        cX = GF16Utils.gf16FromNibble((byte)val);

        for (int ij = 0; ij < lsq; ij++)
        {
            xTemp[ij] ^= cX * xS[l - 1][ij];
        }

        // Convert to nibbles and clear temp
        for (int ij = 0; ij < lsq; ij++)
        {
            ptMatrix[ij] = GF16Utils.gf16ToNibble(xTemp[ij]);
        }
        Arrays.fill(xTemp, 0); // Secure clear
    }

    public void makeInvertibleByAddingAS(byte[] source)
    {
        if (gf16Determinant(source) != 0)
        {
            return;
        }


        byte[] temp = new byte[l * l];

        for (int a = 1; a < 16; a++)
        {
            generateASMatrix(temp, (byte)a);
            addMatrices(temp, source, source);

            if (gf16Determinant(source) != 0)
            {
                return;
            }
        }
        throw new IllegalStateException("Failed to make matrix invertible");
    }

    private byte gf16Determinant(byte[] matrix)
    {
        switch (l)
        {
        case 2:
            return determinant2x2(matrix);
        case 3:
            return determinant3x3(matrix);
        case 4:
            return determinant4x4(matrix);
        case 5:
            return determinant5x5(matrix);
        default:
            throw new IllegalStateException();
        }
    }

    private byte determinant2x2(byte[] m)
    {
        return gf16Add(
            gf16Mul(getGF16m(m, 0, 0), getGF16m(m, 1, 1)),
            gf16Mul(getGF16m(m, 0, 1), getGF16m(m, 1, 0)));
    }

    private byte determinant3x3(byte[] m)
    {
        return gf16Add(
            gf16Add(
                gf16Mul(getGF16m(m, 0, 0), gf16Add(
                    gf16Mul(getGF16m(m, 1, 1), getGF16m(m, 2, 2)),
                    gf16Mul(getGF16m(m, 1, 2), getGF16m(m, 2, 1))
                )),
                gf16Mul(getGF16m(m, 0, 1), gf16Add(
                    gf16Mul(getGF16m(m, 1, 0), getGF16m(m, 2, 2)),
                    gf16Mul(getGF16m(m, 1, 2), getGF16m(m, 2, 0))
                ))
            ),
            gf16Mul(getGF16m(m, 0, 2), gf16Add(
                gf16Mul(getGF16m(m, 1, 0), getGF16m(m, 2, 1)),
                gf16Mul(getGF16m(m, 1, 1), getGF16m(m, 2, 0))
            ))
        );
    }

    private byte determinant4x4(byte[] m)
    {
        byte d0 = gf16Mul(getGF16m(m, 0, 0), gf16Add(
            gf16Add(
                pod(m, 1, 1, 2, 2, 3, 3, 2, 3, 3, 2),
                pod(m, 1, 2, 2, 1, 3, 3, 2, 3, 3, 1)
            ),
            pod(m, 1, 3, 2, 1, 3, 2, 2, 2, 3, 1)
        ));

        byte d1 = gf16Mul(getGF16m(m, 0, 1), gf16Add(
            gf16Add(
                pod(m, 1, 0, 2, 2, 3, 3, 2, 3, 3, 2),
                pod(m, 1, 2, 2, 0, 3, 3, 2, 3, 3, 0)
            ),
            pod(m, 1, 3, 2, 0, 3, 2, 2, 2, 3, 0)
        ));

        byte d2 = gf16Mul(getGF16m(m, 0, 2), gf16Add(
            gf16Add(
                pod(m, 1, 0, 2, 1, 3, 3, 2, 3, 3, 1),
                pod(m, 1, 1, 2, 0, 3, 3, 2, 3, 3, 0)
            ),
            pod(m, 1, 3, 2, 0, 3, 1, 2, 1, 3, 0)
        ));

        byte d3 = gf16Mul(getGF16m(m, 0, 3), gf16Add(
            gf16Add(
                pod(m, 1, 0, 2, 1, 3, 2, 2, 2, 3, 1),
                pod(m, 1, 1, 2, 0, 3, 2, 2, 2, 3, 0)
            ),
            pod(m, 1, 2, 2, 0, 3, 1, 2, 1, 3, 0)
        ));

        return (byte)(d0 ^ d1 ^ d2 ^ d3);
    }

    private byte determinant5x5(byte[] m)
    {
        return 0;
        //TODO:
//        byte result;
//
//        result = gf16Mul(det3x3(m, 0, 1, 2, 0, 1, 2),
//            gf16Add(gf16Mul(m[3][3], m[4][4]), gf16Mul(m[3][4], m[4][3])));
        // ... similar calculations for other components ...
        //result ^= gf16Mul(det3x3(m, 0, 1, 2, 0, 1, 2),
        //            gf16Add(gf16Mul(m[3][3], m[4][4]), gf16Mul(m[3][4], m[4][3])));
        //return result;
    }

    private byte det3x3(byte[] m, int row1, int row2, int row3, int col1, int col2, int col3)
    {
        //TODO:
//        byte[][] sub = new byte[3][3];
//        for (int i = 0; i < 3; i++)
//        {
//            sub[0][i] = m[row1][col1 + i];
//            sub[1][i] = m[row2][col1 + i];
//            sub[2][i] = m[row3][col1 + i];
//        }
//        return determinant3x3(sub);
        return 0;
    }

    private void generateASMatrix(byte[] target, byte a)
    {
        for (int i = 0; i < l; i++)
        {
            for (int j = 0; j < l; j++)
            {
                byte coefficient = (byte)(8 - (i + j));
                if (l == 5 && i == 4 && j == 4)
                {
                    coefficient = 9;
                }
                setGF16m(target, i, j, gf16Mul(coefficient, a));
            }
        }
    }

    // POD -> entry[a][b] * (entry[c][d] * entry[e][f] + entry[g][h] * entry[i][j])
    private byte pod(byte[] m, int a, int b, int c, int d, int e, int f, int g, int h, int i, int j)
    {
        return gf16Add(
            gf16Mul(getGF16m(m, a, b), gf16Mul(getGF16m(m, c, d), getGF16m(m, e, f))),
            gf16Mul(getGF16m(m, g, h), getGF16m(m, i, j)));
    }

    private void addMatrices(byte[] a, byte[] b, byte[] c)
    {
        for (int i = 0; i < l; i++)
        {
            for (int j = 0; j < l; j++)
            {
                setGF16m(c, i, j, gf16Add(getGF16m(a, i, j), getGF16m(b, i, j)));
            }
        }
    }

    // GF(16) arithmetic
    private static byte gf16Add(byte a, byte b)
    {
        return (byte)(a ^ b);
    }

    // GF(16) multiplication using lookup table
    private static byte gf16Mul(byte a, byte b)
    {
        return GF16Utils.mul(a, b);
    }

    public void genAFqS(byte[] c, int cOff, byte[] ptMatrix)
    {
        byte[] temp = new byte[l * l];

        // Initialize with be_aI
        be_aI(ptMatrix, c[cOff]);

        // Process middle terms
        for (int i = 1; i < l - 1; ++i)
        {
            gf16mScale(S[i], c[cOff + i], temp);
            addMatrices(ptMatrix, temp, ptMatrix);
        }

        // Handle last term with special case
        byte lastScalar = (c[cOff + l - 1] != 0) ? c[cOff + l - 1] :
            gf16Add((byte)16, gf16Add(c[cOff], (byte)(c[cOff] == 0 ? 1 : 0)));
        gf16mScale(S[l - 1], lastScalar, temp);
        addMatrices(ptMatrix, temp, ptMatrix);

        // Clear temporary matrix
        //clearMatrix(temp);
    }

    private void gf16mScale(byte[] a, byte k, byte[] result)
    {
        for (int i = 0; i < l; ++i)
        {
            for (int j = 0; j < l; ++j)
            {
                setGF16m(result, i, j, gf16Mul(getGF16m(a, i, j), k));
            }
        }
    }

    public void genF(MapGroup2 map2, MapGroup1 map1, byte[][][] T12) {
        int m = params.getM();
        int v = params.getV();
        int o = params.getO();
        int l = params.getL();
        int lsq = l * l;

        // Copy initial matrices
        copy4DMatrix(map1.p11, map2.f11, m, v, v, lsq);
        copy4DMatrix(map1.p12, map2.f12, m, v, o, lsq);
        copy4DMatrix(map1.p21, map2.f21, m, o, v, lsq);

        byte[] temp = new byte[lsq];

        // First matrix operation sequence
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < v; j++) {
                for (int k = 0; k < o; k++) {
                    for (int index = 0; index < v; index++) {
                        GF16Utils.gf16mMul(temp, map1.p11[i][j][index], T12[index][k], l);
                        GF16Utils.gf16mAdd(map2.f12[i][j][k], map2.f12[i][j][k], temp, l);
                    }
                }
            }
        }

        // Second matrix operation sequence
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < o; j++) {
                for (int k = 0; k < v; k++) {
                    for (int index = 0; index < v; index++) {
                        GF16Utils.gf16mMul(temp, T12[index][j], map1.p11[i][index][k], l);
                        GF16Utils.gf16mAdd(map2.f21[i][j][k], map2.f21[i][j][k], temp, l);
                    }
                }
            }
        }

        // Secure clear temporary buffer
        Arrays.fill(temp, (byte) 0);
    }

    private static void copy4DMatrix(byte[][][][] src, byte[][][][] dest,
                                     int dim1, int dim2, int dim3, int lsq) {
        for (int i = 0; i < dim1; i++) {
            for (int j = 0; j < dim2; j++) {
                for (int k = 0; k < dim3; k++) {
                    System.arraycopy(
                        src[i][j][k], 0,
                        dest[i][j][k], 0,
                        lsq
                    );
                }
            }
        }
    }

    public void genP22(byte[] outP22, byte[][][] T12, byte[][][][] P21, byte[][][][] F12, SnovaParameters params) {
        int m = params.getM();
        int o = params.getO();
        int v = params.getV();
        int l = params.getL();
        int lsq = l * l;

        // Initialize P22 with zeros
        byte[][][][] P22 = new byte[m][o][o][lsq];

        // Temporary buffers
        byte[] temp1 = new byte[lsq];
        byte[] temp2 = new byte[lsq];

        try {
            for (int i = 0; i < m; i++) {
                for (int j = 0; j < o; j++) {
                    for (int k = 0; k < o; k++) {
                        for (int index = 0; index < v; index++) {
                            // temp1 = T12[index][j] * F12[i][index][k]
                            GF16Utils.gf16mMul(temp1, T12[index][j], F12[i][index][k], l);

                            // temp2 = P21[i][j][index] * T12[index][k]
                            GF16Utils.gf16mMul(temp2, P21[i][j][index], T12[index][k], l);

                            // temp1 += temp2
                            GF16Utils.gf16mAdd(temp1, temp1, temp2, l);

                            // P22[i][j][k] += temp1
                            GF16Utils.gf16mAdd(P22[i][j][k], P22[i][j][k], temp1, l);
                        }
                    }
                }
            }

            // Convert GF16 elements to packed bytes
            //TODO
            //GF16Utils.decode(P22, outP22, m * o * o *lsq);
        } finally {
            // Secure clear temporary buffers
            Arrays.fill(temp1, (byte) 0);
            Arrays.fill(temp2, (byte) 0);
        }
    }
}
