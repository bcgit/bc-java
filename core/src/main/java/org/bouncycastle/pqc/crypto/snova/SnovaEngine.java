package org.bouncycastle.pqc.crypto.snova;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class SnovaEngine
{
    private final SnovaParameters params;
    private final int l;
    final byte[][] S;
    final int[][] xS;

    public SnovaEngine(SnovaParameters params)
    {
        this.params = params;
        this.l = params.getL();
        int lsq = l * l;
        S = new byte[l][lsq];
        xS = new int[l][lsq];
        be_aI(S[0], 0, (byte)1);
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

    public void be_aI(byte[] target, int off, byte a)
    {
        // Mask 'a' to ensure it's a valid 4-bit GF16 element
        a = (byte)(a & 0x0F);

        for (int i = 0; i < l; ++i)
        {
            for (int j = 0; j < l; ++j)
            {
                int index = i * l + j + off;
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

    public void makeInvertibleByAddingAS(byte[] source, int off)
    {
        if (gf16Determinant(source, off) != 0)
        {
            return;
        }

        byte[] temp = new byte[l * l];

        for (int a = 1; a < 16; a++)
        {
            generateASMatrix(temp, (byte)a);
            addMatrices(temp, 0, source, off, source, off);

            if (gf16Determinant(source, off) != 0)
            {
                return;
            }
        }
    }

    private byte gf16Determinant(byte[] matrix, int off)
    {
        switch (l)
        {
        case 2:
            return determinant2x2(matrix, off);
        case 3:
            return determinant3x3(matrix, off, 0, 1, 2);
        case 4:
            return determinant4x4(matrix, off);
        case 5:
            return determinant5x5(matrix, off);
        default:
            throw new IllegalStateException();
        }
    }

    private byte determinant2x2(byte[] m, int off)
    {
        return (byte)
            (GF16Utils.mul(getGF16m(m, 0, off), getGF16m(m, 1, off + 1)) ^
                GF16Utils.mul(getGF16m(m, 0, off + 1), getGF16m(m, 1, off)));
    }

    private byte determinant3x3(byte[] m, int off, int i0, int i1, int i2)
    {
        return (byte)(
            GF16Utils.mul(getGF16m(m, 0, off + i0), (byte)(
                GF16Utils.mul(getGF16m(m, 1, off + i1), getGF16m(m, 2, off + i2)) ^
                    GF16Utils.mul(getGF16m(m, 1, off + i2), getGF16m(m, 2, off + i1)))) ^
                GF16Utils.mul(getGF16m(m, 0, off + i1), (byte)(
                    GF16Utils.mul(getGF16m(m, 1, off + i0), getGF16m(m, 2, off + i2)) ^
                        GF16Utils.mul(getGF16m(m, 1, off + i2), getGF16m(m, 2, off + i0)))) ^
                GF16Utils.mul(getGF16m(m, 0, off + i2), (byte)(
                    GF16Utils.mul(getGF16m(m, 1, off + i0), getGF16m(m, 2, off + i1)) ^
                        GF16Utils.mul(getGF16m(m, 1, off + i1), getGF16m(m, 2, off + i0)))));
    }

    private byte determinant4x4(byte[] m, int off)
    {
        byte m00 = m[off++];
        byte m01 = m[off++];
        byte m02 = m[off++];
        byte m03 = m[off++];
        byte m10 = m[off++];
        byte m11 = m[off++];
        byte m12 = m[off++];
        byte m13 = m[off++];
        byte m20 = m[off++];
        byte m21 = m[off++];
        byte m22 = m[off++];
        byte m23 = m[off++];
        byte m30 = m[off++];
        byte m31 = m[off++];
        byte m32 = m[off++];
        byte m33 = m[off];

        byte m22xm33_m23xm32 = (byte)(GF16Utils.mul(m22, m33) ^ GF16Utils.mul(m23, m32));
        byte m21xm33_m23xm31 = (byte)(GF16Utils.mul(m21, m33) ^ GF16Utils.mul(m23, m31));
        byte m21xm32_m22xm31 = (byte)(GF16Utils.mul(m21, m32) ^ GF16Utils.mul(m22, m31));
        byte m20xm33_m23xm30 = (byte)(GF16Utils.mul(m20, m33) ^ GF16Utils.mul(m23, m30));
        byte m20xm32_m32xm30 = (byte)(GF16Utils.mul(m20, m32) ^ GF16Utils.mul(m22, m30));
        byte m20xm31_m21xm30 = (byte)(GF16Utils.mul(m20, m31) ^ GF16Utils.mul(m21, m30));
        // POD -> entry[a][b] * (entry[c][d] * entry[e][f] + entry[g][h] * entry[i][j])
        return (byte)(GF16Utils.mul(m00, (byte)(GF16Utils.mul(m11, m22xm33_m23xm32) ^
            GF16Utils.mul(m12, m21xm33_m23xm31) ^ GF16Utils.mul(m13, m21xm32_m22xm31))) ^
            GF16Utils.mul(m01, (byte)(GF16Utils.mul(m10, m22xm33_m23xm32) ^
                GF16Utils.mul(m12, m20xm33_m23xm30) ^ GF16Utils.mul(m13, m20xm32_m32xm30))) ^
            GF16Utils.mul(m02, (byte)(GF16Utils.mul(m10, m21xm33_m23xm31) ^
                GF16Utils.mul(m11, m20xm33_m23xm30) ^ GF16Utils.mul(m13, m20xm31_m21xm30))) ^
            GF16Utils.mul(m03, (byte)(GF16Utils.mul(m10, m21xm32_m22xm31) ^
                GF16Utils.mul(m11, m20xm32_m32xm30) ^ GF16Utils.mul(m12, m20xm31_m21xm30))));
    }

    private byte determinant5x5(byte[] m, int off)
    {
        byte m30 = getGF16m(m, 3, off);
        byte m31 = getGF16m(m, 3, off + 1);
        byte m32 = getGF16m(m, 3, off + 2);
        byte m33 = getGF16m(m, 3, off + 3);
        byte m34 = getGF16m(m, 3, off + 4);

        byte m40 = getGF16m(m, 4, off);
        byte m41 = getGF16m(m, 4, off + 1);
        byte m42 = getGF16m(m, 4, off + 2);
        byte m43 = getGF16m(m, 4, off + 3);
        byte m44 = getGF16m(m, 4, off + 4);
        byte result = GF16Utils.mul(determinant3x3(m, off, 0, 1, 2),
            (byte)(GF16Utils.mul(m33, m44) ^ GF16Utils.mul(m34, m43)));
        result ^= GF16Utils.mul(determinant3x3(m, off, 0, 1, 3),
            (byte)(GF16Utils.mul(m32, m44) ^ GF16Utils.mul(m34, m42)));
        result ^= GF16Utils.mul(determinant3x3(m, off, 0, 1, 4),
            (byte)(GF16Utils.mul(m32, m43) ^ GF16Utils.mul(m33, m42)));
        result ^= GF16Utils.mul(determinant3x3(m, off, 0, 2, 3),
            (byte)(GF16Utils.mul(m31, m44) ^ GF16Utils.mul(m34, m41)));
        result ^= GF16Utils.mul(determinant3x3(m, off, 0, 2, 4),
            (byte)(GF16Utils.mul(m31, m43) ^ GF16Utils.mul(m33, m41)));
        result ^= GF16Utils.mul(determinant3x3(m, off, 0, 3, 4),
            (byte)(GF16Utils.mul(m31, m42) ^ GF16Utils.mul(m32, m41)));
        result ^= GF16Utils.mul(determinant3x3(m, off, 1, 2, 3),
            (byte)(GF16Utils.mul(m30, m44) ^ GF16Utils.mul(m34, m40)));
        result ^= GF16Utils.mul(determinant3x3(m, off, 1, 2, 4),
            (byte)(GF16Utils.mul(m30, m43) ^ GF16Utils.mul(m33, m40)));
        result ^= GF16Utils.mul(determinant3x3(m, off, 1, 3, 4),
            (byte)(GF16Utils.mul(m30, m42) ^ GF16Utils.mul(m32, m40)));
        result ^= GF16Utils.mul(determinant3x3(m, off, 2, 3, 4),
            (byte)(GF16Utils.mul(m30, m41) ^ GF16Utils.mul(m31, m40)));
        return result;
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
                setGF16m(target, i, j, GF16Utils.mul(coefficient, a));
            }
        }
    }


    private void addMatrices(byte[] a, int aOff, byte[] b, int bOff, byte[] c, int cOff)
    {
        for (int i = 0; i < l; i++)
        {
            for (int j = 0; j < l; j++)
            {
                setGF16m(c, i, cOff + j, (byte)(getGF16m(a, i, aOff + j) ^ getGF16m(b, i, bOff + j)));
            }
        }
    }

    public void genAFqS(byte[] c, int cOff, byte[] ptMatrix, int off)
    {
        byte[] temp = new byte[l * l];

        // Initialize with be_aI
        be_aI(ptMatrix, off, c[cOff]);

        // Process middle terms
        for (int i = 1; i < l - 1; ++i)
        {
            gf16mScale(S[i], c[cOff + i], temp);
            addMatrices(ptMatrix, off, temp, 0, ptMatrix, off);
        }

        // Handle last term with special case
        byte lastScalar = (byte)((c[cOff + l - 1] != 0) ? c[cOff + l - 1] : 16 - (c[cOff] + (c[cOff] == 0 ? 1 : 0)));
        gf16mScale(S[l - 1], lastScalar, temp);
        addMatrices(ptMatrix, off, temp, 0, ptMatrix, off);

        // Clear temporary matrix
        //clearMatrix(temp);
    }

    private void gf16mScale(byte[] a, byte k, byte[] result)
    {
        for (int i = 0; i < l; ++i)
        {
            for (int j = 0; j < l; ++j)
            {
                setGF16m(result, i, j, GF16Utils.mul(getGF16m(a, i, j), k));
            }
        }
    }

    public void genF(MapGroup2 map2, MapGroup1 map1, byte[][][] T12)
    {
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
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < v; j++)
            {
                for (int k = 0; k < o; k++)
                {
                    for (int index = 0; index < v; index++)
                    {
                        GF16Utils.gf16mMul(map1.p11[i][j][index], T12[index][k], temp, l);
                        GF16Utils.gf16mAdd(map2.f12[i][j][k], temp, map2.f12[i][j][k], l);
                    }
                }
            }
        }

        // Second matrix operation sequence
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < o; j++)
            {
                for (int k = 0; k < v; k++)
                {
                    for (int index = 0; index < v; index++)
                    {
                        GF16Utils.gf16mMul(T12[index][j], map1.p11[i][index][k], temp, l);
                        GF16Utils.gf16mAdd(map2.f21[i][j][k], temp, map2.f21[i][j][k], l);
                    }
                }
            }
        }

        // Secure clear temporary buffer
        Arrays.fill(temp, (byte)0);
    }

    private static void copy4DMatrix(byte[][][][] src, byte[][][][] dest,
                                     int dim1, int dim2, int dim3, int lsq)
    {
        for (int i = 0; i < dim1; i++)
        {
            for (int j = 0; j < dim2; j++)
            {
                for (int k = 0; k < dim3; k++)
                {
                    System.arraycopy(
                        src[i][j][k], 0,
                        dest[i][j][k], 0,
                        lsq
                    );
                }
            }
        }
    }

    public void genP22(byte[] outP22, byte[][][] T12, byte[][][][] P21, byte[][][][] F12)
    {
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

        try
        {
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < o; j++)
                {
                    for (int k = 0; k < o; k++)
                    {
                        for (int index = 0; index < v; index++)
                        {
                            // temp1 = T12[index][j] * F12[i][index][k]
                            GF16Utils.gf16mMul(T12[index][j], F12[i][index][k], temp1, l);

                            // temp2 = P21[i][j][index] * T12[index][k]
                            GF16Utils.gf16mMul(P21[i][j][index], T12[index][k], temp2, l);

                            // temp1 += temp2
                            GF16Utils.gf16mAdd(temp1, temp2, temp1, l);

                            // P22[i][j][k] += temp1
                            GF16Utils.gf16mAdd(P22[i][j][k], temp1, P22[i][j][k], l);
                        }
                    }
                }
            }

            // Convert GF16 elements to packed bytes
            byte[] tmp = new byte[outP22.length << 1];
            MapGroup1.copyTo(P22, tmp);
            GF16Utils.encode(tmp, outP22, 0, tmp.length);
        }
        finally
        {
            // Secure clear temporary buffers
            Arrays.fill(temp1, (byte)0);
            Arrays.fill(temp2, (byte)0);
        }
    }

    void genSeedsAndT12(byte[][][] T12, byte[] skSeed)
    {
        int bytesPrngPrivate = (params.getV() * params.getO() * params.getL() + 1) >>> 1;
        int gf16sPrngPrivate = params.getV() * params.getO() * params.getL();
        byte[] prngOutput = new byte[bytesPrngPrivate];

        // Generate PRNG output using SHAKE-256
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(skSeed, 0, skSeed.length);
        shake.doFinal(prngOutput, 0, prngOutput.length);

        // Convert bytes to GF16 array
        byte[] gf16PrngOutput = new byte[gf16sPrngPrivate];
        GF16Utils.decode(prngOutput, gf16PrngOutput, gf16sPrngPrivate);

        // Generate T12 matrices
        int ptArray = 0;
        int l = params.getL();
        for (int j = 0; j < params.getV(); j++)
        {
            for (int k = 0; k < params.getO(); k++)
            {
                //gen_a_FqS_ct
                genAFqSCT(gf16PrngOutput, ptArray, T12[j][k]);
                ptArray += l;
            }
        }
    }

    void genABQP(MapGroup1 map1, byte[] pkSeed, byte[] fixedAbq)
    {
        int l = params.getL();
        int lsq = l * l;
        int m = params.getM();
        int alpha = params.getAlpha();
        int v = params.getV();
        int o = params.getO();
        int n = v + o;

        int gf16sPrngPublic = lsq * (2 * m * alpha + m * (n * n - m * m)) + l * 2 * m * alpha;
        byte[] qTemp = new byte[(m * alpha * lsq + m * alpha * lsq) / l];
        byte[] prngOutput = new byte[(gf16sPrngPublic + 1) >> 1];

        if (params.isPkExpandShake())
        {
            final int SHAKE128_RATE = 168; // 1344-bit rate = 168 bytes
            long blockCounter = 0;
            int offset = 0;
            int remaining = prngOutput.length;
            byte[] counterBytes = new byte[8];
            SHAKEDigest shake = new SHAKEDigest(128);
            while (remaining > 0)
            {
                // Process seed + counter
                shake.update(pkSeed, 0, pkSeed.length);
                Pack.longToLittleEndian(blockCounter, counterBytes, 0);
                shake.update(counterBytes, 0, 8);

                // Calculate bytes to generate in this iteration
                int bytesToGenerate = Math.min(remaining, SHAKE128_RATE);

                // Generate output (XOF mode)
                shake.doFinal(prngOutput, offset, bytesToGenerate);

                offset += bytesToGenerate;
                remaining -= bytesToGenerate;
                blockCounter++;
            }
        }
        else
        {
            // Create a 16-byte IV (all zeros)
            byte[] iv = new byte[16]; // automatically zero-initialized
            // AES-CTR-based expansion
            // Set up AES engine in CTR (SIC) mode.
            BlockCipher aesEngine = AESEngine.newInstance();
            // SICBlockCipher implements CTR mode for AES.
            CTRModeCipher ctrCipher = SICBlockCipher.newInstance(aesEngine);
            ParametersWithIV params = new ParametersWithIV(new KeyParameter(pkSeed), iv);
            ctrCipher.init(true, params);
            int blockSize = ctrCipher.getBlockSize(); // typically 16 bytes
            byte[] zeroBlock = new byte[blockSize];     // block of zeros
            byte[] blockOut = new byte[blockSize];

            int offset = 0;
            // Process full blocks
            while (offset + blockSize <= prngOutput.length)
            {
                ctrCipher.processBlock(zeroBlock, 0, blockOut, 0);
                System.arraycopy(blockOut, 0, prngOutput, offset, blockSize);
                offset += blockSize;
            }
            // Process any remaining partial block.
            if (offset < prngOutput.length)
            {
                ctrCipher.processBlock(zeroBlock, 0, blockOut, 0);
                int remaining = prngOutput.length - offset;
                System.arraycopy(blockOut, 0, prngOutput, offset, remaining);
            }
        }
        byte[] temp = new byte[gf16sPrngPublic - qTemp.length];
        GF16Utils.decode(prngOutput, temp, temp.length);
        map1.fill(temp);
        if (l >= 4)
        {
            GF16Utils.decode(prngOutput, temp.length >> 1, qTemp, 0, qTemp.length);

            // Post-processing for invertible matrices
            for (int pi = 0; pi < m; ++pi)
            {
                for (int a = 0; a < alpha; ++a)
                {
                    makeInvertibleByAddingAS(map1.aAlpha[pi][a], 0);
                }
            }
            for (int pi = 0; pi < m; ++pi)
            {
                for (int a = 0; a < alpha; ++a)
                {
                    makeInvertibleByAddingAS(map1.bAlpha[pi][a], 0);
                }
            }

            int ptArray = 0;
            for (int pi = 0; pi < m; ++pi)
            {
                for (int a = 0; a < alpha; ++a)
                {
                    genAFqS(qTemp, ptArray, map1.qAlpha1[pi][a], 0);
                    ptArray += l;
                }
            }
            for (int pi = 0; pi < m; ++pi)
            {
                for (int a = 0; a < alpha; ++a)
                {
                    genAFqS(qTemp, ptArray, map1.qAlpha2[pi][a], 0);
                    ptArray += l;
                }
            }
        }
        else
        {
            MapGroup1.fillAlpha(fixedAbq, 0, map1.aAlpha, m * o * alpha * lsq);
            MapGroup1.fillAlpha(fixedAbq, o * alpha * lsq, map1.bAlpha, (m - 1) * o * alpha * lsq);
            MapGroup1.fillAlpha(fixedAbq, o * alpha * lsq * 2, map1.qAlpha1, (m - 2) * o * alpha * lsq);
            MapGroup1.fillAlpha(fixedAbq, o * alpha * lsq * 3, map1.qAlpha2, (m - 3) * o * alpha * lsq);
        }
    }
}
