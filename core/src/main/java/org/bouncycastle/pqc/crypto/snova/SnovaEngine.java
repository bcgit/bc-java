package org.bouncycastle.pqc.crypto.snova;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.GF16;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

class SnovaEngine
{
    private final static Map<Integer, byte[]> fixedAbqSet = new HashMap<Integer, byte[]>();//key is o
    private final static Map<Integer, byte[][]> sSet = new HashMap<Integer, byte[][]>(); //key is l
    private final static Map<Integer, int[][]> xSSet = new HashMap<Integer, int[][]>(); //key is l
    private final SnovaParameters params;
    private final int l;
    private final int lsq;
    private final int m;
    private final int v;
    private final int o;
    private final int alpha;
    private final int n;
    final byte[][] S;
    final int[][] xS;

    public SnovaEngine(SnovaParameters params)
    {
        this.params = params;
        this.l = params.getL();
        this.lsq = params.getLsq();
        this.m = params.getM();
        this.v = params.getV();
        this.o = params.getO();
        this.alpha = params.getAlpha();
        this.n = params.getN();
        if (!xSSet.containsKey(Integers.valueOf(l)))
        {
            byte[][] S = new byte[l][lsq];
            int[][] xS = new int[l][lsq];
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
            sSet.put(Integers.valueOf(l), S);
            xSSet.put(Integers.valueOf(l), xS);
        }
        S = (byte[][])sSet.get(Integers.valueOf(l));
        xS = (int[][])xSSet.get(Integers.valueOf(l));
        if (l < 4 && !fixedAbqSet.containsKey(Integers.valueOf(o)))
        {
            int alphaxl = alpha * l;
            int alphaxlsq = alphaxl * l;
            int oxalphaxl = o * alphaxl;
            int oxalphaxlsq = o * alphaxlsq;
            byte[] fixedAbq = new byte[oxalphaxlsq << 2];
            byte[] rngOut = new byte[oxalphaxlsq + oxalphaxl];
            byte[] q12 = new byte[oxalphaxl << 2];
            byte[] seed = "SNOVA_ABQ".getBytes();
            SHAKEDigest shake = new SHAKEDigest(256);
            shake.update(seed, 0, seed.length);
            shake.doFinal(rngOut, 0, rngOut.length);
            GF16.decode(rngOut, fixedAbq, oxalphaxlsq << 1);
            GF16.decode(rngOut, alphaxlsq, q12, 0, oxalphaxl << 1);
            // Post-processing for invertible matrices
            for (int pi = 0, pixAlphaxlsq = 0, pixalphaxl = 0; pi < o; ++pi, pixAlphaxlsq += alphaxlsq, pixalphaxl += alphaxl)
            {
                for (int a = 0, axl = pixalphaxl, axlsq = pixAlphaxlsq; a < alpha; ++a, axl += l, axlsq += lsq)
                {
                    makeInvertibleByAddingAS(fixedAbq, axlsq);
                    makeInvertibleByAddingAS(fixedAbq, oxalphaxlsq + axlsq);
                    genAFqS(q12, axl, fixedAbq, (oxalphaxlsq << 1) + axlsq);
                    genAFqS(q12, oxalphaxl + axl, fixedAbq, (oxalphaxlsq << 1) + oxalphaxlsq + axlsq);
                }
            }
            fixedAbqSet.put(Integers.valueOf(o), fixedAbq);
        }
    }

    private void beTheS(byte[] target)
    {
        // Set all elements to 8 - (i + j) in GF16 (4-bit values)
        for (int i = 0, il = 0; i < l; ++i, il += l)
        {
            for (int j = 0; j < l; ++j)
            {
                int value = 8 - (i + j);
                target[il + j] = (byte)(value & 0x0F);  // Mask to 4 bits
            }
        }

        // Special case for rank 5
        if (l == 5)
        {
            target[24] = (byte)9;  // Set (4,4) to 9
        }
    }

    private void be_aI(byte[] target, int off, byte a)
    {
        // Ensure 'a' iss a valid 4-bit GF16 element
        int l1 = l + 1;
        for (int i = 0; i < l; ++i, off += l1)
        {
            target[off] = a;
        }
    }

    // Constant-time GF16 matrix generation
    private void genAFqSCT(byte[] c, int cOff, byte[] ptMatrix)
    {
        int[] xTemp = new int[lsq];
        int l1 = l + 1;
        // Initialize diagonal with c[0]
        int cX = GF16Utils.gf16FromNibble(c[cOff]);
        for (int ij = 0, ijl1 = 0; ij < l; ij++, ijl1 += l1)
        {
            xTemp[ijl1] = cX;
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
            ptMatrix[ij] = GF16Utils.gf16ToNibble(xTemp[ij]);
        }
        Arrays.fill(xTemp, 0); // Secure clear
    }

    private void makeInvertibleByAddingAS(byte[] source, int off)
    {
        if (gf16Determinant(source, off) != 0)
        {
            return;
        }

        for (int a = 1; a < 16; a++)
        {
            generateASMatrixTo(source, off, (byte)a);

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
            return determinant3x3(matrix, off);
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
        return (byte)(GF16.mul(m[off], m[off + 3]) ^ GF16.mul(m[off + 1], m[off + 2]));
    }

    private byte determinant3x3(byte[] m, int off)
    {
        byte m00 = m[off++];
        byte m01 = m[off++];
        byte m02 = m[off++];
        byte m10 = m[off++];
        byte m11 = m[off++];
        byte m12 = m[off++];
        byte m20 = m[off++];
        byte m21 = m[off++];
        byte m22 = m[off];
        return (byte)(GF16.mul(m00, GF16.mul(m11, m22) ^ GF16.mul(m12, m21)) ^
            GF16.mul(m01, GF16.mul(m10, m22) ^ GF16.mul(m12, m20)) ^
            GF16.mul(m02, GF16.mul(m10, m21) ^ GF16.mul(m11, m20)));
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

        byte m22xm33_m23xm32 = (byte)(GF16.mul(m22, m33) ^ GF16.mul(m23, m32));
        byte m21xm33_m23xm31 = (byte)(GF16.mul(m21, m33) ^ GF16.mul(m23, m31));
        byte m21xm32_m22xm31 = (byte)(GF16.mul(m21, m32) ^ GF16.mul(m22, m31));
        byte m20xm33_m23xm30 = (byte)(GF16.mul(m20, m33) ^ GF16.mul(m23, m30));
        byte m20xm32_m32xm30 = (byte)(GF16.mul(m20, m32) ^ GF16.mul(m22, m30));
        byte m20xm31_m21xm30 = (byte)(GF16.mul(m20, m31) ^ GF16.mul(m21, m30));
        // POD -> entry[a][b] * (entry[c][d] * entry[e][f] + entry[g][h] * entry[i][j])
        return (byte)(GF16.mul(m00, GF16.mul(m11, m22xm33_m23xm32) ^
            GF16.mul(m12, m21xm33_m23xm31) ^ GF16.mul(m13, m21xm32_m22xm31)) ^
            GF16.mul(m01, GF16.mul(m10, m22xm33_m23xm32) ^
                GF16.mul(m12, m20xm33_m23xm30) ^ GF16.mul(m13, m20xm32_m32xm30)) ^
            GF16.mul(m02, GF16.mul(m10, m21xm33_m23xm31) ^
                GF16.mul(m11, m20xm33_m23xm30) ^ GF16.mul(m13, m20xm31_m21xm30)) ^
            GF16.mul(m03, GF16.mul(m10, m21xm32_m22xm31) ^
                GF16.mul(m11, m20xm32_m32xm30) ^ GF16.mul(m12, m20xm31_m21xm30)));
    }

    private byte determinant5x5(byte[] m, int off)
    {
        byte m00 = m[off++];
        byte m01 = m[off++];
        byte m02 = m[off++];
        byte m03 = m[off++];
        byte m04 = m[off++];
        byte m10 = m[off++];
        byte m11 = m[off++];
        byte m12 = m[off++];
        byte m13 = m[off++];
        byte m14 = m[off++];
        byte m20 = m[off++];
        byte m21 = m[off++];
        byte m22 = m[off++];
        byte m23 = m[off++];
        byte m24 = m[off++];
        byte m30 = m[off++];
        byte m31 = m[off++];
        byte m32 = m[off++];
        byte m33 = m[off++];
        byte m34 = m[off++];
        byte m40 = m[off++];
        byte m41 = m[off++];
        byte m42 = m[off++];
        byte m43 = m[off++];
        byte m44 = m[off];

        byte m10xm21_m11xm20 = (byte)(GF16.mul(m10, m21) ^ GF16.mul(m11, m20));
        byte m10xm22_m12xm20 = (byte)(GF16.mul(m10, m22) ^ GF16.mul(m12, m20));
        byte m10xm23_m13xm20 = (byte)(GF16.mul(m10, m23) ^ GF16.mul(m13, m20));
        byte m10xm24_m14xm20 = (byte)(GF16.mul(m10, m24) ^ GF16.mul(m14, m20));
        byte m11xm22_m12xm21 = (byte)(GF16.mul(m11, m22) ^ GF16.mul(m12, m21));
        byte m11xm23_m13xm21 = (byte)(GF16.mul(m11, m23) ^ GF16.mul(m13, m21));
        byte m11xm24_m14xm21 = (byte)(GF16.mul(m11, m24) ^ GF16.mul(m14, m21));
        byte m12xm23_m13xm22 = (byte)(GF16.mul(m12, m23) ^ GF16.mul(m13, m22));
        byte m12xm24_m14xm22 = (byte)(GF16.mul(m12, m24) ^ GF16.mul(m14, m22));
        byte m13xm24_m14xm23 = (byte)(GF16.mul(m13, m24) ^ GF16.mul(m14, m23));

        byte result = (byte)GF16.mul(//determinant3x3(m, off, 0, 1, 2),
            (GF16.mul(m00, m11xm22_m12xm21) ^
                GF16.mul(m01, m10xm22_m12xm20) ^
                GF16.mul(m02, m10xm21_m11xm20)),
            (GF16.mul(m33, m44) ^ GF16.mul(m34, m43)));
        result ^= GF16.mul(//determinant3x3(m, off, 0, 1, 3),
            (GF16.mul(m00, m11xm23_m13xm21) ^
                GF16.mul(m01, m10xm23_m13xm20) ^
                GF16.mul(m03, m10xm21_m11xm20)),
            (GF16.mul(m32, m44) ^ GF16.mul(m34, m42)));
        result ^= GF16.mul(//determinant3x3(m, off, 0, 1, 4),
            (GF16.mul(m00, m11xm24_m14xm21) ^
                GF16.mul(m01, m10xm24_m14xm20) ^
                GF16.mul(m04, m10xm21_m11xm20)),
            (GF16.mul(m32, m43) ^ GF16.mul(m33, m42)));
        result ^= GF16.mul(//determinant3x3(m, off, 0, 2, 3),
            (GF16.mul(m00, m12xm23_m13xm22) ^
                GF16.mul(m02, m10xm23_m13xm20) ^
                GF16.mul(m03, m10xm22_m12xm20)),
            (GF16.mul(m31, m44) ^ GF16.mul(m34, m41)));
        result ^= GF16.mul(//determinant3x3(m, off, 0, 2, 4),
            (GF16.mul(m00, m12xm24_m14xm22) ^
                GF16.mul(m02, m10xm24_m14xm20) ^
                GF16.mul(m04, m10xm22_m12xm20)),
            (GF16.mul(m31, m43) ^ GF16.mul(m33, m41)));
        result ^= GF16.mul(//determinant3x3(m, off, 0, 3, 4),
            (GF16.mul(m00, m13xm24_m14xm23) ^
                GF16.mul(m03, m10xm24_m14xm20) ^
                GF16.mul(m04, m10xm23_m13xm20)),
            (GF16.mul(m31, m42) ^ GF16.mul(m32, m41)));
        result ^= GF16.mul(//determinant3x3(m, off, 1, 2, 3),
            (GF16.mul(m01, m12xm23_m13xm22) ^
                GF16.mul(m02, m11xm23_m13xm21) ^
                GF16.mul(m03, m11xm22_m12xm21)),
            (GF16.mul(m30, m44) ^ GF16.mul(m34, m40)));
        result ^= GF16.mul(//determinant3x3(m, off, 1, 2, 4),
            (GF16.mul(m01, m12xm24_m14xm22) ^
                GF16.mul(m02, m11xm24_m14xm21) ^
                GF16.mul(m04, m11xm22_m12xm21)),
            (GF16.mul(m30, m43) ^ GF16.mul(m33, m40)));
        result ^= GF16.mul(//determinant3x3(m, off, 1, 3, 4),
            (GF16.mul(m01, m13xm24_m14xm23) ^
                GF16.mul(m03, m11xm24_m14xm21) ^
                GF16.mul(m04, m11xm23_m13xm21)),
            (GF16.mul(m30, m42) ^ GF16.mul(m32, m40)));
        result ^= GF16.mul(//determinant3x3(m, off, 2, 3, 4),
            (GF16.mul(m02, m13xm24_m14xm23) ^
                GF16.mul(m03, m12xm24_m14xm22) ^
                GF16.mul(m04, m12xm23_m13xm22)),
            (GF16.mul(m30, m41) ^ GF16.mul(m31, m40)));
        return result;
    }

    private void generateASMatrixTo(byte[] target, int off, byte a)
    {
        for (int i = 0, ixl = off; i < l; i++, ixl += l)
        {
            for (int j = 0; j < l; j++)
            {
                byte coefficient = (byte)(8 - (i + j));
                if (l == 5 && i == 4 && j == 4)
                {
                    coefficient = 9;
                }
                target[ixl + j] ^= GF16.mul(coefficient, a);
            }
        }
    }

    private void genAFqS(byte[] c, int cOff, byte[] ptMatrix, int off)
    {
        // Initialize with be_aI
        be_aI(ptMatrix, off, c[cOff]);

        // Process middle terms
        for (int i = 1; i < l - 1; ++i)
        {
            gf16mScaleTo(S[i], c[cOff + i], ptMatrix, off);
        }

        // Handle last term with special case
        byte lastScalar = (byte)((c[cOff + l - 1] != 0) ? c[cOff + l - 1] : 16 - (c[cOff] + (c[cOff] == 0 ? 1 : 0)));
        gf16mScaleTo(S[l - 1], lastScalar, ptMatrix, off);
    }

    private void gf16mScaleTo(byte[] a, byte k, byte[] c, int cOff)
    {
        for (int i = 0, il = 0; i < l; ++i, il += l)
        {
            for (int j = 0; j < l; ++j)
            {
                c[il + j + cOff] ^= GF16.mul(a[il + j], k);
            }
        }
    }

    private void genF(MapGroup2 map2, MapGroup1 map1, byte[][][] T12)
    {
        // Copy initial matrices
        copy4DMatrix(map1.p11, map2.f11, m, v, v, lsq);
        copy4DMatrix(map1.p12, map2.f12, m, v, o, lsq);
        copy4DMatrix(map1.p21, map2.f21, m, o, v, lsq);

        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < v; j++)
            {
                for (int k = 0; k < o; k++)
                {
                    for (int index = 0; index < v; index++)
                    {
                        GF16Utils.gf16mMulToTo(map1.p11[i][j][index], T12[index][k], map1.p11[i][index][j], map2.f12[i][j][k], map2.f21[i][k][j], l);
                    }
                }
            }
        }
    }

    private static void copy4DMatrix(byte[][][][] src, byte[][][][] dest, int dim1, int dim2, int dim3, int lsq)
    {
        for (int i = 0; i < dim1; i++)
        {
            for (int j = 0; j < dim2; j++)
            {
                for (int k = 0; k < dim3; k++)
                {
                    System.arraycopy(src[i][j][k], 0, dest[i][j][k], 0, lsq);
                }
            }
        }
    }

    public void genP22(byte[] outP22, int outOff, byte[][][] T12, byte[][][][] P21, byte[][][][] F12)
    {
        // Initialize P22 with zeros
        int oxlsq = o * lsq;
        int oxoxlsq = oxlsq * o;
        byte[] P22 = new byte[m * oxoxlsq];

        for (int i = 0, ixoxolsq = 0; i < m; i++, ixoxolsq += oxoxlsq)
        {
            for (int j = 0, jxoxlsq = ixoxolsq; j < o; j++, jxoxlsq += oxlsq)
            {
                for (int k = 0, kxlsq = jxoxlsq; k < o; k++, kxlsq += lsq)
                {
                    for (int index = 0; index < v; index++)
                    {
                        //  P22[i][j][k] ^= (T12[index][j] * F12[i][index][k]) ^ (P21[i][j][index] * T12[index][k])
                        GF16Utils.gf16mMulTo(T12[index][j], F12[i][index][k], P21[i][j][index], T12[index][k], P22, kxlsq, l);
                    }
                }
            }
        }

        // Convert GF16 elements to packed bytes
        GF16.encode(P22, outP22, outOff, P22.length);
    }

    private void genSeedsAndT12(byte[][][] T12, byte[] skSeed)
    {
        int gf16sPrngPrivate = v * o * l;
        int bytesPrngPrivate = (gf16sPrngPrivate + 1) >>> 1;
        byte[] prngOutput = new byte[bytesPrngPrivate];

        // Generate PRNG output using SHAKE-256
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(skSeed, 0, skSeed.length);
        shake.doFinal(prngOutput, 0, prngOutput.length);

        // Convert bytes to GF16 array
        byte[] gf16PrngOutput = new byte[gf16sPrngPrivate];
        GF16.decode(prngOutput, gf16PrngOutput, gf16sPrngPrivate);

        // Generate T12 matrices
        int ptArray = 0;
        for (int j = 0; j < v; j++)
        {
            for (int k = 0; k < o; k++)
            {
                //gen_a_FqS_ct
                genAFqSCT(gf16PrngOutput, ptArray, T12[j][k]);
                ptArray += l;
            }
        }
    }

    public void genABQP(MapGroup1 map1, byte[] pkSeed)
    {
        int gf16sPrngPublic = lsq * (2 * m * alpha + m * (n * n - m * m)) + l * 2 * m * alpha;
        byte[] qTemp = new byte[(m * alpha * l) << 1];
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
            // SICBlockCipher implements CTR mode for AES.
            CTRModeCipher ctrCipher = SICBlockCipher.newInstance(AESEngine.newInstance());
            ctrCipher.init(true, new ParametersWithIV(new KeyParameter(pkSeed), iv));
            int blockSize = ctrCipher.getBlockSize(); // typically 16 bytes
            byte[] zeroBlock = new byte[blockSize];     // block of zeros

            int offset = 0;
            // Process full blocks
            while (offset + blockSize <= prngOutput.length)
            {
                ctrCipher.processBlock(zeroBlock, 0, prngOutput, offset);
                offset += blockSize;
            }
            // Process any remaining partial block.
            if (offset < prngOutput.length)
            {
                ctrCipher.processBlock(zeroBlock, 0, zeroBlock, 0);
                int remaining = prngOutput.length - offset;
                System.arraycopy(zeroBlock, 0, prngOutput, offset, remaining);
            }
        }
        if ((lsq & 1) == 0)
        {
            map1.decode(prngOutput, (gf16sPrngPublic - qTemp.length) >> 1, l >= 4);
        }
        else
        {
            byte[] temp = new byte[gf16sPrngPublic - qTemp.length];
            GF16.decode(prngOutput, temp, temp.length);
            map1.fill(temp, l >= 4);
        }
        if (l >= 4)
        {
            GF16.decode(prngOutput, (gf16sPrngPublic - qTemp.length) >> 1, qTemp, 0, qTemp.length);
            int ptArray = 0;
            // Post-processing for invertible matrices
            int offset = m * alpha * l;
            for (int pi = 0; pi < m; ++pi)
            {
                for (int a = 0; a < alpha; ++a)
                {
                    makeInvertibleByAddingAS(map1.aAlpha[pi][a], 0);
                    makeInvertibleByAddingAS(map1.bAlpha[pi][a], 0);
                    genAFqS(qTemp, ptArray, map1.qAlpha1[pi][a], 0);
                    genAFqS(qTemp, offset, map1.qAlpha2[pi][a], 0);
                    ptArray += l;
                    offset += l;
                }
            }
        }
        else
        {
            int oxalphaxlsq = o * alpha * lsq;
            byte[] fixedAbq = (byte[])fixedAbqSet.get(Integers.valueOf(o));
            MapGroup1.fillAlpha(fixedAbq, 0, map1.aAlpha, m * oxalphaxlsq);
            MapGroup1.fillAlpha(fixedAbq, oxalphaxlsq, map1.bAlpha, (m - 1) * oxalphaxlsq);
            MapGroup1.fillAlpha(fixedAbq, oxalphaxlsq * 2, map1.qAlpha1, (m - 2) * oxalphaxlsq);
            MapGroup1.fillAlpha(fixedAbq, oxalphaxlsq * 3, map1.qAlpha2, (m - 3) * oxalphaxlsq);
        }
    }

    public void genMap1T12Map2(SnovaKeyElements keyElements, byte[] pkSeed, byte[] skSeed)
    {
        // Generate T12 matrix
        genSeedsAndT12(keyElements.T12, skSeed);

        // Generate map components
        genABQP(keyElements.map1, pkSeed);

        // Generate F matrices
        genF(keyElements.map2, keyElements.map1, keyElements.T12);
    }
}
