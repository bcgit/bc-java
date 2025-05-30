package org.bouncycastle.pqc.crypto.cross;

import org.bouncycastle.crypto.digests.SHAKEDigest;

class CrossEngine
{
    // Precomputed constants for exponentiation
    private static final int RESTR_G_GEN_1 = 16;
    private static final int RESTR_G_GEN_2 = 256;
    private static final int RESTR_G_GEN_4 = 384;
    private static final int RESTR_G_GEN_8 = 355;
    private static final int RESTR_G_GEN_16 = 302;
    private static final int RESTR_G_GEN_32 = 93;
    private static final int RESTR_G_GEN_64 = 505;
    private static final long REDUCTION_CONST = 2160140723L;
    private static final long RESTR_G_TABLE = 0x0140201008040201L;
    private final SHAKEDigest digest;
    private final int securityLevel;

    public CrossEngine(int securityLevel)
    {
        this.securityLevel = securityLevel;
        if (securityLevel <= 128)
        {
            digest = new SHAKEDigest(128);
        }
        else
        {
            digest = new SHAKEDigest(256);
        }
    }

    public void init(byte[] seed, int seedLen, int dsc)
    {
        init(seed, 0, seedLen, dsc);
    }

    public void init(byte[] seed, int seedOff, int seedLen, int dsc)
    {
        digest.reset();
        digest.update(seed, seedOff, seedLen);
        byte[] dscBytes = new byte[]{
            (byte)(dsc & 0xFF),
            (byte)((dsc >> 8) & 0xFF)
        };
        digest.update(dscBytes, 0, 2);
    }

    public void randomBytes(byte[] out, int outLen)
    {
        randomBytes(out, 0, outLen);
    }

    public void randomBytes(byte[] out, int outOff, int outLen)
    {
        digest.doOutput(out, outOff, outLen);
    }

    // Helper function to round up to nearest multiple
    public static int roundUp(int amount, int roundAmt)
    {
        return ((amount + roundAmt - 1) / roundAmt) * roundAmt;
    }

    // Calculate bits needed to represent a number
    public static int bitsToRepresent(int n)
    {
        if (n == 0)
        {
            return 1;
        }
        return 32 - Integer.numberOfLeadingZeros(n);
    }

    // Expand public key for RSDP variant
    public void expandPk(CrossParameters params, byte[][] V_tr, byte[] seedPk)
    {
        int dsc = 0 + (3 * params.getT() + 2); // CSPRNG_DOMAIN_SEP_CONST is 0
        init(seedPk, seedPk.length, dsc);
        csprngFpMat(V_tr, params);
    }

    // Expand public key for RSDPG variant
    public void expandPk(CrossParameters params, short[][] V_tr, byte[][] W_mat, byte[] seedPk)
    {
        int dsc = 0 + (3 * params.getT() + 2); // CSPRNG_DOMAIN_SEP_CONST is 0
        init(seedPk, seedPk.length, dsc);
        csprngFzMat(W_mat, params);
        csprngFpMat(V_tr, params);
    }

    // Generate FP matrix (8-bit version)
    private void csprngFpMat(byte[][] res, CrossParameters params)
    {
        int rows = params.getK();
        int cols = params.getN() - params.getK();
        int total = rows * cols;
        int bitsForP = bitsToRepresent(params.getP() - 1);
        long mask = (1L << bitsForP) - 1;
        int bufferSize = roundUp(params.getBitsVCtRng(), 8) / 8;
        byte[] CSPRNG_buffer = new byte[bufferSize];
        randomBytes(CSPRNG_buffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(CSPRNG_buffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < total)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(CSPRNG_buffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < params.getP())
            {
                int row = placed / cols;
                int col = placed % cols;
                res[row][col] = (byte)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForP; // Unsigned right shift
            bitsInSubBuf -= bitsForP;
        }
    }

    // Generate FP matrix (16-bit version)
    private void csprngFpMat(short[][] res, CrossParameters params)
    {
        int rows = params.getK();
        int cols = params.getN() - params.getK();
        int total = rows * cols;
        int bitsForP = bitsToRepresent(params.getP() - 1);
        long mask = (1L << bitsForP) - 1;
        int bufferSize = roundUp(params.getBitsVCtRng(), 8) / 8;
        byte[] CSPRNG_buffer = new byte[bufferSize];
        randomBytes(CSPRNG_buffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(CSPRNG_buffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < total)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(CSPRNG_buffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < params.getP())
            {
                int row = placed / cols;
                int col = placed % cols;
                res[row][col] = (short)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForP; // Unsigned right shift
            bitsInSubBuf -= bitsForP;
        }
    }

    // Generate FZ matrix (8-bit version)
    private void csprngFzMat(byte[][] res, CrossParameters params)
    {
        int rows = params.getM();
        int cols = params.getN() - params.getM();
        int total = rows * cols;
        int bitsForZ = bitsToRepresent(params.getZ() - 1);
        long mask = (1L << bitsForZ) - 1;
        int bufferSize = roundUp(params.getBitsWCtRng(), 8) / 8;
        byte[] CSPRNG_buffer = new byte[bufferSize];
        randomBytes(CSPRNG_buffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(CSPRNG_buffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < total)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(CSPRNG_buffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < params.getZ())
            {
                int row = placed / cols;
                int col = placed % cols;
                res[row][col] = (byte)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForZ; // Unsigned right shift
            bitsInSubBuf -= bitsForZ;
        }
    }

    // Generate FZ vector for RSDP variant
    public void csprngFzVec(byte[] res, CrossParameters params)
    {
        int n = params.getN();
        int z = params.getZ();
        int bitsForZ = bitsToRepresent(z - 1);
        long mask = (1L << bitsForZ) - 1;
        int bufferSize = roundUp(params.getBitsNFzCtRng(), 8) / 8;
        byte[] CSPRNG_buffer = new byte[bufferSize];
        randomBytes(CSPRNG_buffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(CSPRNG_buffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < n)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(CSPRNG_buffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < z)
            {
                res[placed] = (byte)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForZ; // Unsigned right shift
            bitsInSubBuf -= bitsForZ;
        }
    }

    // Generate FZ vector for RSDPG variant
    public void csprngFzInfW(byte[] res, CrossParameters params)
    {
        int m = params.getM();
        int z = params.getZ();
        int bitsForZ = bitsToRepresent(z - 1);
        long mask = (1L << bitsForZ) - 1;
        //TODO: BitsMFzCtRng
        int bufferSize = 0;//roundUp(params.getBitsMFzCtRng(), 8) / 8;
        byte[] CSPRNG_buffer = new byte[bufferSize];
        randomBytes(CSPRNG_buffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(CSPRNG_buffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < m)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(CSPRNG_buffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < z)
            {
                res[placed] = (byte)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForZ; // Unsigned right shift
            bitsInSubBuf -= bitsForZ;
        }
    }

    // Reduction methods for RSDPG (Z=127)
    public static int fzRedSingle(int x)
    {
        return (x & 0x7F) + (x >>> 7);
    }

    public static int fpRedSingle(int x)
    {
        long xLong = x & 0xFFFFFFFFL; // Treat as unsigned
        long quotient = (xLong * REDUCTION_CONST) >>> 40;
        long result = xLong - quotient * 509;
        if (result < 0)
        {
            result += 509;
        }
        else if (result >= 509)
        {
            result -= 509;
        }
        return (int)result;
    }

    public static int fzRedDouble(int x)
    {
        return fzRedSingle(fzRedSingle(x));
    }

    public static int fzDoubleZeroNorm(int x)
    {
        return (x + ((x + 1) >>> 7)) & 0x7F;
    }

    // Matrix-vector multiplication for RSDPG
    public static void fzInfWByFzMatrix(byte[] res, byte[] e, byte[][] W_mat, CrossParameters params)
    {
        int n = params.getN();
        int m = params.getM();
        int nMinusM = n - m;

        // Initialize result: first (n-m) elements = 0, last m elements = e
        for (int j = 0; j < nMinusM; j++)
        {
            res[j] = 0;
        }
        System.arraycopy(e, 0, res, nMinusM, m);

        // Compute matrix-vector product
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < nMinusM; j++)
            {
                // Convert bytes to unsigned integers
                int eVal = e[i] & 0xFF;
                int wVal = W_mat[i][j] & 0xFF;
                int current = res[j] & 0xFF;

                // Compute product and sum
                int product = eVal * wVal;
                int sum = current + product;

                // Apply double reduction
                int reduced = fzRedDouble(sum);

                // Store result
                res[j] = (byte)reduced;
            }
        }
    }

    // Vector normalization
    public static void fzDzNormN(byte[] v)
    {
        for (int i = 0; i < v.length; i++)
        {
            int val = v[i] & 0xFF;
            v[i] = (byte)fzDoubleZeroNorm(val);
        }
    }

    public static int fpRedDouble(int x)
    {
        return fpRedSingle(fpRedSingle(x));
    }

    public static byte restrToVal(byte x)
    {
        int shift = 8 * (x & 0x07); // x is in [0,6]
        return (byte)((RESTR_G_TABLE >>> shift) & 0xFF);
    }

//    public static short restrToVal(byte x)
//    {
//        int xInt = x & 0xFF; // Convert to unsigned integer
//        int res1 = cmov((xInt >> 0) & 1, RESTR_G_GEN_1, 1);
//        int res2 = cmov((xInt >> 1) & 1, RESTR_G_GEN_2, 1);
//        int res3 = cmov((xInt >> 2) & 1, RESTR_G_GEN_4, 1);
//        int res4 = cmov((xInt >> 3) & 1, RESTR_G_GEN_8, 1);
//        int res5 = cmov((xInt >> 4) & 1, RESTR_G_GEN_16, 1);
//        int res6 = cmov((xInt >> 5) & 1, RESTR_G_GEN_32, 1);
//        int res7 = cmov((xInt >> 6) & 1, RESTR_G_GEN_64, 1);
//
//        // Multiply pairs with reduction
//        int prod1 = fpRedSingle(res1 * res2);
//        int prod2 = fpRedSingle(res3 * res4);
//        int prod3 = fpRedSingle(res5 * res6);
//
//        // Combine results
//        int prod12 = fpRedSingle(prod1 * prod2);
//        int prod123 = fpRedSingle(prod12 * prod3);
//        int finalProd = fpRedSingle(prod123 * res7);
//
//        return (short)finalProd;
//    }

    public static void restrVecByFpMatrix(byte[] res, byte[] e, byte[][] V_tr, CrossParameters params)
    {
        int n = params.getN();
        int k = params.getK();
        int nMinusK = n - k;

        // Initialize res with restricted values from the last n-k elements of e
        for (int i = k; i < n; i++)
        {
            res[i - k] = restrToVal(e[i]);
        }

        // Accumulate matrix-vector product
        for (int i = 0; i < k; i++)
        {
            byte e_val = restrToVal(e[i]);
            for (int j = 0; j < nMinusK; j++)
            {
                int current = res[j] & 0xFF;
                int product = (e_val & 0xFF) * (V_tr[i][j] & 0xFF);
                int sum = current + product;
                int reduced = fpRedDouble(sum);
                res[j] = (byte)reduced;
            }
        }
    }

    // Conditional move for constant-time operations
    private static int cmov(int bit, int trueVal, int falseVal)
    {
        int mask = -bit; // mask = 0xFFFFFFFF if bit=1, 0 if bit=0
        return (trueVal & mask) | (falseVal & ~mask);
    }


    public static void restrVecByFpMatrix(short[] res, byte[] e, short[][] V_tr, CrossParameters params)
    {
        int n = params.getN();
        int k = params.getK();
        int nMinusK = n - k;

        // Initialize res with restricted values from the last n-k elements of e
        for (int i = k; i < n; i++)
        {
            res[i - k] = restrToVal(e[i]);
        }

        // Accumulate matrix-vector product
        for (int i = 0; i < k; i++)
        {
            short e_val = restrToVal(e[i]);
            for (int j = 0; j < nMinusK; j++)
            {
                int current = res[j] & 0xFFFF;
                int product = (e_val & 0xFFFF) * (V_tr[i][j] & 0xFFFF);
                int sum = current + product;
                int reduced = fpRedSingle(sum);
                res[j] = (short)reduced;
            }
        }
    }
}
