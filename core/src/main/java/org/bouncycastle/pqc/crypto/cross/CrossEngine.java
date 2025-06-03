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
            subBuffer |= ((long)(CSPRNG_buffer[i] & 0xFF)) << 8 * i;
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

            byte elementLong = (byte)(subBuffer & mask);
            if (elementLong < z)
            {
                res[placed] = elementLong;
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
        int bufferSize = roundUp(params.getBitsMFzCtRng(), 8) / 8;
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
        return fzRedSingle(fzRedSingle(x));
    }

    public static long restrToVal(long x)
    {
        return (RESTR_G_TABLE >>> (8 * x));
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
            res[i - k] = (byte)restrToVal(e[i]);
        }

        // Accumulate matrix-vector product
        for (int i = 0; i < k; i++)
        {
            long e_val = restrToVal(e[i]);
            for (int j = 0; j < nMinusK; j++)
            {
                short current = (short)(res[j] & 0xFF);
                short product = (short)((short)e_val * (short)(V_tr[i][j] & 0xFF));
                short sum = (short)(current + product);
                int reduced = (sum & 0x7F) + (sum >>> 7);
                reduced = (reduced & 0x7F) + (reduced >>> 7);
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
            res[i - k] = (byte)restrToVal(e[i]);
        }

        // Accumulate matrix-vector product
        for (int i = 0; i < k; i++)
        {
            short e_val = (short)restrToVal(e[i]);
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


    // Normalizes a syndrome vector of finite field elements
    public static void fpDzNormSynd(byte[] v, CrossParameters params)
    {
        int p = params.getP();
        if (p == 127)
        {
            for (int i = 0; i < v.length; i++)
            {
                int val = v[i] & 0xFF;
                v[i] = (byte)((val + ((val + 1) >> 7)) & 0x7F);
            }
        }
        // For P=509, no normalization is needed (identity operation)
    }

    // Packs a syndrome vector of finite field elements into a byte array
    public static void packFpSyn(byte[] out, byte[] in, CrossParameters params)
    {
        int p = params.getP();
        if (p == 127)
        {
            genericPack7Bit(out, in);
        }
        else if (p == 509)
        {
            // Convert byte[] to short[] for 9-bit packing
            short[] inShort = new short[in.length];
            for (int i = 0; i < in.length; i++)
            {
                inShort[i] = (short)(in[i] & 0xFF);
            }
            genericPack9Bit(out, inShort);
        }
        else
        {
            throw new IllegalArgumentException("Unsupported modulus: " + p);
        }
    }

    // Packs 7-bit elements (for P=127)
    private static void genericPack7Bit(byte[] out, byte[] in)
    {
        int inlen = in.length;
        int fullBlocks = inlen / 8;
        int i;

        for (i = 0; i < fullBlocks; i++)
        {
            int baseIn = i * 8;
            int baseOut = i * 7;

            out[baseOut] = (byte)(in[baseIn] | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 1] = (byte)(((in[baseIn + 1] & 0xFF) >>> 1) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 2] = (byte)(((in[baseIn + 2] & 0xFF) >>> 2) | ((in[baseIn + 3] & 0x07) << 5));
            out[baseOut + 3] = (byte)(((in[baseIn + 3] & 0xFF) >>> 3) | ((in[baseIn + 4] & 0x0F) << 4));
            out[baseOut + 4] = (byte)(((in[baseIn + 4] & 0xFF) >>> 4) | ((in[baseIn + 5] & 0x1F) << 3));
            out[baseOut + 5] = (byte)(((in[baseIn + 5] & 0xFF) >>> 5) | ((in[baseIn + 6] & 0x3F) << 2));
            out[baseOut + 6] = (byte)(((in[baseIn + 6] & 0xFF) >>> 6) | ((in[baseIn + 7] & 0x7F) << 1));
        }

        int remaining = inlen % 8;
        int baseIn = i * 8;
        int baseOut = i * 7;

        switch (remaining)
        {
        case 1:
            out[baseOut] = in[baseIn];
            break;
        case 2:
            out[baseOut] = (byte)(in[baseIn] | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 1] = (byte)((in[baseIn + 1] & 0xFF) >>> 1);
            break;
        case 3:
            out[baseOut] = (byte)(in[baseIn] | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 1] = (byte)(((in[baseIn + 1] & 0xFF) >>> 1) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 2] = (byte)((in[baseIn + 2] & 0xFF) >>> 2);
            break;
        case 4:
            out[baseOut] = (byte)(in[baseIn] | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 1] = (byte)(((in[baseIn + 1] & 0xFF) >>> 1) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 2] = (byte)(((in[baseIn + 2] & 0xFF) >>> 2) | ((in[baseIn + 3] & 0x07) << 5));
            out[baseOut + 3] = (byte)((in[baseIn + 3] & 0xFF) >>> 3);
            break;
        case 5:
            out[baseOut] = (byte)(in[baseIn] | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 1] = (byte)(((in[baseIn + 1] & 0xFF) >>> 1) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 2] = (byte)(((in[baseIn + 2] & 0xFF) >>> 2) | ((in[baseIn + 3] & 0x07) << 5));
            out[baseOut + 3] = (byte)(((in[baseIn + 3] & 0xFF) >>> 3) | ((in[baseIn + 4] & 0x0F) << 4));
            out[baseOut + 4] = (byte)((in[baseIn + 4] & 0xFF) >>> 4);
            break;
        case 6:
            out[baseOut] = (byte)(in[baseIn] | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 1] = (byte)(((in[baseIn + 1] & 0xFF) >>> 1) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 2] = (byte)(((in[baseIn + 2] & 0xFF) >>> 2) | ((in[baseIn + 3] & 0x07) << 5));
            out[baseOut + 3] = (byte)(((in[baseIn + 3] & 0xFF) >>> 3) | ((in[baseIn + 4] & 0x0F) << 4));
            out[baseOut + 4] = (byte)(((in[baseIn + 4] & 0xFF) >>> 4) | ((in[baseIn + 5] & 0x1F) << 3));
            out[baseOut + 5] = (byte)((in[baseIn + 5] & 0xFF) >>> 5);
            break;
        case 7:
            out[baseOut] = (byte)(in[baseIn] | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 1] = (byte)(((in[baseIn + 1] & 0xFF) >>> 1) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 2] = (byte)(((in[baseIn + 2] & 0xFF) >>> 2) | ((in[baseIn + 3] & 0x07) << 5));
            out[baseOut + 3] = (byte)(((in[baseIn + 3] & 0xFF) >>> 3) | ((in[baseIn + 4] & 0x0F) << 4));
            out[baseOut + 4] = (byte)(((in[baseIn + 4] & 0xFF) >>> 4) | ((in[baseIn + 5] & 0x1F) << 3));
            out[baseOut + 5] = (byte)(((in[baseIn + 5] & 0xFF) >>> 5) | ((in[baseIn + 6] & 0x3F) << 2));
            out[baseOut + 6] = (byte)((in[baseIn + 6] & 0xFF) >>> 6);
            break;
        }
    }

    // Packs 9-bit elements (for P=509)
    private static void genericPack9Bit(byte[] out, short[] in)
    {
        int inlen = in.length;
        int fullBlocks = inlen / 8;
        int i;

        for (i = 0; i < fullBlocks; i++)
        {
            int baseIn = i * 8;
            int baseOut = i * 9;

            out[baseOut] = (byte)in[baseIn];
            out[baseOut + 1] = (byte)((in[baseIn] >>> 8) | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 2] = (byte)((in[baseIn + 1] >>> 7) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 3] = (byte)((in[baseIn + 2] >>> 6) | ((in[baseIn + 3] & 0x07) << 5));
            out[baseOut + 4] = (byte)((in[baseIn + 3] >>> 5) | ((in[baseIn + 4] & 0x0F) << 4));
            out[baseOut + 5] = (byte)((in[baseIn + 4] >>> 4) | ((in[baseIn + 5] & 0x1F) << 3));
            out[baseOut + 6] = (byte)((in[baseIn + 5] >>> 3) | ((in[baseIn + 6] & 0x3F) << 2));
            out[baseOut + 7] = (byte)((in[baseIn + 6] >>> 2) | ((in[baseIn + 7] & 0x7F) << 1));
            out[baseOut + 8] = (byte)(in[baseIn + 7] >>> 1);
        }

        int remaining = inlen % 8;
        int baseIn = i * 8;
        int baseOut = i * 9;

        switch (remaining)
        {
        case 1:
            out[baseOut] = (byte)in[baseIn];
            out[baseOut + 1] = (byte)(in[baseIn] >>> 8);
            break;
        case 2:
            out[baseOut] = (byte)in[baseIn];
            out[baseOut + 1] = (byte)((in[baseIn] >>> 8) | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 2] = (byte)(in[baseIn + 1] >>> 7);
            break;
        case 3:
            out[baseOut] = (byte)in[baseIn];
            out[baseOut + 1] = (byte)((in[baseIn] >>> 8) | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 2] = (byte)((in[baseIn + 1] >>> 7) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 3] = (byte)(in[baseIn + 2] >>> 6);
            break;
        case 4:
            out[baseOut] = (byte)in[baseIn];
            out[baseOut + 1] = (byte)((in[baseIn] >>> 8) | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 2] = (byte)((in[baseIn + 1] >>> 7) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 3] = (byte)((in[baseIn + 2] >>> 6) | ((in[baseIn + 3] & 0x07) << 5));
            out[baseOut + 4] = (byte)(in[baseIn + 3] >>> 5);
            break;
        case 5:
            out[baseOut] = (byte)in[baseIn];
            out[baseOut + 1] = (byte)((in[baseIn] >>> 8) | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 2] = (byte)((in[baseIn + 1] >>> 7) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 3] = (byte)((in[baseIn + 2] >>> 6) | ((in[baseIn + 3] & 0x07) << 5));
            out[baseOut + 4] = (byte)((in[baseIn + 3] >>> 5) | ((in[baseIn + 4] & 0x0F) << 4));
            out[baseOut + 5] = (byte)(in[baseIn + 4] >>> 4);
            break;
        case 6:
            out[baseOut] = (byte)in[baseIn];
            out[baseOut + 1] = (byte)((in[baseIn] >>> 8) | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 2] = (byte)((in[baseIn + 1] >>> 7) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 3] = (byte)((in[baseIn + 2] >>> 6) | ((in[baseIn + 3] & 0x07) << 5));
            out[baseOut + 4] = (byte)((in[baseIn + 3] >>> 5) | ((in[baseIn + 4] & 0x0F) << 4));
            out[baseOut + 5] = (byte)((in[baseIn + 4] >>> 4) | ((in[baseIn + 5] & 0x1F) << 3));
            out[baseOut + 6] = (byte)(in[baseIn + 5] >>> 3);
            break;
        case 7:
            out[baseOut] = (byte)in[baseIn];
            out[baseOut + 1] = (byte)((in[baseIn] >>> 8) | ((in[baseIn + 1] & 0x01) << 7));
            out[baseOut + 2] = (byte)((in[baseIn + 1] >>> 7) | ((in[baseIn + 2] & 0x03) << 6));
            out[baseOut + 3] = (byte)((in[baseIn + 2] >>> 6) | ((in[baseIn + 3] & 0x07) << 5));
            out[baseOut + 4] = (byte)((in[baseIn + 3] >>> 5) | ((in[baseIn + 4] & 0x0F) << 4));
            out[baseOut + 5] = (byte)((in[baseIn + 4] >>> 4) | ((in[baseIn + 5] & 0x1F) << 3));
            out[baseOut + 6] = (byte)((in[baseIn + 5] >>> 3) | ((in[baseIn + 6] & 0x3F) << 2));
            out[baseOut + 7] = (byte)(in[baseIn + 6] >>> 2);
            break;
        }
    }

}
