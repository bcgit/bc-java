package org.bouncycastle.pqc.crypto.cross;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

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
    static final int CSPRNG_DOMAIN_SEP_CONST = 0;
    static final int HASH_DOMAIN_SEP_CONST = 32768;

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

    public static byte restrToVal(long x)
    {
        return (byte)(RESTR_G_TABLE >>> (8 * x));
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
            byte e_val = restrToVal(e[i] & 0xFFL);
            for (int j = 0; j < nMinusK; j++)
            {
                int current = (res[j] & 0xFF);
                int product = (e_val * (V_tr[i][j] & 0xFF));
                int sum = current + product;
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

    private static void genericPack7Bit(byte[] out, int outOff, byte[] in)
    {
        int inlen = in.length;
        int fullBlocks = inlen / 8;
        int i;

        for (i = 0; i < fullBlocks; i++)
        {
            int baseIn = i * 8;
            int baseOut = outOff + i * 7;

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
        int baseOut = outOff + i * 7;

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

    private static void genericPack9Bit(byte[] out, int outOff, short[] in)
    {
        int inlen = in.length;
        int fullBlocks = inlen / 8;
        int i;

        for (i = 0; i < fullBlocks; i++)
        {
            int baseIn = i * 8;
            int baseOut = outOff + i * 9;

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
        int baseOut = outOff + i * 9;

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

    public void expandSk(CrossParameters params, byte[] seedSk,
                         byte[] e_bar, byte[] e_G_bar,
                         byte[][] V_tr, byte[][] W_mat)
    {
        int keypairSeedLen = params.getKeypairSeedLengthBytes();
        byte[][] seedESeedPk = new byte[2][keypairSeedLen];

        // Step 1: Initialize CSPRNG for secret key expansion
        int dscCsprngSeedSk = (3 * params.getT() + 1); // CSPRNG_DOMAIN_SEP_CONST = 0
        init(seedSk, seedSk.length, dscCsprngSeedSk);

        // Step 2: Generate seeds for error vector and public key
        randomBytes(seedESeedPk[0], keypairSeedLen);
        randomBytes(seedESeedPk[1], keypairSeedLen);

        if (params.getP() == 127)
        { // RSDP
            // Step 3: Expand public key matrix
            expandPk(params, V_tr, seedESeedPk[1]);

            // Step 4: Generate error vector
            int dscCsprngSeedE = (3 * params.getT() + 3);

            init(seedESeedPk[0], seedESeedPk[0].length, dscCsprngSeedE);
            csprngFzVec(e_bar, params);
        }
        else if (params.getP() == 509)
        { // RSDPG
            // Step 3: Expand public key matrices
            short[][] V_tr_short = new short[params.getK()][params.getN() - params.getK()];
            expandPk(params, V_tr_short, W_mat, seedESeedPk[1]);

            // Convert to byte arrays for consistency
            for (int i = 0; i < V_tr_short.length; i++)
            {
                for (int j = 0; j < V_tr_short[i].length; j++)
                {
                    V_tr[i][j] = (byte)V_tr_short[i][j];
                }
            }

            // Step 4: Generate error information word
            int dscCsprngSeedE = (3 * params.getT() + 3);

            init(seedESeedPk[0], seedESeedPk[0].length, dscCsprngSeedE);
            csprngFzInfW(e_G_bar, params);

            // Step 5: Compute full error vector
            fzInfWByFzMatrix(e_bar, e_G_bar, W_mat, params);

            // Step 6: Normalize error vector
            fzDzNormN(e_bar);
        }
    }

    // Vector normalization for RSDP (Z=7)
    public static void fzDzNormRSDP(byte[] v)
    {
        for (int i = 0; i < v.length; i++)
        {
            int val = v[i] & 0xFF;
            v[i] = (byte)((val + ((val + 1) >> 3)) & 0x07);
        }
    }

    // Vector normalization for RSDPG (Z=127)
    public static void fzDzNormRSDPG(byte[] v)
    {
        for (int i = 0; i < v.length; i++)
        {
            int val = v[i] & 0xFF;
            v[i] = (byte)((val + ((val + 1) >> 7)) & 0x7F);
        }
    }

    // For SPEED variant (NO_TREES)
    public int seedLeavesSpeed(CrossParameters params, byte[] roundsSeeds,
                               byte[] rootSeed, byte[] salt)
    {
        int seedLen = params.getSeedLengthBytes();
        int saltLen = params.getSaltLengthBytes();
        int t = params.getT();

        // 1. Prepare CSPRNG input: root_seed || salt
        byte[] csprngInput = new byte[seedLen + saltLen];
        System.arraycopy(rootSeed, 0, csprngInput, 0, seedLen);
        System.arraycopy(salt, 0, csprngInput, seedLen, saltLen);

        // 2. Initialize CSPRNG and generate quad seeds
        init(csprngInput, csprngInput.length, 0); // Domain sep = 0
        byte[] quadSeed = new byte[4 * seedLen];
        randomBytes(quadSeed, quadSeed.length);

        // 3. Determine remainders based on T mod 4
        int r = t % 4;
        int[] remainders = new int[4];
        remainders[0] = (r > 0) ? 1 : 0;
        remainders[1] = (r > 1) ? 1 : 0;
        remainders[2] = (r > 2) ? 1 : 0;

        // 4. Generate seeds in 4 groups
        int offset = 0;
        int dscCounter = 0;
        for (int i = 0; i < 4; i++)
        {
            // Prepare input for group CSPRNG: seed_i || salt
            byte[] groupInput = new byte[seedLen + saltLen];
            System.arraycopy(quadSeed, i * seedLen, groupInput, 0, seedLen);
            System.arraycopy(salt, 0, groupInput, seedLen, saltLen);

            // Initialize group CSPRNG
            dscCounter++;
            init(groupInput, groupInput.length, dscCounter);

            // Calculate number of seeds for this group
            int groupSeeds = (t / 4) + remainders[i];
            int startPos = ((t / 4) * i + offset) * seedLen;

            // Generate seeds directly into output array
            randomBytes(roundsSeeds, startPos, groupSeeds * seedLen);
            offset += remainders[i];
        }
        return t;
    }

    // For BALANCED/SMALL variants (with seed trees)
    public static void seedLeavesTree(CrossParameters params, byte[] roundsSeeds, byte[] seedTree)
    {
        int seedLen = params.getSeedLengthBytes();
        int cnt = 0;

        for (int i = 0; i < params.getTreeSubroots(); i++)
        {
            int consecutive = params.getTreeConsecutiveLeaves()[i];
            int startIndex = params.getTreeLeavesStartIndices()[i];

            for (int j = 0; j < consecutive; j++)
            {
                int srcPos = (startIndex + j) * seedLen;
                int destPos = cnt * seedLen;
                System.arraycopy(seedTree, srcPos, roundsSeeds, destPos, seedLen);
                cnt++;
            }
        }
    }

    public static byte fzRedSingle(byte x)
    {
        int val = x & 0xFF;
        return (byte)((val & 0x7F) + (val >>> 7));
    }

    public static byte fzRedDouble(byte x)
    {
        return fzRedSingle(fzRedSingle(x));
    }

    public static byte fzRedOpposite(byte x)
    {
        return (byte)(x ^ 0x7F);
    }

    public static byte fzDoubleZeroNorm(byte x)
    {
        int val = x & 0xFF;
        return (byte)((val + ((val + 1) >> 7)) & 0x7F);
    }

    // Vector subtraction: res = a - b (mod Z)
    public static void fzVecSubM(byte[] res, byte[] a, byte[] b, int m)
    {
        for (int i = 0; i < m; i++)
        {
            int aVal = a[i] & 0xFF;
            int bVal = fzRedOpposite(b[i]) & 0xFF;
            res[i] = fzRedSingle((byte)(aVal + bVal));
        }
    }

    // Vector normalization for M elements
    public static void fzDzNormM(byte[] v, int m)
    {
        for (int i = 0; i < m; i++)
        {
            v[i] = fzDoubleZeroNorm(v[i]);
        }
    }

    // Vector subtraction: res = a - b (mod Z)
    public static void fzVecSubN(byte[] res, byte[] a, byte[] b, CrossParameters params)
    {
        int n = params.getN();
        int z = params.getZ();

        for (int i = 0; i < n; i++)
        {
            int aVal = a[i] & 0xFF;
            int bVal = b[i] & 0xFF;

            if (z == 7)
            {
                bVal = fzRedOpposite(b[i]) & 0xFF;
                res[i] = fzRedSingle((byte)(aVal + bVal));
            }
            else
            { // z == 127
                bVal = fzRedOpposite(b[i]) & 0xFF;
                res[i] = fzRedSingle((byte)(aVal + bVal));
            }
        }
    }

    // Convert restricted vector to finite field elements
    public static void convertRestrVecToFp(byte[] fpOut, byte[] fzIn, CrossParameters params)
    {
        int n = params.getN();
        int p = params.getP();

        for (int j = 0; j < n; j++)
        {
            if (p == 127)
            {
                fpOut[j] = restrToVal(fzIn[j]);
            }
            else
            { // p == 509
                short val = restrToVal(fzIn[j]);
                fpOut[j] = (byte)val; // Note: may need to handle 16-bit values
            }
        }
    }

    // Generate random FP vector using CSPRNG
    public void csprngFpVec(byte[] res, CrossParameters params)
    {
        int n = params.getN();
        int p = params.getP();
        int bitsForP = bitsToRepresent(p - 1);
        long mask = (1L << bitsForP) - 1;
        int bufferSize = roundUp(params.getBitsNFpCtRng(), 8) / 8;
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
            if (elementLong < p)
            {
                res[placed] = (byte)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForP; // Unsigned right shift
            bitsInSubBuf -= bitsForP;
        }
    }

    // Pointwise vector multiplication: res = in1 * in2 (mod P)
    public static void fpVecByFpVecPointwise(byte[] res, byte[] in1, byte[] in2, CrossParameters params)
    {
        int n = params.getN();
        int p = params.getP();

        for (int i = 0; i < n; i++)
        {
            int val1 = in1[i] & 0xFF;
            int val2 = in2[i] & 0xFF;
            long product = (long)val1 * val2;

            if (p == 127)
            {
                res[i] = (byte)fpRedDouble((int)product);
            }
            else
            { // p == 509
                res[i] = (byte)fpRedSingle((int)product);
            }
        }
    }

    // Matrix-vector multiplication: res = V_tr * e (mod P)
    public static void fpVecByFpMatrix(byte[] res, byte[] e, byte[][] V_tr, CrossParameters params)
    {
        int n = params.getN();
        int k = params.getK();
        int nMinusK = n - k;

        // Initialize with last n-k elements of e
        System.arraycopy(e, k, res, 0, nMinusK);

        // Compute matrix-vector product
        for (int i = 0; i < k; i++)
        {
            for (int j = 0; j < nMinusK; j++)
            {
                int eVal = e[i] & 0xFF;
                int vVal = V_tr[i][j] & 0xFF;
                int current = res[j] & 0xFF;
                long product = (long)eVal * vVal;
                long sum = current + product;

                if (params.getP() == 127)
                {
                    res[j] = (byte)fpRedDouble((int)sum);
                }
                else
                { // p == 509
                    res[j] = (byte)fpRedSingle((int)sum);
                }
            }
        }
    }

    // Pack FZ vector into byte array
    public static void packFzVec(byte[] out, int outOff, byte[] in, CrossParameters params)
    {
        int n = params.getN();
        int z = params.getZ();
        int packedSize = params.getDenselyPackedFzVecSize();
        genericPackFz(out, outOff, in, z, packedSize, n);
    }

    // Pack FZ RSDPG vector into byte array
    public static void packFzRsdpGVec(byte[] out, int outOff, byte[] in, CrossParameters params)
    {
        int m = params.getM();
        int z = params.getZ();
        int bitsForZ = bitsToRepresent(z - 1);
        int packedSize = params.getDenselyPackedFzRsdpGVecSize();
        genericPackFz(out, outOff, in, packedSize, m, bitsForZ);
    }

    // Generic packing for FZ vectors
    public static void genericPackFz(byte[] out, int outOff, byte[] in, int Z, int outlen, int inlen)
    {
        if (Z == 127)
        {
            genericPack7Bit(out, outOff, in, outlen, inlen);
        }
        else if (Z == 7)
        {
            genericPack3Bit(out, outOff, in, outlen, inlen);
        }
        else
        {
            throw new IllegalArgumentException("Unsupported modulus Z: " + Z);
        }
    }

    public static void genericPack3Bit(byte[] out, int outOff, byte[] in, int outlen, int inlen)
    {
        // Clear output array
        for (int i = 0; i < outlen; i++)
        {
            out[outOff + i] = 0;
        }

        int fullBlocks = inlen / 8;
        int i;

        // Process full blocks (8 elements → 3 bytes)
        for (i = 0; i < fullBlocks; i++)
        {
            int baseIn = i * 8;
            int baseOut = outOff + i * 3;

            out[baseOut] = (byte)(
                (in[baseIn] & 0x07) |
                    ((in[baseIn + 1] & 0x07) << 3) |
                    ((in[baseIn + 2] & 0x03) << 6)  // Only 2 bits fit here
            );

            out[baseOut + 1] = (byte)(
                ((in[baseIn + 2] >>> 2) & 0x01) |
                    ((in[baseIn + 3] & 0x07) << 1) |
                    ((in[baseIn + 4] & 0x07) << 4) |
                    ((in[baseIn + 5] & 0x01) << 7)  // Only 1 bit fits here
            );

            out[baseOut + 2] = (byte)(
                ((in[baseIn + 5] >>> 1) & 0x03) |
                    ((in[baseIn + 6] & 0x07) << 2) |
                    ((in[baseIn + 7] & 0x07) << 5)
            );
        }

        // Process remaining elements (1-7)
        int baseIn = i * 8;
        int baseOut = outOff + i * 3;
        int remaining = inlen % 8;

        switch (remaining)
        {
        case 1:
            out[baseOut] = (byte)(in[baseIn] & 0x07);
            break;
        case 2:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x07) |
                    ((in[baseIn + 1] & 0x07) << 3)
            );
            break;
        case 3:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x07) |
                    ((in[baseIn + 1] & 0x07) << 3) |
                    ((in[baseIn + 2] & 0x03) << 6)
            );
            out[baseOut + 1] = (byte)((in[baseIn + 2] >>> 2) & 0x01);
            break;
        case 4:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x07) |
                    ((in[baseIn + 1] & 0x07) << 3) |
                    ((in[baseIn + 2] & 0x03) << 6)
            );
            out[baseOut + 1] = (byte)(
                ((in[baseIn + 2] >>> 2) & 0x01) |
                    ((in[baseIn + 3] & 0x07) << 1)
            );
            break;
        case 5:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x07) |
                    ((in[baseIn + 1] & 0x07) << 3) |
                    ((in[baseIn + 2] & 0x03) << 6)
            );
            out[baseOut + 1] = (byte)(
                ((in[baseIn + 2] >>> 2) & 0x01) |
                    ((in[baseIn + 3] & 0x07) << 1) |
                    ((in[baseIn + 4] & 0x07) << 4)
            );
            break;
        case 6:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x07) |
                    ((in[baseIn + 1] & 0x07) << 3) |
                    ((in[baseIn + 2] & 0x03) << 6)
            );
            out[baseOut + 1] = (byte)(
                ((in[baseIn + 2] >>> 2) & 0x01) |
                    ((in[baseIn + 3] & 0x07) << 1) |
                    ((in[baseIn + 4] & 0x07) << 4) |
                    ((in[baseIn + 5] & 0x01) << 7)
            );
            out[baseOut + 2] = (byte)((in[baseIn + 5] >>> 1) & 0x03);
            break;
        case 7:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x07) |
                    ((in[baseIn + 1] & 0x07) << 3) |
                    ((in[baseIn + 2] & 0x03) << 6)
            );
            out[baseOut + 1] = (byte)(
                ((in[baseIn + 2] >>> 2) & 0x01) |
                    ((in[baseIn + 3] & 0x07) << 1) |
                    ((in[baseIn + 4] & 0x07) << 4) |
                    ((in[baseIn + 5] & 0x01) << 7)
            );
            out[baseOut + 2] = (byte)(
                ((in[baseIn + 5] >>> 1) & 0x03) |
                    ((in[baseIn + 6] & 0x07) << 2)
            );
            break;
        }
    }

    public static void genericPack7Bit(byte[] out, int outOff, byte[] in, int outlen, int inlen)
    {
        // Clear output array
        for (int i = 0; i < outlen; i++)
        {
            out[outOff + i] = 0;
        }

        int fullBlocks = inlen / 8;
        int i;

        // Process full blocks (8 elements → 7 bytes)
        for (i = 0; i < fullBlocks; i++)
        {
            int baseIn = i * 8;
            int baseOut = outOff + i * 7;

            out[baseOut] = (byte)(
                (in[baseIn] & 0x7F) |
                    ((in[baseIn + 1] & 0x01) << 7)
            );

            out[baseOut + 1] = (byte)(
                ((in[baseIn + 1] >>> 1) & 0x3F) |
                    ((in[baseIn + 2] & 0x03) << 6)
            );

            out[baseOut + 2] = (byte)(
                ((in[baseIn + 2] >>> 2) & 0x1F) |
                    ((in[baseIn + 3] & 0x07) << 5)
            );

            out[baseOut + 3] = (byte)(
                ((in[baseIn + 3] >>> 3) & 0x0F) |
                    ((in[baseIn + 4] & 0x0F) << 4)
            );

            out[baseOut + 4] = (byte)(
                ((in[baseIn + 4] >>> 4) & 0x07) |
                    ((in[baseIn + 5] & 0x1F) << 3)
            );

            out[baseOut + 5] = (byte)(
                ((in[baseIn + 5] >>> 5) & 0x03) |
                    ((in[baseIn + 6] & 0x3F) << 2)
            );

            out[baseOut + 6] = (byte)(
                ((in[baseIn + 6] >>> 6) & 0x01) |
                    ((in[baseIn + 7] & 0x7F) << 1)
            );
        }

        // Process remaining elements (1-7)
        int baseIn = i * 8;
        int baseOut = outOff + i * 7;
        int remaining = inlen % 8;

        switch (remaining)
        {
        case 1:
            out[baseOut] = (byte)(in[baseIn] & 0x7F);
            break;
        case 2:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x7F) |
                    ((in[baseIn + 1] & 0x01) << 7)
            );
            out[baseOut + 1] = (byte)((in[baseIn + 1] >>> 1) & 0x3F);
            break;
        case 3:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x7F) |
                    ((in[baseIn + 1] & 0x01) << 7)
            );
            out[baseOut + 1] = (byte)(
                ((in[baseIn + 1] >>> 1) & 0x3F) |
                    ((in[baseIn + 2] & 0x03) << 6)
            );
            out[baseOut + 2] = (byte)((in[baseIn + 2] >>> 2) & 0x1F);
            break;
        case 4:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x7F) |
                    ((in[baseIn + 1] & 0x01) << 7)
            );
            out[baseOut + 1] = (byte)(
                ((in[baseIn + 1] >>> 1) & 0x3F) |
                    ((in[baseIn + 2] & 0x03) << 6)
            );
            out[baseOut + 2] = (byte)(
                ((in[baseIn + 2] >>> 2) & 0x1F) |
                    ((in[baseIn + 3] & 0x07) << 5)
            );
            out[baseOut + 3] = (byte)((in[baseIn + 3] >>> 3) & 0x0F);
            break;
        case 5:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x7F) |
                    ((in[baseIn + 1] & 0x01) << 7)
            );
            out[baseOut + 1] = (byte)(
                ((in[baseIn + 1] >>> 1) & 0x3F) |
                    ((in[baseIn + 2] & 0x03) << 6)
            );
            out[baseOut + 2] = (byte)(
                ((in[baseIn + 2] >>> 2) & 0x1F) |
                    ((in[baseIn + 3] & 0x07) << 5)
            );
            out[baseOut + 3] = (byte)(
                ((in[baseIn + 3] >>> 3) & 0x0F) |
                    ((in[baseIn + 4] & 0x0F) << 4)
            );
            out[baseOut + 4] = (byte)((in[baseIn + 4] >>> 4) & 0x07);
            break;
        case 6:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x7F) |
                    ((in[baseIn + 1] & 0x01) << 7)
            );
            out[baseOut + 1] = (byte)(
                ((in[baseIn + 1] >>> 1) & 0x3F) |
                    ((in[baseIn + 2] & 0x03) << 6)
            );
            out[baseOut + 2] = (byte)(
                ((in[baseIn + 2] >>> 2) & 0x1F) |
                    ((in[baseIn + 3] & 0x07) << 5)
            );
            out[baseOut + 3] = (byte)(
                ((in[baseIn + 3] >>> 3) & 0x0F) |
                    ((in[baseIn + 4] & 0x0F) << 4)
            );
            out[baseOut + 4] = (byte)(
                ((in[baseIn + 4] >>> 4) & 0x07) |
                    ((in[baseIn + 5] & 0x1F) << 3)
            );
            out[baseOut + 5] = (byte)((in[baseIn + 5] >>> 5) & 0x03);
            break;
        case 7:
            out[baseOut] = (byte)(
                (in[baseIn] & 0x7F) |
                    ((in[baseIn + 1] & 0x01) << 7)
            );
            out[baseOut + 1] = (byte)(
                ((in[baseIn + 1] >>> 1) & 0x3F) |
                    ((in[baseIn + 2] & 0x03) << 6)
            );
            out[baseOut + 2] = (byte)(
                ((in[baseIn + 2] >>> 2) & 0x1F) |
                    ((in[baseIn + 3] & 0x07) << 5)
            );
            out[baseOut + 3] = (byte)(
                ((in[baseIn + 3] >>> 3) & 0x0F) |
                    ((in[baseIn + 4] & 0x0F) << 4)
            );
            out[baseOut + 4] = (byte)(
                ((in[baseIn + 4] >>> 4) & 0x07) |
                    ((in[baseIn + 5] & 0x1F) << 3)
            );
            out[baseOut + 5] = (byte)(
                ((in[baseIn + 5] >>> 5) & 0x03) |
                    ((in[baseIn + 6] & 0x3F) << 2)
            );
            out[baseOut + 6] = (byte)((in[baseIn + 6] >>> 6) & 0x01);
            break;
        }
    }

    public static void hash(byte[] digest, byte[] m, int dsc, CrossParameters params)
    {
        int securityLambda = params.getSecMarginLambda();
        int digestLength = params.getHashDigestLength();

        // Initialize SHAKE digest based on security level
        SHAKEDigest shake;
        if (securityLambda <= 128)
        {
            shake = new SHAKEDigest(128);
        }
        else
        {
            shake = new SHAKEDigest(256);
        }

        // Process message
        shake.update(m, 0, m.length);

        // Process domain separation constant (little-endian)
        byte[] dscBytes = new byte[]{
            (byte)(dsc & 0xFF),
            (byte)((dsc >> 8) & 0xFF)
        };
        shake.update(dscBytes, 0, 2);

        // Finalize and extract digest
        shake.doFinal(digest, 0, digestLength);
    }

    public static void hash(byte[] digest, int outOff, byte[] m, int dsc, CrossParameters params)
    {
        int securityLambda = params.getSecMarginLambda();
        int digestLength = params.getHashDigestLength();

        // Initialize SHAKE digest based on security level
        SHAKEDigest shake;
        if (securityLambda <= 128)
        {
            shake = new SHAKEDigest(128);
        }
        else
        {
            shake = new SHAKEDigest(256);
        }

        // Process message
        shake.update(m, 0, m.length);

        // Process domain separation constant (little-endian)
        byte[] dscBytes = new byte[]{
            (byte)(dsc & 0xFF),
            (byte)((dsc >> 8) & 0xFF)
        };
        shake.update(dscBytes, 0, 2);

        // Finalize and extract digest
        shake.doFinal(digest, outOff, digestLength);
    }

    public int[] csprngFpVecChall1(CrossParameters params)
    {
        int t = params.getT();
        int p = params.getP();
        int bitsForP = bitsToRepresent(p - 2);
        long mask = (1L << bitsForP) - 1;
        int bufferSize = roundUp(params.getBitsChall1FpstarCtRng(), 8) / 8;

        byte[] cspRngBuffer = new byte[bufferSize];
        randomBytes(cspRngBuffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(cspRngBuffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;
        int[] res = new int[t];

        while (placed < t)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(cspRngBuffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            int element = (int)elementLong + 1;  // Map to [1, P-1]
            if (element < p)
            {
                res[placed] = element;
                placed++;
            }
            subBuffer >>>= bitsForP;  // Unsigned right shift
            bitsInSubBuf -= bitsForP;
        }
        return res;
    }

    // Vector scaling: res = u_prime + e * chall_1 (mod P)
    public static void fpVecByRestrVecScaled(byte[] res, byte[] e, int chall_1,
                                             byte[] u_prime, CrossParameters params)
    {
        int n = params.getN();
        int p = params.getP();

        for (int i = 0; i < n; i++)
        {
            int eVal;
            if (p == 127)
            {
                eVal = restrToVal(e[i]) & 0xFF;
            }
            else
            { // p == 509
                eVal = restrToVal(e[i]) & 0xFFFF;
            }

            int uPrimeVal = u_prime[i] & 0xFF;
            long product = (long)eVal * chall_1;
            long sum = uPrimeVal + product;

            if (p == 127)
            {
                res[i] = (byte)fpRedDouble((int)sum);
            }
            else
            { // p == 509
                res[i] = (byte)fpRedSingle((int)sum);
            }
        }
    }

    // Vector normalization
    public static void fpDzNorm(byte[] v, CrossParameters params)
    {
        int n = params.getN();
        int p = params.getP();

        for (int i = 0; i < n; i++)
        {
            int val = v[i] & 0xFF;
            if (p == 127)
            {
                v[i] = (byte)((val + ((val + 1) >> 7)) & 0x7F);
            }
            else
            { // p == 509 (identity)
                // No normalization needed for P=509
            }
        }
    }

    // Pack FP vector
    public static void packFpVec(byte[] out, byte[] in, CrossParameters params)
    {
        int p = params.getP();
        int packedSize = params.getDenselyPackedFpVecSize();

        if (p == 127)
        {
            genericPack7Bit(out, in);
        }
        else
        { // p == 509
            // Convert to short[] for 9-bit packing
            short[] inShort = new short[in.length];
            for (int i = 0; i < in.length; i++)
            {
                inShort[i] = (short)(in[i] & 0xFF);
            }
            genericPack9Bit(out, inShort);
        }
    }

    public static void packFpVec(byte[] out, int outOff, byte[] in, CrossParameters params)
    {
        int p = params.getP();
        int packedSize = params.getDenselyPackedFpVecSize();

        if (p == 127)
        {
            genericPack7Bit(out, outOff, in);
        }
        else
        { // p == 509
            // Convert to short[] for 9-bit packing
            short[] inShort = new short[in.length];
            for (int i = 0; i < in.length; i++)
            {
                inShort[i] = (short)(in[i] & 0xFF);
            }
            genericPack9Bit(out, outOff, inShort);
        }
    }

    // Generate fixed-weight binary string
    public void expandDigestToFixedWeight(byte[] fixedWeightString,
                                          byte[] digest,
                                          CrossParameters params)
    {
        int t = params.getT();
        int w = params.getW();

        // Initialize fixed-weight string: first W ones, rest zeros
        for (int i = 0; i < w; i++)
        {
            fixedWeightString[i] = 1;
        }
        for (int i = w; i < t; i++)
        {
            fixedWeightString[i] = 0;
        }

        // Initialize CSPRNG with domain separation
        int dsc = (3 * t); // CSPRNG_DOMAIN_SEP_CONST = 0

        init(digest, digest.length, dsc);

        int bufferSize = roundUp(params.getBitsCWStrRng(), 8) / 8;
        byte[] cspRngBuffer = new byte[bufferSize];
        randomBytes(cspRngBuffer, bufferSize);

        long subBuffer = 0;
        for (int i = 0; i < 8; i++)
        {
            subBuffer |= ((long)(cspRngBuffer[i] & 0xFF)) << (8 * i);
        }

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int curr = 0;

        while (curr < t)
        {
            // Refill buffer if needed
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = 0;
                for (int i = 0; i < refreshAmount; i++)
                {
                    refreshBuf |= ((long)(cspRngBuffer[posInBuf + i] & 0xFF)) << (8 * i);
                }
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            // Calculate bits needed for current range
            int range = t - curr;
            int bitsForPos = bitsToRepresent(range - 1);
            long posMask = (1L << bitsForPos) - 1;

            // Get candidate position
            long candidatePos = subBuffer & posMask;
            if (candidatePos < range)
            {
                int dest = curr + (int)candidatePos;

                // Swap elements
                byte tmp = fixedWeightString[curr];
                fixedWeightString[curr] = fixedWeightString[dest];
                fixedWeightString[dest] = tmp;

                curr++;
            }

            // Update buffer
            subBuffer >>>= bitsForPos;
            bitsInSubBuf -= bitsForPos;
        }
    }

    public static final byte TO_PUBLISH = 1;
    public static final byte NOT_TO_PUBLISH = 0;
    public static final byte COMPUTED = 1;
    public static final byte NOT_COMPUTED = 0;

    // For SPEED variant (NO_TREES)
    public static int treeProofSpeed(byte[] mtp, byte[][] leaves, byte[] leavesToReveal, int hashDigestLength)
    {
        int published = 0;
        for (int i = 0; i < leavesToReveal.length; i++)
        {
            if (leavesToReveal[i] == TO_PUBLISH)
            {
                System.arraycopy(leaves[i], 0, mtp, published * hashDigestLength, hashDigestLength);
                published++;
            }
        }
        return published;
    }

    public static int seedPathSpeed(byte[] seedStorage, byte[] roundsSeeds, byte[] indicesToPublish, int seedLengthBytes)
    {
        int published = 0;
        for (int i = 0; i < indicesToPublish.length; i++)
        {
            if (indicesToPublish[i] == TO_PUBLISH)
            {
                System.arraycopy(roundsSeeds, i * seedLengthBytes,
                    seedStorage, published * seedLengthBytes,
                    seedLengthBytes);
                published++;
            }
        }
        return published;
    }

    // For BALANCED/SMALL variants (with trees)
    public static int treeProofBalanced(byte[] mtp, byte[] tree, byte[] leavesToReveal, CrossParameters params)
    {
        int numNodes = params.getNumNodesMerkleTree();
        byte[] flagTree = new byte[numNodes];
        Arrays.fill(flagTree, NOT_COMPUTED);

        labelLeaves(flagTree, leavesToReveal, params);

        int[] off = params.getTreeOffsets();
        int[] npl = params.getTreeNodesPerLevel();
        int[] leavesStartIndices = params.getTreeLeavesStartIndices();
        int logT = off.length - 1;  // LOG2(T)

        int published = 0;
        int startNode = leavesStartIndices[0];

        for (int level = logT; level > 0; level--)
        {
            for (int i = npl[level] - 2; i >= 0; i -= 2)
            {
                int currentNode = startNode + i;
                int parentNode = parent(currentNode, level - 1, off);

                // Propagate computed status to parent
                if (flagTree[currentNode] == COMPUTED || flagTree[sibling(currentNode)] == COMPUTED)
                {
                    flagTree[parentNode] = COMPUTED;
                }

                // Publish left sibling if needed
                if (flagTree[currentNode] == NOT_COMPUTED && flagTree[sibling(currentNode)] == COMPUTED)
                {
                    int srcPos = currentNode * params.getHashDigestLength();
                    System.arraycopy(tree, srcPos, mtp, published * params.getHashDigestLength(), params.getHashDigestLength());
                    published++;
                }

                // Publish right sibling if needed
                if (flagTree[currentNode] == COMPUTED && flagTree[sibling(currentNode)] == NOT_COMPUTED)
                {
                    int srcPos = sibling(currentNode) * params.getHashDigestLength();
                    System.arraycopy(tree, srcPos, mtp, published * params.getHashDigestLength(), params.getHashDigestLength());
                    published++;
                }
            }
            startNode -= npl[level - 1];
        }
        return published;
    }

    public static int seedPathBalanced(byte[] seedStorage, byte[] seedTree, byte[] indicesToPublish, CrossParameters params)
    {
        int numNodes = params.getNumNodesSeedTree();
        byte[] flagsTree = new byte[numNodes];
        Arrays.fill(flagsTree, NOT_TO_PUBLISH);

        computeSeedsToPublish(flagsTree, indicesToPublish, params);

        int[] off = params.getTreeOffsets();
        int[] npl = params.getTreeNodesPerLevel();
        int logT = off.length - 1;  // LOG2(T)

        int numSeedsPublished = 0;
        int startNode = 1;  // Start at level 1 (root is level 0)

        for (int level = 1; level <= logT; level++)
        {
            for (int nodeInLevel = 0; nodeInLevel < npl[level]; nodeInLevel++)
            {
                int currentNode = startNode + nodeInLevel;
                int fatherNode = parent(currentNode, level - 1, off);

                if (flagsTree[currentNode] == TO_PUBLISH && flagsTree[fatherNode] == NOT_TO_PUBLISH)
                {
                    int srcPos = currentNode * params.getSeedLengthBytes();
                    System.arraycopy(seedTree, srcPos,
                        seedStorage, numSeedsPublished * params.getSeedLengthBytes(),
                        params.getSeedLengthBytes());
                    numSeedsPublished++;
                }
            }
            startNode += npl[level];
        }
        return numSeedsPublished;
    }

    private static void computeSeedsToPublish(byte[] flagsTree, byte[] indicesToPublish, CrossParameters params)
    {
        labelLeaves(flagsTree, indicesToPublish, params);

        int[] off = params.getTreeOffsets();
        int[] npl = params.getTreeNodesPerLevel();
        int[] leavesStartIndices = params.getTreeLeavesStartIndices();
        int logT = off.length - 1;  // LOG2(T)

        int startNode = leavesStartIndices[0];
        for (int level = logT; level > 0; level--)
        {
            for (int i = npl[level] - 2; i >= 0; i -= 2)
            {
                int currentNode = startNode + i;
                int parentNode = parent(currentNode, level - 1, off);

                if (flagsTree[currentNode] == TO_PUBLISH && flagsTree[sibling(currentNode)] == TO_PUBLISH)
                {
                    flagsTree[parentNode] = TO_PUBLISH;
                }
            }
            startNode -= npl[level - 1];
        }
    }

    private static void labelLeaves(byte[] flagTree, byte[] indicesToPublish, CrossParameters params)
    {
        int cnt = 0;
        int[] leavesStartIndices = params.getTreeLeavesStartIndices();
        int[] consecutiveLeaves = params.getTreeConsecutiveLeaves();
        int subroots = params.getTreeSubroots();

        for (int i = 0; i < subroots; i++)
        {
            int startIndex = leavesStartIndices[i];
            for (int j = 0; j < consecutiveLeaves[i]; j++)
            {
                if (indicesToPublish[cnt] == 0)
                {
                    flagTree[startIndex + j] = 1;
                }
                cnt++;
            }
        }
    }

    private static int parent(int node, int parentLevel, int[] off)
    {
        return ((node - 1) >> 1) + (off[parentLevel] >> 1);
    }

    private static int sibling(int node)
    {
        return (node % 2 == 1) ? node + 1 : node - 1;
    }

    public void genSeedTree(CrossParameters params, byte[] seedTree,
                            byte[] rootSeed, byte[] salt)
    {
        int seedLen = params.getSeedLengthBytes();
        int saltLen = params.getSaltLengthBytes();
        int numNodes = params.getNumNodesSeedTree();
        int logT = params.getTreeOffsets().length - 1; // LOG2(T)

        // 1. Initialize root seed
        System.arraycopy(rootSeed, 0, seedTree, 0, seedLen);

        // 2. Prepare CSPRNG input buffer (seed + salt)
        byte[] csprngInput = new byte[seedLen + saltLen];
        System.arraycopy(salt, 0, csprngInput, seedLen, saltLen);

        // 3. Get tree structure parameters
        int[] off = params.getTreeOffsets();
        int[] npl = params.getTreeNodesPerLevel();
        int[] lpl = params.getTreeLeavesPerLevel();

        // 4. Generate tree levels
        int startNode = 0;
        for (int level = 0; level < logT; level++)
        {
            int nodesToProcess = npl[level] - lpl[level];

            for (int nodeInLevel = 0; nodeInLevel < nodesToProcess; nodeInLevel++)
            {
                int fatherNode = startNode + nodeInLevel;
                int leftChildNode = leftChild(fatherNode) - off[level];

                // Prepare CSPRNG input: father seed + salt
                System.arraycopy(seedTree, fatherNode * seedLen,
                    csprngInput, 0, seedLen);

                // Domain separation: 0 + father node index
                int domainSep = fatherNode;

                // Initialize CSPRNG and generate children
                init(csprngInput, csprngInput.length, domainSep);

                // Generate two children (2 * seedLen bytes)
                int childPos = leftChildNode * seedLen;
                randomBytes(seedTree, childPos, 2 * seedLen);
            }
            startNode += npl[level];
        }
    }

    private static int leftChild(int nodeIndex)
    {
        return 2 * nodeIndex + 1;
    }

    // For NO_TREES (SPEED variant)
    public void treeRootSpeed(byte[] root, byte[][] leaves, CrossParameters params)
    {
        int T = params.getT();
        int hashDigestLength = params.getHashDigestLength();
        int[] remainders = new int[4];
        remainders[0] = (T % 4 > 0) ? 1 : 0;
        remainders[1] = (T % 4 > 1) ? 1 : 0;
        remainders[2] = (T % 4 > 2) ? 1 : 0;

        byte[] hashInput = new byte[4 * hashDigestLength];
        int offset = 0;

        for (int i = 0; i < 4; i++)
        {
            int groupSize = T / 4 + remainders[i];
            byte[] groupLeaves = new byte[groupSize * hashDigestLength];

            // Flatten group leaves into contiguous array
            for (int j = 0; j < groupSize; j++)
            {
                int leafIndex = (T / 4) * i + j + offset;
                System.arraycopy(leaves[leafIndex], 0, groupLeaves, j * hashDigestLength, hashDigestLength);
            }

            // Hash group and store in hashInput
            byte[] groupHash = new byte[hashDigestLength];
            hash(groupHash, groupLeaves, CrossEngine.HASH_DOMAIN_SEP_CONST, params);
            System.arraycopy(groupHash, 0, hashInput, i * hashDigestLength, hashDigestLength);
            offset += remainders[i];
        }

        // Compute final root hash
        hash(root, hashInput, CrossEngine.HASH_DOMAIN_SEP_CONST, params);
    }

    // For tree-based variants (BALANCED/SMALL)
    public void treeRootBalanced(byte[] root, byte[] tree, byte[][] leaves, CrossParameters params)
    {
        int hashDigestLength = params.getHashDigestLength();
        int[] off = params.getTreeOffsets();
        int[] npl = params.getTreeNodesPerLevel();
        int[] leavesStartIndices = params.getTreeLeavesStartIndices();
        int logT = off.length - 1;
        int treeSubroots = params.getTreeSubroots();

        // Place leaves in the tree
        placeCmtOnLeaves(tree, leaves, leavesStartIndices, params.getTreeConsecutiveLeaves(), treeSubroots, hashDigestLength);

        int startNode = leavesStartIndices[0];
        for (int level = logT; level > 0; level--)
        {
            for (int i = npl[level] - 2; i >= 0; i -= 2)
            {
                int currentNode = startNode + i;
                int parentNode = parent(currentNode, level - 1, off);

                // Hash sibling pair
                byte[] siblingPair = Arrays.copyOfRange(tree, currentNode * hashDigestLength, (currentNode + 2) * hashDigestLength);
                byte[] parentHash = new byte[hashDigestLength];
                hash(parentHash, siblingPair, CrossEngine.HASH_DOMAIN_SEP_CONST, params);
                System.arraycopy(parentHash, 0, tree, parentNode * hashDigestLength, hashDigestLength);
            }
            startNode -= npl[level - 1];
        }

        // Root is at index 0
        System.arraycopy(tree, 0, root, 0, hashDigestLength);
    }

    private static void placeCmtOnLeaves(byte[] merkleTree, byte[][] leaves,
                                         int[] leavesStartIndices, int[] consecutiveLeaves,
                                         int treeSubroots, int hashDigestLength)
    {
        int cnt = 0;
        for (int i = 0; i < treeSubroots; i++)
        {
            int startIdx = leavesStartIndices[i];
            for (int j = 0; j < consecutiveLeaves[i]; j++)
            {
                int treePos = (startIdx + j) * hashDigestLength;
                System.arraycopy(leaves[cnt], 0, merkleTree, treePos, hashDigestLength);
                cnt++;
            }
        }
    }
}
