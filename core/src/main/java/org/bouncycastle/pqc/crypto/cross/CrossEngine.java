package org.bouncycastle.pqc.crypto.cross;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

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
    final SHAKEDigest digest;
    static final int CSPRNG_DOMAIN_SEP_CONST = 0;
    static final int HASH_DOMAIN_SEP_CONST = 32768;
    static final byte[] HASH_DOMAIN_SEP = Pack.shortToLittleEndian((short)32768);

    private final int digestLength;

    public CrossEngine(CrossParameters params)
    {
        digest = new SHAKEDigest(params.getSecMarginLambda() <= 128 ? 128 : 256);
        digestLength = params.getHashDigestLength();
    }

    public void init(byte[] seed, int seedLen, int dsc)
    {
        digest.reset();
        digest.update(seed, 0, seedLen);
        byte[] dscBytes = Pack.shortToLittleEndian((short)dsc);
        digest.update(dscBytes, 0, 2);
    }

    public void randomBytes(byte[] out, int outLen)
    {
        randomBytes(out, 0, outLen);
    }

    public byte[] randomBytes(int outLen)
    {
        byte[] out = new byte[outLen];
        randomBytes(out, 0, outLen);
        return out;
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

    // Expand public key for RSDP variant
    public void expandPk(CrossParameters params, byte[][] V_tr, byte[] seedPk)
    {
        int dsc = 3 * params.getT() + 2;
        init(seedPk, seedPk.length, dsc);
        csprngFMat(V_tr, params.getK(), params.getN() - params.getK(), params.getP(), roundUp(params.getBitsVCtRng(), 8) >>> 3);
    }

    // Expand public key for RSDPG variant
    public void expandPk(CrossParameters params, short[][] V_tr, byte[][] W_mat, byte[] seedPk)
    {
        int dsc = 3 * params.getT() + 2;
        init(seedPk, seedPk.length, dsc);
        csprngFMat(W_mat, params.getM(), params.getN() - params.getM(), params.getZ(), roundUp(params.getBitsWCtRng(), 8) >>> 3);
        csprngFpMat(V_tr, params);
    }

    private void csprngFMat(byte[][] res, int rows, int cols, int size, int bufferSize)
    {
        int total = rows * cols;
        int bitsFor = Utils.bitsToRepresent(size - 1);
        long mask = (1L << bitsFor) - 1;
        byte[] CSPRNG_buffer = randomBytes(bufferSize);

        long subBuffer = Pack.littleEndianToLong(CSPRNG_buffer, 0);

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < total)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = Pack.littleEndianToLong(CSPRNG_buffer, posInBuf);
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < size)
            {
                int row = placed / cols;
                int col = placed % cols;
                res[row][col] = (byte)elementLong;
                placed++;
            }
            subBuffer >>>= bitsFor; // Unsigned right shift
            bitsInSubBuf -= bitsFor;
        }
    }

    // Generate FP matrix (16-bit version)
    private void csprngFpMat(short[][] res, CrossParameters params)
    {
        int rows = params.getK();
        int cols = params.getN() - params.getK();
        int total = rows * cols;
        int bitsForP = Utils.bitsToRepresent(params.getP() - 1);
        long mask = (1L << bitsForP) - 1;
        int bufferSize = roundUp(params.getBitsVCtRng(), 8) >>> 3;
        byte[] CSPRNG_buffer = randomBytes(bufferSize);

        long subBuffer = Pack.littleEndianToLong(CSPRNG_buffer, 0);

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < total)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = Pack.littleEndianToLong(CSPRNG_buffer, posInBuf);
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
            subBuffer >>>= bitsForP;
            bitsInSubBuf -= bitsForP;
        }
    }

    public void csprngFVec(byte[] res, int size, int loop, int bufferSize)
    {
        int bitsFor = Utils.bitsToRepresent(size - 1);
        long mask = (1L << bitsFor) - 1;
        byte[] CSPRNG_buffer = randomBytes(bufferSize);

        long subBuffer = Pack.littleEndianToLong(CSPRNG_buffer, 0);

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < loop)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = Pack.littleEndianToLong(CSPRNG_buffer, posInBuf);
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            byte elementLong = (byte)(subBuffer & mask);
            if (elementLong < size)
            {
                res[placed] = elementLong;
                placed++;
            }
            subBuffer >>>= bitsFor; // Unsigned right shift
            bitsInSubBuf -= bitsFor;
        }
    }

    public void csprngFpVec(short[] res, CrossParameters params)
    {
        int n = params.getN();
        int p = params.getP();
        int bitsForP = Utils.bitsToRepresent(p - 1);
        long mask = (1L << bitsForP) - 1;
        int bufferSize = roundUp(params.getBitsNFpCtRng(), 8) >>> 3;
        byte[] CSPRNG_buffer = randomBytes(bufferSize);

        long subBuffer = Pack.littleEndianToLong(CSPRNG_buffer, 0);

        int bitsInSubBuf = 64;
        int posInBuf = 8;
        int posRemaining = bufferSize - posInBuf;
        int placed = 0;

        while (placed < n)
        {
            if (bitsInSubBuf <= 32 && posRemaining > 0)
            {
                int refreshAmount = Math.min(4, posRemaining);
                long refreshBuf = Pack.littleEndianToLong(CSPRNG_buffer, posInBuf);
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            long elementLong = subBuffer & mask;
            if (elementLong < p)
            {
                res[placed] = (short)elementLong;
                placed++;
            }
            subBuffer >>>= bitsForP; // Unsigned right shift
            bitsInSubBuf -= bitsForP;
        }
    }

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
        vecMatrixProduct(res, e, W_mat, m, nMinusM);
    }

    private static void vecMatrixProduct(byte[] res, byte[] e, byte[][] W_mat, int m, int nMinusM)
    {
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < nMinusM; j++)
            {
                res[j] = (byte)fpRedDouble((res[j] & 0xFF) + (e[i] & 0xFF) * (W_mat[i][j] & 0xFF));
            }
        }
    }

    public static int fpRedDouble(int x)
    {
        return fzRedSingle(fzRedSingle(x));
    }

    /**
     * Converts a restricted exponent to a finite field value using precomputed table lookup.
     * This method is optimized for RSDP variant (P=127) where elements are represented as 7-bit values.
     * The implementation extracts an 8-bit value from a precomputed constant table by shifting
     * 8*x bits and taking the least significant byte.
     *
     * @param x The exponent index (0-127) to convert
     * @return The finite field element corresponding to the exponent
     */
    public static byte restrToVal(int x)
    {
        return (byte)(RESTR_G_TABLE >>> (x << 3));
    }

    /**
     * Constant-time conditional move (CMOV) operation for cryptographic implementations.
     * Returns either the true value (if bit=1) or 1 (if bit=0) without using branches,
     * providing protection against timing side-channel attacks.
     *
     * @param bit     The condition bit (0 or 1)
     * @param trueVal The value to return when bit=1
     * @return trueVal if bit=1, 1 otherwise
     */
    private static int cmov(int bit, int trueVal)
    {
        int mask = -bit; // mask = 0xFFFFFFFF if bit=1, 0 if bit=0
        return (trueVal & mask) | (1 & ~mask);
    }

    /**
     * Converts a restricted exponent to a finite field value for RSDPG variant (P=509).
     * This method computes g^x mod 509 using precomputed generator powers in constant time,
     * where g is a fixed generator of the multiplicative group. The 7-bit exponent is decomposed
     * into its binary representation, and the corresponding powers are multiplied together.
     * Intermediate results are reduced modulo 509 to prevent overflow.
     *
     * @param x The 7-bit exponent (0-127) to raise the generator to
     * @return The finite field element g^x mod 509 as a short value
     */
    public static short restrToValRsdpg(byte x)
    {
        int xInt = x & 0xFF;
        int finalProd = fpRedSingle(fpRedSingle(cmov((xInt) & 1, RESTR_G_GEN_1) * cmov((xInt >> 1) & 1, RESTR_G_GEN_2)
            * cmov((xInt >> 2) & 1, RESTR_G_GEN_4) * cmov((xInt >> 3) & 1, RESTR_G_GEN_8)) *
            fpRedSingle(cmov((xInt >> 4) & 1, RESTR_G_GEN_16) * cmov((xInt >> 5) & 1, RESTR_G_GEN_32) * cmov((xInt >> 6) & 1, RESTR_G_GEN_64)));

        return (short)finalProd;
    }

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
            byte e_val = restrToVal(e[i] & 0xFF);
            for (int j = 0; j < nMinusK; j++)
            {
                int sum = (res[j] & 0xFF) + (e_val * (V_tr[i][j] & 0xFF));
                int reduced = (sum & 0x7F) + (sum >>> 7);
                res[j] = (byte)((reduced & 0x7F) + (reduced >>> 7));
            }
        }
    }

    public static void restrVecByFpMatrix(short[] res, byte[] e, short[][] V_tr, CrossParameters params)
    {
        int n = params.getN();
        int k = params.getK();
        int nMinusK = n - k;

        // Initialize res with restricted values from the last n-k elements of e
        for (int i = k; i < n; i++)
        {
            res[i - k] = restrToValRsdpg(e[i]);
        }

        // Accumulate matrix-vector product
        for (int i = 0; i < k; i++)
        {
            short e_val = restrToValRsdpg(e[i]);
            for (int j = 0; j < nMinusK; j++)
            {
                res[j] = (short)fpRedSingle(res[j] + e_val * V_tr[i][j]);
            }
        }
    }

    // Vector normalization
    public static void fDzNorm(byte[] v, int n)
    {
        for (int i = 0; i < n; i++)
        {
            int val = v[i] & 0xFF;
            v[i] = (byte)((val + ((val + 1) >> 7)) & 0x7F);
        }
    }

    public static int fzDoubleZeroNorm(int x)
    {
        return (x + ((x + 1) >>> 7)) & 0x7F;
    }

    public void expandSk(CrossParameters params, byte[][] seedESeedPk, byte[] e_bar, byte[][] V_tr)
    {
        // Step 3: Expand public key matrix
        expandPk(params, V_tr, seedESeedPk[1]);

        // Step 4: Generate error vector
        int dscCsprngSeedE = (3 * params.getT() + 3);

        init(seedESeedPk[0], seedESeedPk[0].length, dscCsprngSeedE);
        csprngFVec(e_bar, params.getZ(), params.getN(), roundUp(params.getBitsNFzCtRng(), 8) >>> 3);
    }

    public void expandSk(CrossParameters params, byte[][] seedESeedPk, byte[] e_bar, byte[] e_G_bar,
                         short[][] V_tr, byte[][] W_mat)
    {
        // Step 3: Expand public key matrices
        short[][] V_tr_short = new short[params.getK()][params.getN() - params.getK()];
        expandPk(params, V_tr_short, W_mat, seedESeedPk[1]);

        // Convert to byte arrays for consistency
        for (int i = 0; i < V_tr_short.length; i++)
        {
            System.arraycopy(V_tr_short[i], 0, V_tr[i], 0, V_tr_short[i].length);
        }

        // Step 4: Generate error information word
        int dscCsprngSeedE = (3 * params.getT() + 3);

        init(seedESeedPk[0], seedESeedPk[0].length, dscCsprngSeedE);
        csprngFVec(e_G_bar, params.getZ(), params.getM(), roundUp(params.getBitsMFzCtRng(), 8) >>> 3);

        // Step 5: Compute full error vector
        fzInfWByFzMatrix(e_bar, e_G_bar, W_mat, params);

        // Step 6: Normalize error vector
        fDzNorm(e_bar, e_bar.length);
    }

    // For SPEED variant (NO_TREES)
    public void seedLeavesSpeed(CrossParameters params, byte[] roundsSeeds,
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

    // Vector subtraction: res = a - b (mod Z)
    public static void fzVecSub(byte[] res, byte[] a, byte[] b, int m)
    {
        for (int i = 0; i < m; i++)
        {
            res[i] = (byte)fzRedSingle(((a[i] & 0xFF) + ((b[i] ^ 0x7F) & 0xFF)));
        }
    }

    // Convert restricted vector to finite field elements
    public static void convertRestrVecToFp(byte[] fpOut, byte[] fzIn, CrossParameters params)
    {
        int n = params.getN();
        for (int j = 0; j < n; j++)
        {
            fpOut[j] = restrToVal(fzIn[j]);
        }
    }

    public static void convertRestrVecToFp(short[] fpOut, byte[] fzIn, CrossParameters params)
    {
        int n = params.getN();

        for (int j = 0; j < n; j++)
        {
            fpOut[j] = restrToValRsdpg(fzIn[j]);
        }
    }

    // Pointwise vector multiplication: res = in1 * in2 (mod P)
    public static void fpVecByFpVecPointwise(byte[] res, byte[] in1, byte[] in2, CrossParameters params)
    {
        int n = params.getN();

        for (int i = 0; i < n; i++)
        {
            res[i] = (byte)fpRedDouble((in1[i] & 0xFF) * (in2[i] & 0xFF));
        }
    }

    public static void fpVecByFpVecPointwise(short[] res, short[] in1, short[] in2, CrossParameters params)
    {
        int n = params.getN();

        for (int i = 0; i < n; i++)
        {
            res[i] = (short)fpRedSingle(in1[i] * in2[i]);
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
        vecMatrixProduct(res, e, V_tr, k, nMinusK);
    }

    public static void fpVecByFpMatrix(short[] res, short[] e, short[][] V_tr, CrossParameters params)
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
                res[j] = (short)fpRedSingle(res[j] + e[i] * V_tr[i][j]);
            }
        }
    }

    public void hash(byte[] digest, int outOff, byte[] m, int mOff, int mLen, byte[] dsc)
    {
        this.digest.reset();
        this.digest.update(m, mOff, mLen);
        this.digest.update(dsc, 0, 2);
        this.digest.doFinal(digest, outOff, digestLength);
    }

    public void hash(byte[] digest, int outOff, byte[] m, int mOff, int mLen, int dsc)
    {
        this.digest.reset();
        this.digest.update(m, mOff, mLen);
        this.digest.update(Pack.shortToLittleEndian((short)dsc), 0, 2);
        this.digest.doFinal(digest, outOff, digestLength);
    }

    public void hash(byte[] digest, int outOff, byte[] in1, int in1Off, int in1Len,
                     byte[] in2, int in2Off, int in2Len, byte[] dsc)
    {
        this.digest.reset();
        this.digest.update(in1, in1Off, in1Len);
        this.digest.update(in2, in2Off, in2Len);
        this.digest.update(dsc, 0, 2);
        this.digest.doFinal(digest, outOff, digestLength);
    }

    public void hash(byte[] digest, int outOff, byte[] in1,
                     byte[] in2, byte[] in3, byte[] dsc)
    {
        this.digest.reset();
        this.digest.update(in1, 0, in1.length);
        this.digest.update(in2, 0, in2.length);
        this.digest.update(in3, 0, in3.length);
        this.digest.update(dsc, 0, 2);
        this.digest.doFinal(digest, outOff, digestLength);
    }

    public int[] csprngFpVecChall1(CrossParameters params)
    {
        int t = params.getT();
        int p = params.getP();
        int bitsForP = Utils.bitsToRepresent(p - 2);
        long mask = (1L << bitsForP) - 1;
        int bufferSize = roundUp(params.getBitsChall1FpstarCtRng(), 8) >>> 3;

        byte[] cspRngBuffer = randomBytes(bufferSize);

        long subBuffer = Pack.littleEndianToLong(cspRngBuffer, 0);

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
                long refreshBuf = Pack.littleEndianToLong(cspRngBuffer, posInBuf);
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

        for (int i = 0; i < n; i++)
        {
            res[i] = (byte)fpRedDouble((u_prime[i] & 0xFF) + (restrToVal(e[i]) & 0xFF) * chall_1);
        }
    }

    public static void fpVecByRestrVecScaled(short[] res, byte[] e, int chall_1,
                                             short[] u_prime, CrossParameters params)
    {
        int n = params.getN();

        for (int i = 0; i < n; i++)
        {
            res[i] = (short)fpRedSingle(u_prime[i] + restrToValRsdpg(e[i]) * chall_1);
        }
    }

    // Generate fixed-weight binary string
    public void expandDigestToFixedWeight(byte[] fixedWeightString, byte[] digest, CrossParameters params)
    {
        int t = params.getT();
        int w = params.getW();

        // Initialize fixed-weight string: first W ones, rest zeros
        for (int i = 0; i < w; i++)
        {
            fixedWeightString[i] = 1;
        }

        // Initialize CSPRNG with domain separation
        int dsc = 3 * t; // CSPRNG_DOMAIN_SEP_CONST = 0

        init(digest, digest.length, dsc);

        int bufferSize = roundUp(params.getBitsCWStrRng(), 8) >>> 3;
        byte[] cspRngBuffer = randomBytes(bufferSize);

        long subBuffer = Pack.littleEndianToLong(cspRngBuffer, 0);

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
                long refreshBuf = Pack.littleEndianToLong(cspRngBuffer, posInBuf);
                posInBuf += refreshAmount;
                posRemaining -= refreshAmount;
                subBuffer |= refreshBuf << bitsInSubBuf;
                bitsInSubBuf += 8 * refreshAmount;
            }

            // Calculate bits needed for current range
            int range = t - curr;
            int bitsForPos = Utils.bitsToRepresent(range - 1);
            long posMask = (1L << bitsForPos) - 1;

            // Get candidate position
            int candidatePos = (int)(subBuffer & posMask);
            if (candidatePos < range)
            {
                int dest = curr + candidatePos;

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
    public static void treeProofSpeed(byte[] mtp, byte[][] leaves, byte[] leavesToReveal, int hashDigestLength)
    {
        int published = 0;
        for (int i = 0; i < leavesToReveal.length; i++)
        {
            if (leavesToReveal[i] == TO_PUBLISH)
            {
                System.arraycopy(leaves[i], 0, mtp, published++ * hashDigestLength, hashDigestLength);
            }
        }
    }

    public static void seedPathSpeed(byte[] seedStorage, byte[] roundsSeeds, byte[] indicesToPublish, int seedLengthBytes)
    {
        int published = 0;
        for (int i = 0; i < indicesToPublish.length; i++)
        {
            if (indicesToPublish[i] == TO_PUBLISH)
            {
                System.arraycopy(roundsSeeds, i * seedLengthBytes, seedStorage, published * seedLengthBytes, seedLengthBytes);
                published++;
            }
        }
    }

    /**
     * Rebuild leaves (NO_TREES variant)
     *
     * @param roundsSeeds      Output array for reconstructed seeds (T * seedLength)
     * @param indicesToPublish Array indicating which seeds to publish (T elements)
     * @param seedStorage      Stored seeds to copy from
     * @param seedLength       Length of each seed in bytes
     * @return Always true (success)
     */
    public static boolean rebuildLeaves(byte[] roundsSeeds, byte[] indicesToPublish, byte[] seedStorage, int seedLength)
    {
        int published = 0;
        for (int i = 0; i < indicesToPublish.length; i++)
        {
            if (indicesToPublish[i] == TO_PUBLISH)
            {
                System.arraycopy(seedStorage, published * seedLength, roundsSeeds, i * seedLength, seedLength);
                published++;
            }
        }
        return true;
    }

    // For BALANCED/SMALL variants (with trees)
    public static void treeProofBalanced(byte[] mtp, byte[] tree, byte[] leavesToReveal, CrossParameters params)
    {
        int numNodes = params.getNumNodesMerkleTree();
        byte[] flagTree = new byte[numNodes];
        Arrays.fill(flagTree, NOT_COMPUTED);

        labelLeavesMerkle(flagTree, leavesToReveal, params);

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
    }

    public static void seedPathBalanced(byte[] seedStorage, byte[] seedTree, byte[] indicesToPublish, CrossParameters params)
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
    }

    private static void computeSeedsToPublish(byte[] flagsTree, byte[] indicesToPublish, CrossParameters params)
    {
        labelLeavesSeedTree(flagsTree, indicesToPublish, params);

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

    private static void labelLeavesMerkle(byte[] flagTree, byte[] indicesToPublish, CrossParameters params)
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

    private static void labelLeavesSeedTree(byte[] flagTree, byte[] indicesToPublish, CrossParameters params)
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
                flagTree[startIndex + j] = indicesToPublish[cnt];
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
                System.arraycopy(seedTree, fatherNode * seedLen, csprngInput, 0, seedLen);

                // Initialize CSPRNG and generate children
                init(csprngInput, csprngInput.length, fatherNode);

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
        int t_div_4 = T >>> 2;
        for (int i = 0; i < 4; i++)
        {
            int groupSize = t_div_4 + remainders[i];
            digest.reset();
            // Flatten group leaves into contiguous array
            for (int j = 0; j < groupSize; j++)
            {
                digest.update(leaves[t_div_4 * i + j + offset], 0, hashDigestLength);
            }
            digest.update(HASH_DOMAIN_SEP, 0, 2);
            digest.doFinal(hashInput, i * hashDigestLength, digestLength);
            offset += remainders[i];
        }

        // Compute final root hash
        hash(root, 0, hashInput, 0, hashInput.length, HASH_DOMAIN_SEP);
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
                hash(tree, parentNode * hashDigestLength, tree, currentNode * hashDigestLength, hashDigestLength * 2, HASH_DOMAIN_SEP);
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

    /**
     * Rebuild full seed tree
     *
     * @param seedTree         Output seed tree (numNodes * seedLength)
     * @param indicesToPublish Array indicating which leaves to publish (T elements)
     * @param storedSeeds      Stored seeds to copy into the tree
     * @param salt             Salt used in CSPRNG initialization
     * @param params           Algorithm parameters
     * @return true if reconstruction successful, false if unused bytes non-zero
     */
    public boolean rebuildTree(byte[] seedTree, byte[] indicesToPublish,
                               byte[] storedSeeds, byte[] salt,
                               CrossParameters params)
    {
        int seedLength = params.getSeedLengthBytes();
        int numNodes = params.getNumNodesSeedTree();
        byte[] flagsTree = new byte[numNodes];
        computeSeedsToPublish(flagsTree, indicesToPublish, params);

        // Prepare CSPRNG input (seed + salt)
        byte[] csprngInput = new byte[seedLength + salt.length];
        System.arraycopy(salt, 0, csprngInput, seedLength, salt.length);

        // Tree structure parameters
        int[] off = params.getTreeOffsets();
        int[] npl = params.getTreeNodesPerLevel();
        int[] lpl = params.getTreeLeavesPerLevel();
        int logT = off.length - 1;

        int nodesUsed = 0;
        int startNode = 1;  // Skip root (index 0)

        for (int level = 1; level <= logT; level++)
        {
            for (int nodeInLevel = 0; nodeInLevel < npl[level]; nodeInLevel++)
            {
                int currentNode = startNode + nodeInLevel;
                int fatherNode = parent(currentNode, level - 1, off);
                int leftChild = leftChild(currentNode) - off[level];

                // Copy stored seeds into tree
                if (flagsTree[currentNode] == TO_PUBLISH && flagsTree[fatherNode] == NOT_TO_PUBLISH)
                {
                    System.arraycopy(storedSeeds, nodesUsed * seedLength, seedTree, currentNode * seedLength, seedLength);
                    nodesUsed++;
                }

                // Expand children for non-leaf nodes
                if (flagsTree[currentNode] == TO_PUBLISH &&
                    nodeInLevel < npl[level] - lpl[level])
                {
                    // Prepare CSPRNG input: current seed + salt
                    System.arraycopy(seedTree, currentNode * seedLength, csprngInput, 0, seedLength);

                    // Initialize CSPRNG with domain separation
                    int domainSep = CrossEngine.CSPRNG_DOMAIN_SEP_CONST + currentNode;
                    init(csprngInput, csprngInput.length, domainSep);

                    // Expand children
                    byte[] children = new byte[2 * seedLength];
                    randomBytes(children, children.length);
                    System.arraycopy(children, 0, seedTree, leftChild * seedLength, children.length);
                }
            }
            startNode += npl[level];
        }

        // Verify unused storage bytes are zero
        return checkTree(storedSeeds, params, seedLength, nodesUsed);
    }

    /**
     * Recompute root (NO_TREES/SPEED variant)
     *
     * @param root             Output root hash
     * @param recomputedLeaves Output reconstructed leaves
     * @param mtp              Merkle proof data
     * @param leavesToReveal   Array indicating leaves to reveal
     * @param params           Algorithm parameters
     * @return true if successful
     */
    public boolean recomputeRootSpeed(byte[] root, byte[][] recomputedLeaves,
                                      byte[] mtp, byte[] leavesToReveal,
                                      CrossParameters params)
    {
        int T = params.getT();
        int hashDigestLength = params.getHashDigestLength();
        int published = 0;

        // Reconstruct leaves from proof
        for (int i = 0; i < T; i++)
        {
            if (leavesToReveal[i] == TO_PUBLISH)
            {
                System.arraycopy(
                    mtp, published * hashDigestLength,
                    recomputedLeaves[i], 0,
                    hashDigestLength
                );
                published++;
            }
        }

        // Compute root from reconstructed leaves
        treeRootSpeed(root, recomputedLeaves, params);
        return true;
    }

    /**
     * Recompute root (Tree-based variants)
     *
     * @param root             Output root hash
     * @param recomputedLeaves Output reconstructed leaves
     * @param mtp              Merkle proof data
     * @param leavesToReveal   Array indicating leaves to reveal
     * @param params           Algorithm parameters
     * @return true if successful, false if unused bytes non-zero
     */
    public boolean recomputeRootTreeBased(byte[] root, byte[][] recomputedLeaves,
                                          byte[] mtp, byte[] leavesToReveal,
                                          CrossParameters params)
    {
        int hashDigestLength = params.getHashDigestLength();
        int numNodes = params.getNumNodesMerkleTree();
        byte[] tree = new byte[numNodes * hashDigestLength];
        byte[] flagTree = new byte[numNodes];
        Arrays.fill(flagTree, NOT_COMPUTED);

        // Place commitments in tree
        placeCmtOnLeaves(tree, recomputedLeaves, params.getTreeLeavesStartIndices(), params.getTreeConsecutiveLeaves(), params.getTreeSubroots(), params.getHashDigestLength());
        labelLeavesMerkle(flagTree, leavesToReveal, params);

        // Tree structure parameters
        int[] off = params.getTreeOffsets();
        int[] npl = params.getTreeNodesPerLevel();
        int[] leavesStartIndices = params.getTreeLeavesStartIndices();
        int logT = off.length - 1;

        int published = 0;
        int startNode = leavesStartIndices[0];

        for (int level = logT; level > 0; level--)
        {
            for (int i = npl[level] - 2; i >= 0; i -= 2)
            {
                int currentNode = startNode + i;
                int parentNode = parent(currentNode, level - 1, off);
                int siblingNode = sibling(currentNode);

                // Skip if both siblings unused
                if (flagTree[currentNode] == NOT_COMPUTED && flagTree[siblingNode] == NOT_COMPUTED)
                {
                    continue;
                }
                digest.reset();
                // Process left sibling (current node)
                if (flagTree[currentNode] == COMPUTED)
                {
                    digest.update(tree, currentNode * hashDigestLength, hashDigestLength);
                }
                else
                {
                    digest.update(mtp, published * hashDigestLength, hashDigestLength);
                    published++;
                }

                // Process right sibling
                if (flagTree[siblingNode] == COMPUTED)
                {
                    digest.update(tree, siblingNode * hashDigestLength, hashDigestLength);
                }
                else
                {
                    digest.update(mtp, published * hashDigestLength, hashDigestLength);
                    published++;
                }
                digest.update(HASH_DOMAIN_SEP, 0, 2);
                // Hash siblings and store at parent
                digest.doFinal(tree, parentNode * hashDigestLength, hashDigestLength);

                flagTree[parentNode] = COMPUTED;
            }
            startNode -= npl[level - 1];
        }

        // Root is at index 0
        System.arraycopy(tree, 0, root, 0, hashDigestLength);

        // Verify unused proof bytes are zero
        return checkTree(mtp, params, hashDigestLength, published);
    }

    private static boolean checkTree(byte[] mtp, CrossParameters params, int hashDigestLength, int published)
    {
        int bytesUsed = published * hashDigestLength;
        int totalProofBytes = params.getTreeNodesToStore() * hashDigestLength;
        for (int i = bytesUsed; i < totalProofBytes; i++)
        {
            if (mtp[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    // Checks if all elements in an FZ vector are within [0, Z-1]
    public static boolean isFzVecInRestrGroupN(byte[] vec, CrossParameters params)
    {
        int z = params.getZ();
        for (byte element : vec)
        {
            // Convert to unsigned integer for comparison
            int unsignedVal = element & 0xFF;
            if (unsignedVal >= z)
            {
                return false;
            }
        }
        return true;
    }

    // Computes: res = synd - (s * chall_1) mod P
    public static void fpSyndMinusFpVecScaled(byte[] res, byte[] synd, byte chall_1, byte[] s, CrossParameters params)
    {
        int p = params.getP();
        int n_k = params.getN() - params.getK();

        for (int j = 0; j < n_k; j++)
        {
            // Multiply s[j] * chall_1, Reduce product mod P, Compute negative equivalent mod P
            // res[j] = synd[j] + negative mod P
            res[j] = (byte)(((synd[j] & 0xFF) + (p - fzDoubleZeroNorm(fpRedDouble((s[j] & 0xFF) * (chall_1 & 0xFF)))) % p) % p);
        }
    }

    public static void fpSyndMinusFpVecScaled(short[] res, short[] synd, short chall_1, short[] s, CrossParameters params)
    {
        int p = params.getP();
        int n_k = params.getN() - params.getK();

        for (int j = 0; j < n_k; j++)
        {
            res[j] = (short)((synd[j] + ((p - ((s[j] * chall_1) % p)) % p)) % p);
        }
    }

    /**
     * Checks if all elements in the FZ vector are within [0, Z-1]
     *
     * @param vec Finite ring vector to validate
     * @param z   Modulus value (upper bound for valid elements)
     * @param m   Number of elements to check (first M elements)
     * @return 1 if all elements are valid, 0 otherwise
     */
    public static boolean isFzVecInRestrGroupM(byte[] vec, int z, int m)
    {
        for (int i = 0; i < m; i++)
        {
            // Convert byte to unsigned integer
            int value = vec[i] & 0xFF;
            if (value >= z)
            {
                return false;  // Found invalid element
            }
        }
        return true;  // All elements valid
    }
}