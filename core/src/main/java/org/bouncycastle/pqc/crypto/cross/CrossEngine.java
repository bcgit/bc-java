package org.bouncycastle.pqc.crypto.cross;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class CrossEngine
{
    // Precomputed constants for exponentiation
    final SHAKEDigest digest;
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

    public void init(byte[] seed, int seedOff, int seedLen, int dsc)
    {
        digest.reset();
        digest.update(seed, seedOff, seedLen);
        byte[] dscBytes = Pack.shortToLittleEndian((short)dsc);
        digest.update(dscBytes, 0, 2);
    }

    public void init(byte[] in1, int in1Off, int in1Len, byte[] in2, int dsc)
    {
        digest.reset();
        digest.update(in1, in1Off, in1Len);
        digest.update(in2, 0, in2.length);
        byte[] dscBytes = Pack.shortToLittleEndian((short)dsc);
        digest.update(dscBytes, 0, 2);
    }

    public void init(byte[] in1, int in1Off, int in1Len, byte[] in2, int in2Off, int in2Len, int dsc)
    {
        digest.reset();
        digest.update(in1, in1Off, in1Len);
        digest.update(in2, in2Off, in2Len);
        byte[] dscBytes = Pack.shortToLittleEndian((short)dsc);
        digest.update(dscBytes, 0, 2);
    }

    public void randomBytes(byte[] out, int outOff, int outLen, byte[] in1, int in1Off, int in1Len, byte[] in2, int dsc)
    {
        init(in1, in1Off, in1Len, in2, dsc);
        digest.doOutput(out, outOff, outLen);
    }

    public void randomBytes(byte[] out, int outOff, int outLen, byte[] in1, int in1Off, int in1Len, byte[] in2, int in2Off, int in2Len, int dsc)
    {
        init(in1, in1Off, in1Len, in2, in2Off, in2Len, dsc);
        digest.doOutput(out, outOff, outLen);
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

    // Expand public key for RSDP variant
    public void expandPk(CrossParameters params, byte[][] V_tr, byte[] seedPk)
    {
        init(seedPk, params.getKeypairSeedLengthBytes(), 3 * params.getT() + 2);
        csprngFMat(V_tr, params.getK(), params.getN() - params.getK(), params.getP(), params.getBitsVCtRng());
    }

    // Expand public key for RSDPG variant
    public void expandPk(CrossParameters params, short[][] V_tr, byte[][] W_mat, byte[] seedPk)
    {
        init(seedPk, params.getKeypairSeedLengthBytes(), 3 * params.getT() + 2);
        csprngFMat(W_mat, params.getM(), params.getN() - params.getM(), params.getZ(), params.getBitsWCtRng());
        csprngFpMat(V_tr, params);
    }

    private void csprngFMat(byte[][] res, int rows, int cols, int size, int bufferSize)
    {
        int total = rows * cols;
        Csprng csprng = new Csprng(size, bufferSize, this);
        int placed = 0;
        while (placed < total)
        {
            long elementLong = csprng.next();
            if (elementLong < size)
            {
                int row = placed / cols;
                int col = placed % cols;
                res[row][col] = (byte)elementLong;
                placed++;
            }
        }
    }

    // Generate FP matrix (16-bit version)
    private void csprngFpMat(short[][] res, CrossParameters params)
    {
        int rows = params.getK();
        int cols = params.getN() - params.getK();
        int total = rows * cols;
        int size = params.getP();
        int bufferSize = params.getBitsVCtRng();
        Csprng csprng = new Csprng(size, bufferSize, this);
        int placed = 0;
        while (placed < total)
        {
            long elementLong = csprng.next();
            if (elementLong < size)
            {
                int row = placed / cols;
                int col = placed % cols;
                res[row][col] = (short)elementLong;
                placed++;
            }
        }
    }

    public void csprngFVec(byte[] res, int size, int loop, int bufferSize)
    {
        Csprng csprng = new Csprng(size, bufferSize, this);
        int placed = 0;
        while (placed < loop)
        {
            byte elementLong = (byte)csprng.next();
            if (elementLong < size)
            {
                res[placed] = elementLong;
                placed++;
            }
        }
    }

    public void csprngFpVec(short[] res, CrossParameters params)
    {
        int n = params.getN();
        int p = params.getP();
        int bufferSize = params.getBitsNFpCtRng();
        Csprng csprng = new Csprng(p, bufferSize, this);
        int placed = 0;
        while (placed < n)
        {
            long elementLong = csprng.next();
            if (elementLong < p)
            {
                res[placed] = (short)elementLong;
                placed++;
            }
        }
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
                res[j] = (byte)Utils.fpRedDouble((res[j] & 0xFF) + (e[i] & 0xFF) * (W_mat[i][j] & 0xFF));
            }
        }
    }

    public static void restrVecByFpMatrix(byte[] res, byte[] e, byte[][] V_tr, CrossParameters params)
    {
        int n = params.getN();
        int k = params.getK();
        int nMinusK = n - k;

        // Initialize res with restricted values from the last n-k elements of e
        for (int i = k; i < n; i++)
        {
            res[i - k] = Utils.restrToVal(e[i]);
        }

        // Accumulate matrix-vector product
        for (int i = 0; i < k; i++)
        {
            byte e_val = Utils.restrToVal(e[i] & 0xFF);
            for (int j = 0; j < nMinusK; j++)
            {
                res[j] = (byte)Utils.fpRedDouble((res[j] & 0xFF) + (e_val * (V_tr[i][j] & 0xFF)));
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
            res[i - k] = Utils.restrToValRsdpg(e[i]);
        }

        // Accumulate matrix-vector product
        for (int i = 0; i < k; i++)
        {
            short e_val = Utils.restrToValRsdpg(e[i]);
            for (int j = 0; j < nMinusK; j++)
            {
                res[j] = Utils.fpRedSingle(res[j] + e_val * V_tr[i][j]);
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

    // For SPEED variant (NO_TREES)
    public void seedLeavesSpeed(CrossParameters params, byte[] roundsSeeds,
                                byte[] rootSeed, byte[] salt)
    {
        int seedLen = params.getSeedLengthBytes();
        int t = params.getT();

        // 1-2. Prepare CSPRNG input: root_seed || salt, Initialize CSPRNG and generate quad seeds
        byte[] quadSeed = new byte[4 * seedLen];
        randomBytes(quadSeed, 0, quadSeed.length, rootSeed, 0, seedLen, salt, 0);

        // 3. Determine remainders based on T mod 4
        int r = t & 3;
        int q = t >>> 2;
        int[] remainders = new int[4];
        remainders[0] = (r > 0) ? 1 : 0;
        remainders[1] = (r > 1) ? 1 : 0;
        remainders[2] = (r > 2) ? 1 : 0;

        // 4. Generate seeds in 4 groups
        int offset = 0;
        for (int i = 0; i < 4; i++)
        {
            // Prepare input for group CSPRNG: seed_i || salt
            int groupSeeds = q + remainders[i];
            int startPos = (q * i + offset) * seedLen;
            randomBytes(roundsSeeds, startPos, groupSeeds * seedLen, quadSeed, i * seedLen, seedLen, salt, i + 1);
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
            res[i] = (byte)Utils.fzRedSingle(((a[i] & 0xFF) + ((b[i] ^ 0x7F) & 0xFF)));
        }
    }

    // Convert restricted vector to finite field elements
    public static void convertRestrVecToFp(byte[] fpOut, byte[] fzIn, CrossParameters params)
    {
        int n = params.getN();
        for (int j = 0; j < n; j++)
        {
            fpOut[j] = Utils.restrToVal(fzIn[j]);
        }
    }

    public static void convertRestrVecToFp(short[] fpOut, byte[] fzIn, CrossParameters params)
    {
        int n = params.getN();

        for (int j = 0; j < n; j++)
        {
            fpOut[j] = Utils.restrToValRsdpg(fzIn[j]);
        }
    }

    // Pointwise vector multiplication: res = in1 * in2 (mod P)
    public static void fpVecByFpVecPointwise(byte[] res, byte[] in1, byte[] in2, CrossParameters params)
    {
        int n = params.getN();

        for (int i = 0; i < n; i++)
        {
            res[i] = (byte)Utils.fpRedDouble((in1[i] & 0xFF) * (in2[i] & 0xFF));
        }
    }

    public static void fpVecByFpVecPointwise(short[] res, short[] in1, short[] in2, CrossParameters params)
    {
        int n = params.getN();

        for (int i = 0; i < n; i++)
        {
            res[i] = Utils.fpRedSingle(in1[i] * in2[i]);
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
                res[j] = Utils.fpRedSingle(res[j] + e[i] * V_tr[i][j]);
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

    public void hash(byte[] digest, int outOff, byte[] in1,
                     byte[] in2, int in2Off, int in2Len, byte[] in3, int in3Off, int in3Len, byte[] dsc)
    {
        this.digest.reset();
        this.digest.update(in1, 0, in1.length);
        this.digest.update(in2, in2Off, in2Len);
        this.digest.update(in3, in3Off, in3Len);
        this.digest.update(dsc, 0, 2);
        this.digest.doFinal(digest, outOff, digestLength);
    }

    public int[] csprngFpVecChall1(CrossParameters params)
    {
        int t = params.getT();
        int p = params.getP();
        int[] res = new int[t];
        int bufferSize = params.getBitsChall1FpstarCtRng();
        Csprng csprng = new Csprng(p, bufferSize, Utils.bitsToRepresent(p - 2), this);
        int placed = 0;
        while (placed < t)
        {
            int element = (int)csprng.next() + 1;
            if (element < p)
            {
                res[placed] = element;
                placed++;
            }
        }
        return res;
    }

    // Vector scaling: res = u_prime + e * chall_1 (mod P)
    public static void fpVecByRestrVecScaled(byte[] res, byte[] e, int chall_1, byte[] u_prime, int n)
    {
        for (int i = 0; i < n; i++)
        {
            res[i] = (byte)Utils.fpRedDouble((u_prime[i] & 0xFF) + (Utils.restrToVal(e[i]) & 0xFF) * chall_1);
        }
    }

    public static void fpVecByRestrVecScaled(short[] res, byte[] e, int chall_1, short[] u_prime, int n)
    {
        for (int i = 0; i < n; i++)
        {
            res[i] = Utils.fpRedSingle(u_prime[i] + Utils.restrToValRsdpg(e[i]) * chall_1);
        }
    }

    // Generate fixed-weight binary string
    public void expandDigestToFixedWeight(byte[] fixedWeightString, byte[] digest, int digestOff, CrossParameters params)
    {
        int t = params.getT();
        int w = params.getW();
        // Initialize fixed-weight string: first W ones, rest zeros
        for (int i = 0; i < w; i++)
        {
            fixedWeightString[i] = 1;
        }
        init(digest, digestOff, params.getHashDigestLength(), 3 * t);
        int bufferSize = params.getBitsCWStrRng();
        Csprng csprng = new Csprng(t, bufferSize, this);
        int curr = 0;
        while (curr < t)
        {
            csprng.size = t - curr;
            csprng.bitsFor = Utils.bitsToRepresent(csprng.size - 1);
            csprng.mask = (1L << csprng.bitsFor) - 1;

            // Get candidate position
            int candidatePos = (int)(csprng.next() & csprng.mask);
            if (candidatePos < csprng.size)
            {
                int dest = curr + candidatePos;

                // Swap elements
                byte tmp = fixedWeightString[curr];
                fixedWeightString[curr] = fixedWeightString[dest];
                fixedWeightString[dest] = tmp;

                curr++;
            }
        }
    }

    public static final byte TO_PUBLISH = 1;
    public static final byte NOT_TO_PUBLISH = 0;
    public static final byte COMPUTED = 1;
    public static final byte NOT_COMPUTED = 0;

    // For SPEED variant (NO_TREES)
    public static void treeProofSpeed(byte[] mtp, int mtpOff, byte[][] leaves, byte[] leavesToReveal, int hashDigestLength)
    {
        int published = 0;
        for (int i = 0; i < leavesToReveal.length; i++)
        {
            if (leavesToReveal[i] == TO_PUBLISH)
            {
                System.arraycopy(leaves[i], 0, mtp, mtpOff + published++ * hashDigestLength, hashDigestLength);
            }
        }
    }

    public static void seedPathSpeed(byte[] seedStorage, int seedStorageOff, byte[] roundsSeeds, byte[] indicesToPublish, int seedLengthBytes)
    {
        int published = 0;
        for (int i = 0; i < indicesToPublish.length; i++)
        {
            if (indicesToPublish[i] == TO_PUBLISH)
            {
                System.arraycopy(roundsSeeds, i * seedLengthBytes, seedStorage, seedStorageOff + published * seedLengthBytes, seedLengthBytes);
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
    public static boolean rebuildLeaves(byte[] roundsSeeds, byte[] indicesToPublish, byte[] seedStorage, int seedStorageOff, int seedLength)
    {
        int published = 0;
        for (int i = 0; i < indicesToPublish.length; i++)
        {
            if (indicesToPublish[i] == TO_PUBLISH)
            {
                System.arraycopy(seedStorage, seedStorageOff + published * seedLength, roundsSeeds, i * seedLength, seedLength);
                published++;
            }
        }
        return true;
    }

    // For BALANCED/SMALL variants (with trees)
    public static void treeProofBalanced(byte[] mtp, int mtpOff, byte[] tree, byte[] leavesToReveal, CrossParameters params)
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
                    System.arraycopy(tree, srcPos, mtp, mtpOff + published * params.getHashDigestLength(), params.getHashDigestLength());
                    published++;
                }

                // Publish right sibling if needed
                if (flagTree[currentNode] == COMPUTED && flagTree[sibling(currentNode)] == NOT_COMPUTED)
                {
                    int srcPos = sibling(currentNode) * params.getHashDigestLength();
                    System.arraycopy(tree, srcPos, mtp, mtpOff + published * params.getHashDigestLength(), params.getHashDigestLength());
                    published++;
                }
            }
            startNode -= npl[level - 1];
        }
    }

    public static void seedPathBalanced(byte[] seedStorage, int seedStorageOff, byte[] seedTree, byte[] indicesToPublish, CrossParameters params)
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
                    System.arraycopy(seedTree, srcPos, seedStorage, seedStorageOff + numSeedsPublished * params.getSeedLengthBytes(),
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
                if (indicesToPublish[cnt++] == 0)
                {
                    flagTree[startIndex + j] = 1;
                }
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
                flagTree[startIndex + j] = indicesToPublish[cnt++];
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
        int logT = params.getTreeOffsets().length - 1; // LOG2(T)

        // 1. Initialize root seed
        System.arraycopy(rootSeed, 0, seedTree, 0, seedLen);

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
                int childPos = leftChildNode * seedLen;
                randomBytes(seedTree, childPos, 2 * seedLen, seedTree, fatherNode * seedLen, seedLen, salt, fatherNode);
            }
            startNode += npl[level];
        }
    }

    private static int leftChild(int nodeIndex)
    {
        return (nodeIndex << 1) + 1;
    }

    // For NO_TREES (SPEED variant)
    public void treeRootSpeed(byte[] root, byte[][] leaves, CrossParameters params)
    {
        int T = params.getT();
        int hashDigestLength = params.getHashDigestLength();
        int[] remainders = new int[4];
        remainders[0] = ((T & 3) > 0) ? 1 : 0;
        remainders[1] = ((T & 3) > 1) ? 1 : 0;
        remainders[2] = ((T & 3) > 2) ? 1 : 0;

        byte[] hashInput = new byte[hashDigestLength << 2];
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

    private static void placeCmtOnLeaves(byte[] merkleTree, byte[][] leaves, int[] leavesStartIndices,
                                         int[] consecutiveLeaves, int treeSubroots, int hashDigestLength)
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
                               byte[] storedSeeds, int storedSeedOff, byte[] salt, int saltOff,
                               CrossParameters params)
    {
        int seedLength = params.getSeedLengthBytes();
        int numNodes = params.getNumNodesSeedTree();
        byte[] flagsTree = new byte[numNodes];
        computeSeedsToPublish(flagsTree, indicesToPublish, params);

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
                    System.arraycopy(storedSeeds, storedSeedOff + nodesUsed * seedLength, seedTree, currentNode * seedLength, seedLength);
                    nodesUsed++;
                }

                // Expand children for non-leaf nodes
                if (flagsTree[currentNode] == TO_PUBLISH && nodeInLevel < npl[level] - lpl[level])
                {
                    randomBytes(seedTree, leftChild * seedLength, 2 * seedLength, seedTree,
                        currentNode * seedLength, seedLength, salt, saltOff, params.getHashDigestLength(), currentNode);
                }
            }
            startNode += npl[level];
        }

        // Verify unused storage bytes are zero
        return checkTree(storedSeeds, storedSeedOff, params, seedLength, nodesUsed);
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
                                      byte[] mtp, int mtpOff, byte[] leavesToReveal,
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
                System.arraycopy(mtp, mtpOff + published++ * hashDigestLength, recomputedLeaves[i], 0, hashDigestLength);
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
                                          byte[] mtp, int mtpOff, byte[] leavesToReveal,
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
                    digest.update(mtp, mtpOff + published * hashDigestLength, hashDigestLength);
                    published++;
                }

                // Process right sibling
                if (flagTree[siblingNode] == COMPUTED)
                {
                    digest.update(tree, siblingNode * hashDigestLength, hashDigestLength);
                }
                else
                {
                    digest.update(mtp, mtpOff + published * hashDigestLength, hashDigestLength);
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
        return checkTree(mtp, mtpOff, params, hashDigestLength, published);
    }

    private static boolean checkTree(byte[] mtp, int mtpOff, CrossParameters params, int hashDigestLength, int published)
    {
        int bytesUsed = published * hashDigestLength;
        int totalProofBytes = params.getTreeNodesToStore() * hashDigestLength;
        for (int i = bytesUsed; i < totalProofBytes; i++)
        {
            if (mtp[mtpOff + i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks if all elements in the FZ vector are within [0, Z-1]
     *
     * @param vec Finite ring vector to validate
     * @param z   Modulus value (upper bound for valid elements)
     * @param m   Number of elements to check (first M elements)
     * @return 1 if all elements are valid, 0 otherwise
     */
    public static boolean isFzVecInRestrGroup(byte[] vec, int z, int m)
    {
        for (int i = 0; i < m; i++)
        {
            if ((vec[i] & 0xFF) >= z)
            {
                return false;  // Found invalid element
            }
        }
        return true;  // All elements valid
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
            res[j] = (byte)(((synd[j] & 0xFF) + p - (Utils.fzRedSingle(Utils.fpRedDouble((s[j] & 0xFF) * (chall_1 & 0xFF))) & 0x7F)) % p);
        }
    }

    public static void fpSyndMinusFpVecScaled(short[] res, short[] synd, short chall_1, short[] s, CrossParameters params)
    {
        int p = params.getP();
        int n_k = params.getN() - params.getK();

        for (int j = 0; j < n_k; j++)
        {
            res[j] = (short)((synd[j] + p - (s[j] * chall_1) % p) % p);
        }
    }
}