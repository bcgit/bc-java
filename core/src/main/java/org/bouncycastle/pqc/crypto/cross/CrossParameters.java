package org.bouncycastle.pqc.crypto.cross;

public class CrossParameters
{
    public static final CrossParameters cross_rsdp_1_fast = new CrossParameters(
        "CROSS-RSDP-1-FAST", true, 1,
        127,
        1, 2, 4,
        128, 127, 76, 0, 157, 82, 16,
        16, 32, 32, 32,
        157, 313, 157, 313,
        112, 9, 0,
        new int[]{0, 0, 0, 0, 0, 2, 2, 58, 58},
        new int[]{1, 2, 4, 8, 16, 30, 60, 64, 128},
        new int[]{0, 0, 0, 0, 1, 0, 28, 0, 128},
        3,
        new int[]{185, 93, 30},
        new int[]{128, 28, 1},
        82,
        1127, 1421, 28028, 717, 3656
    );

    public static final CrossParameters cross_rsdp_1_balanced = new CrossParameters(
        "CROSS-RSDP-1-BALANCED", true, 1,
        127,
        1, 2, 4,
        128, 127, 76, 0, 256, 215, 16,
        16, 32, 32, 32,
        256, 511, 256, 511,
        112, 9, 0,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 256},
        1,
        new int[]{255},
        new int[]{256},
        108,
        1127, 2170, 28028, 717, 4776
    );

    public static final CrossParameters cross_rsdp_1_small = new CrossParameters(
        "CROSS-RSDP-1-SMALL", true, 1,
        127,
        1, 2, 4,
        128, 127, 76, 0, 520, 488, 16,
        16, 32, 32, 32,
        520, 1039, 520, 1039,
        112, 9, 0,
        new int[]{0, 0, 0, 0, 0, 16, 16, 16, 16, 16, 16},
        new int[]{1, 2, 4, 8, 16, 16, 32, 64, 128, 256, 512},
        new int[]{0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 512},
        2,
        new int[]{527, 23},
        new int[]{512, 8},
        129,
        1127, 4130, 28028, 717, 10390
    );

    // RSDP Category 3
    public static final CrossParameters cross_rsdp_3_fast = new CrossParameters(
        "CROSS-RSDP-3-FAST", true, 3,
        127,
        1, 2, 4,
        192, 187, 111, 0, 239, 125, 16,
        24, 48, 48, 48,
        239, 477, 239, 477,
        149, 13, 0,
        new int[]{0, 0, 0, 0, 0, 0, 0, 2, 30},
        new int[]{1, 2, 4, 8, 16, 32, 64, 126, 224},
        new int[]{0, 0, 0, 0, 0, 0, 1, 14, 224},
        3,
        new int[]{253, 239, 126},
        new int[]{224, 14, 1},
        125,
        1673, 2163, 60711, 1065, 5264
    );

    public static final CrossParameters cross_rsdp_3_balanced = new CrossParameters(
        "CROSS-RSDP-3-BALANCED", true, 3,
        127,
        1, 2, 4,
        192, 187, 111, 0, 384, 321, 16,
        24, 48, 48, 48,
        384, 767, 384, 767,
        149, 13, 0,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 256},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256, 256},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 128, 256},
        2,
        new int[]{511, 383},
        new int[]{256, 128},
        165,
        1673, 3255, 60711, 1065, 8586
    );

    public static final CrossParameters cross_rsdp_3_small = new CrossParameters(
        "CROSS-RSDP-3-SMALL", true, 3,
        127,
        1, 2, 4,
        192, 187, 111, 0, 580, 527, 16,
        24, 48, 48, 48,
        580, 1159, 580, 1159,
        149, 13, 0,
        new int[]{0, 0, 0, 0, 0, 8, 8, 8, 8, 136, 136},
        new int[]{1, 2, 4, 8, 16, 24, 48, 96, 192, 256, 512},
        new int[]{0, 0, 0, 0, 4, 0, 0, 0, 64, 0, 512},
        3,
        new int[]{647, 327, 27},
        new int[]{512, 64, 4},
        184,
        1673, 4718, 60711, 1065, 12880
    );

    // RSDP Category 5
    public static final CrossParameters cross_rsdp_5_fast = new CrossParameters(
        "CROSS-RSDP-5-FAST", true, 5,
        127,
        1, 2, 4,
        256, 251, 150, 0, 321, 167, 16,
        32, 64, 64, 64,
        321, 641, 321, 641,
        200, 15, 0,
        new int[]{0, 0, 0, 2, 2, 2, 2, 2, 2, 130},
        new int[]{1, 2, 4, 6, 12, 24, 48, 96, 192, 256},
        new int[]{0, 0, 1, 0, 0, 0, 0, 0, 64, 256},
        3,
        new int[]{385, 321, 6},
        new int[]{256, 64, 1},
        167,
        2247, 2905, 108689, 1431, 8343
    );

    public static final CrossParameters cross_rsdp_5_balanced = new CrossParameters(
        "CROSS-RSDP-5-BALANCED", true, 5,
        127,
        1, 2, 4,
        256, 251, 150, 0, 512, 427, 16,
        32, 64, 64, 64,
        512, 1023, 512, 1023,
        200, 15, 0,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256, 512},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 512},
        1,
        new int[]{511},
        new int[]{512},
        220,
        2247, 4347, 108689, 1431, 10746
    );

    public static final CrossParameters cross_rsdp_5_small = new CrossParameters(
        "CROSS-RSDP-5-SMALL", true, 5,
        127,
        1, 2, 4,
        256, 251, 150, 0, 832, 762, 16,
        32, 64, 64, 64,
        832, 1663, 832, 1663,
        200, 15, 0,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 128},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 768},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 768},
        2,
        new int[]{895, 447},
        new int[]{768, 64},
        251,
        2247, 6734, 108689, 1431, 18150
    );

    // RSDPG Category 1
    public static final CrossParameters cross_rsdpg_1_fast = new CrossParameters(
        "CROSS-RSDPG-1-FAST", true, 1,
        509,
        1, 4, 4,
        128, 55, 36, 25, 147, 76, 8,
        16, 32, 32, 32,
        147, 293, 147, 293,
        55, 8, 25,
        new int[]{0, 0, 0, 0, 2, 6, 6, 38, 38},
        new int[]{1, 2, 4, 8, 14, 24, 48, 64, 128},
        new int[]{0, 0, 0, 1, 2, 0, 16, 0, 128},
        4,
        new int[]{165, 85, 27, 14},
        new int[]{128, 16, 2, 1},
        76,
        729, 1647, 6624, 343, 3472
    );

    public static final CrossParameters cross_rsdpg_1_balanced = new CrossParameters(
        "CROSS-RSDPG-1-BALANCED", false, 1,
        509,
        1, 4, 4,
        128, 55, 36, 25, 256, 220, 8,
        16, 32, 32, 32,
        256, 511, 256, 511,
        55, 8, 25,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 256},
        1,
        new int[]{255},
        new int[]{256},
        101,
        729, 2682, 6624, 343, 4776
    );

    public static final CrossParameters cross_rsdpg_1_small = new CrossParameters(
        "CROSS-RSDPG-1-SMALL", false, 1,
        509,
        1, 4, 4,
        128, 55, 36, 25, 512, 484, 16,
        16, 32, 32, 32,
        512, 1023, 512, 1023,
        55, 8, 25,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256, 512},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 512},
        1,
        new int[]{511},
        new int[]{512},
        117,
        729, 5085, 6624, 343, 9153
    );

    // RSDPG Category 3
    public static final CrossParameters cross_rsdpg_3_fast = new CrossParameters(
        "CROSS-RSDPG-3-FAST", false, 3,
        509,
        1, 4, 4,
        192, 79, 48, 40, 224, 119, 8,
        24, 48, 48, 48,
        224, 447, 224, 447,
        79, 8, 40,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 64},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 192},
        new int[]{0, 0, 0, 0, 0, 0, 0, 32, 192},
        2,
        new int[]{255, 223},
        new int[]{192, 32},
        119,
        1071, 2502, 14211, 539, 5128
    );

    public static final CrossParameters cross_rsdpg_3_balanced = new CrossParameters(
        "CROSS-RSDPG-3-BALANCED", false, 3,
        509,
        1, 4, 4,
        192, 79, 48, 40, 268, 196, 8,
        24, 48, 48, 48,
        268, 535, 268, 535,
        79, 8, 40,
        new int[]{0, 0, 0, 0, 0, 8, 24, 24, 24, 24},
        new int[]{1, 2, 4, 8, 16, 24, 32, 64, 128, 256},
        new int[]{0, 0, 0, 0, 4, 8, 0, 0, 0, 256},
        3,
        new int[]{279, 47, 27},
        new int[]{256, 8, 4},
        138,
        1071, 2925, 14211, 539, 6444
    );

    public static final CrossParameters cross_rsdpg_3_small = new CrossParameters(
        "CROSS-RSDPG-3-SMALL", false, 3,
        509,
        1, 4, 4,
        192, 79, 48, 40, 512, 463, 16,
        24, 48, 48, 48,
        512, 1023, 512, 1023,
        79, 8, 40,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256, 512},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 512},
        1,
        new int[]{511},
        new int[]{512},
        165,
        1071, 5238, 14211, 539, 9981
    );

    // RSDPG Category 5
    public static final CrossParameters cross_rsdpg_5_fast = new CrossParameters(
        "CROSS-RSDPG-5-FAST", false, 5,
        509,
        1, 4, 4,
        256, 106, 69, 48, 300, 153, 16,
        32, 64, 64, 64,
        300, 599, 300, 599,
        106, 8, 48,
        new int[]{0, 0, 0, 0, 0, 0, 8, 24, 88, 88},
        new int[]{1, 2, 4, 8, 16, 32, 56, 96, 128, 256},
        new int[]{0, 0, 0, 0, 0, 4, 8, 32, 0, 256},
        4,
        new int[]{343, 183, 111, 59},
        new int[]{256, 32, 8, 4},
        153,
        1431, 3357, 24192, 679, 7929
    );

    public static final CrossParameters cross_rsdpg_5_balanced = new CrossParameters(
        "CROSS-RSDPG-5-BALANCED", false, 5,
        509,
        1, 4, 4,
        256, 106, 69, 48, 356, 258, 16,
        32, 64, 64, 64,
        356, 711, 356, 711,
        106, 8, 48,
        new int[]{0, 0, 0, 0, 0, 0, 8, 8, 8, 200},
        new int[]{1, 2, 4, 8, 16, 32, 56, 112, 224, 256},
        new int[]{0, 0, 0, 0, 0, 4, 0, 0, 96, 256},
        3,
        new int[]{455, 359, 59},
        new int[]{256, 96, 4},
        185,
        1431, 3897, 24192, 679, 8937
    );

    public static final CrossParameters cross_rsdpg_5_small = new CrossParameters(
        "CROSS-RSDPG-5-SMALL", false, 5,
        509,
        1, 4, 4,
        256, 106, 69, 48, 642, 575, 16,
        32, 64, 64, 64,
        642, 1283, 642, 1283,
        106, 8, 48,
        new int[]{0, 0, 0, 0, 4, 4, 4, 4, 4, 4, 260},
        new int[]{1, 2, 4, 8, 12, 24, 48, 96, 192, 384, 512},
        new int[]{0, 0, 0, 2, 0, 0, 0, 0, 0, 128, 512},
        3,
        new int[]{771, 643, 13},
        new int[]{512, 128, 2},
        220,
        1431, 6597, 24192, 679, 15140
    );

    private final String name;
    final boolean rsdp;
    final int category;
    private final int p;
    private final int z;
    private final long restrGTable;
    private final int restrGGen;
    private final int fpElemSize;
    private final int fzElemSize;
    private final int fpDoublePrecSize;
    private final int fpTriplePrecSize;
    private final int secMarginLambda;
    private final int n;
    private final int k;
    private final int m;
    private final int t;
    private final int w;
    private final int positionInFWStringTBits;
    private final int seedLengthBytes;
    private final int keypairSeedLengthBytes;
    private final int hashDigestLength;
    private final int saltLengthBytes;
    private final int numLeavesMerkleTree;
    private final int numNodesMerkleTree;
    private final int numLeavesSeedTree;
    private final int numNodesSeedTree;
    private final int denselyPackedFpVecSize;
    private final int denselyPackedFpSynSize;
    private final int denselyPackedFzVecSize;
    private final int denselyPackedFzRsdpGVecSize;
    private final int[] treeOffsets;
    private final int[] treeNodesPerLevel;
    private final int[] treeLeavesPerLevel;
    private final int treeSubroots;
    private final int[] treeLeavesStartIndices;
    private final int[] treeConsecutiveLeaves;
    private final int treeNodesToStore;
    private final int bitsNFpCtRng;
    private final int bitsChall1FpstarCtRng;
    private final int bitsVCtRng;
    private final int bitsNFzCtRng;
    private final int bitsCWStrRng;
    private final int bitsWCtRng;
    private final int bitsMFzCtRng;

    private CrossParameters(String name, boolean rsdp, int category,
                            int fpElemSize, int fzElemSize, int fpDoublePrecSize, int fpTriplePrecSize,
                            int secMarginLambda, int n, int k, int m, int t, int w,
                            int positionInFWStringTBits,
                            int seedLengthBytes, int keypairSeedLengthBytes, int hashDigestLength,
                            int saltLengthBytes, int numLeavesMerkleTree, int numNodesMerkleTree,
                            int numLeavesSeedTree, int numNodesSeedTree,
                            int denselyPackedFpVecSize,
                            int denselyPackedFzVecSize, int denselyPackedFzRsdpGVecSize,
                            int[] treeOffsets, int[] treeNodesPerLevel, int[] treeLeavesPerLevel,
                            int treeSubroots, int[] treeLeavesStartIndices, int[] treeConsecutiveLeaves,
                            int treeNodesToStore, int bitsNFpCtRng, int bitsChall1FpstarCtRng,
                            int bitsVCtRng, int bitsNFzCtRng, int bitsCWStrRng)
    {
        this.name = name;
        this.rsdp = rsdp;
        this.category = category;
        if (rsdp)
        {
            this.p = 127;
            this.z = 7;
            this.restrGTable = 0x0140201008040201L;
            this.restrGGen = 2;
            this.bitsWCtRng = 0;
            this.bitsMFzCtRng = 0;
        }
        else
        {
            this.p = 509;
            this.z = 177;
            this.restrGTable = 0L;
            this.restrGGen = 16;
            switch (category)
            {
            case 1:
                this.bitsWCtRng = 5677;
                this.bitsMFzCtRng = 343;
                break;
            case 3:
                this.bitsWCtRng = 11655;
                this.bitsMFzCtRng = 539;
                break;
            case 5:
                this.bitsWCtRng = 20594;
                this.bitsMFzCtRng = 679;
                break;
            default:
                throw new IllegalArgumentException("Invalid NIST category level");
            }
        }
        this.fpElemSize = fpElemSize;
        this.fzElemSize = fzElemSize;
        this.fpDoublePrecSize = fpDoublePrecSize;
        this.fpTriplePrecSize = fpTriplePrecSize;
        this.secMarginLambda = secMarginLambda;
        this.n = n;
        this.k = k;
        this.m = m;
        this.t = t;
        this.w = w;
        this.positionInFWStringTBits = positionInFWStringTBits;
        this.seedLengthBytes = seedLengthBytes;
        this.keypairSeedLengthBytes = keypairSeedLengthBytes;
        this.hashDigestLength = hashDigestLength;
        this.saltLengthBytes = saltLengthBytes;
        this.numLeavesMerkleTree = numLeavesMerkleTree;
        this.numNodesMerkleTree = numNodesMerkleTree;
        this.numLeavesSeedTree = numLeavesSeedTree;
        this.numNodesSeedTree = numNodesSeedTree;
        this.denselyPackedFpVecSize = denselyPackedFpVecSize;
        this.denselyPackedFpSynSize = (n - k) / 8 * CrossEngine.bitsToRepresent(p - 1) +
            CrossEngine.roundUp(((n - k) % 8) * CrossEngine.bitsToRepresent(p - 1), 8) / 8;
        this.denselyPackedFzVecSize = denselyPackedFzVecSize;
        this.denselyPackedFzRsdpGVecSize = denselyPackedFzRsdpGVecSize;
        this.treeOffsets = treeOffsets;
        this.treeNodesPerLevel = treeNodesPerLevel;
        this.treeLeavesPerLevel = treeLeavesPerLevel;
        this.treeSubroots = treeSubroots;
        this.treeLeavesStartIndices = treeLeavesStartIndices;
        this.treeConsecutiveLeaves = treeConsecutiveLeaves;
        this.treeNodesToStore = treeNodesToStore;
        this.bitsNFpCtRng = bitsNFpCtRng;
        this.bitsChall1FpstarCtRng = bitsChall1FpstarCtRng;
        this.bitsVCtRng = bitsVCtRng;
        this.bitsNFzCtRng = bitsNFzCtRng;
        this.bitsCWStrRng = bitsCWStrRng;
    }

    public String getName()
    {
        return name;
    }

    public int getP()
    {
        return p;
    }

    public int getZ()
    {
        return z;
    }

    public long getRestrGTable()
    {
        return restrGTable;
    }

    public int getRestrGGen()
    {
        return restrGGen;
    }

    public int getFpElemSize()
    {
        return fpElemSize;
    }

    public int getFzElemSize()
    {
        return fzElemSize;
    }

    public int getFpDoublePrecSize()
    {
        return fpDoublePrecSize;
    }

    public int getFpTriplePrecSize()
    {
        return fpTriplePrecSize;
    }

    public int getSecMarginLambda()
    {
        return secMarginLambda;
    }

    public int getN()
    {
        return n;
    }

    public int getK()
    {
        return k;
    }

    public int getM()
    {
        return m;
    }

    public int getT()
    {
        return t;
    }

    public int getW()
    {
        return w;
    }

    public int getPositionInFWStringTBits()
    {
        return positionInFWStringTBits;
    }

    public int getSeedLengthBytes()
    {
        return seedLengthBytes;
    }

    public int getKeypairSeedLengthBytes()
    {
        return keypairSeedLengthBytes;
    }

    public int getHashDigestLength()
    {
        return hashDigestLength;
    }

    public int getSaltLengthBytes()
    {
        return saltLengthBytes;
    }

    public int getNumLeavesMerkleTree()
    {
        return numLeavesMerkleTree;
    }

    public int getNumNodesMerkleTree()
    {
        return numNodesMerkleTree;
    }

    public int getNumLeavesSeedTree()
    {
        return numLeavesSeedTree;
    }

    public int getNumNodesSeedTree()
    {
        return numNodesSeedTree;
    }

    public int getDenselyPackedFpVecSize()
    {
        return denselyPackedFpVecSize;
    }

    public int getDenselyPackedFpSynSize()
    {
        return denselyPackedFpSynSize;
    }

    public int getDenselyPackedFzVecSize()
    {
        return denselyPackedFzVecSize;
    }

    public int getDenselyPackedFzRsdpGVecSize()
    {
        return denselyPackedFzRsdpGVecSize;
    }

    public int[] getTreeOffsets()
    {
        return treeOffsets;
    }

    public int[] getTreeNodesPerLevel()
    {
        return treeNodesPerLevel;
    }

    public int[] getTreeLeavesPerLevel()
    {
        return treeLeavesPerLevel;
    }

    public int getTreeSubroots()
    {
        return treeSubroots;
    }

    public int[] getTreeLeavesStartIndices()
    {
        return treeLeavesStartIndices;
    }

    public int[] getTreeConsecutiveLeaves()
    {
        return treeConsecutiveLeaves;
    }

    public int getTreeNodesToStore()
    {
        return treeNodesToStore;
    }

    public int getBitsNFpCtRng()
    {
        return bitsNFpCtRng;
    }

    public int getBitsChall1FpstarCtRng()
    {
        return bitsChall1FpstarCtRng;
    }

    public int getBitsVCtRng()
    {
        return bitsVCtRng;
    }

    public int getBitsNFzCtRng()
    {
        return bitsNFzCtRng;
    }

    public int getBitsCWStrRng()
    {
        return bitsCWStrRng;
    }

    public int getBitsWCtRng()
    {
        return bitsWCtRng;
    }

    public int getBitsMFzCtRng()
    {
        return bitsMFzCtRng;
    }
}