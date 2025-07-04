package org.bouncycastle.pqc.crypto.cross;

public class CrossParameters
{
    static final int FAST = 1; //SPEED
    static final int BALANCED = 2;
    static final int SMALL = 3; //SIG_SIZE
    public static final CrossParameters cross_rsdp_1_fast = new CrossParameters(
        "CROSS-RSDP-1-FAST", true, 1, FAST,
        127, 76, 0, 157, 82,
        313, 313,
        new int[]{0, 0, 0, 0, 0, 2, 2, 58, 58},
        new int[]{1, 2, 4, 8, 16, 30, 60, 64, 128},
        new int[]{0, 0, 0, 0, 1, 0, 28, 0, 128},
        3,
        new int[]{185, 93, 30},
        new int[]{128, 28, 1},
        82,
        1127, 1421, 28028, 717, 3656, 18432
    );

    public static final CrossParameters cross_rsdp_1_balanced = new CrossParameters(
        "CROSS-RSDP-1-BALANCED", true, 1, BALANCED,
        127, 76, 0, 256, 215,
        511, 511,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 256},
        1,
        new int[]{255},
        new int[]{256},
        108,
        1127, 2170, 28028, 717, 4776, 13152
    );

    public static final CrossParameters cross_rsdp_1_small = new CrossParameters(
        "CROSS-RSDP-1-SMALL", true, 1, SMALL,
        127, 76, 0, 520, 488,
        1039, 1039,
        new int[]{0, 0, 0, 0, 0, 16, 16, 16, 16, 16, 16},
        new int[]{1, 2, 4, 8, 16, 16, 32, 64, 128, 256, 512},
        new int[]{0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 512},
        2,
        new int[]{527, 23},
        new int[]{512, 8},
        129,
        1127, 4130, 28028, 717, 10390, 12432
    );

    // RSDP Category 3
    public static final CrossParameters cross_rsdp_3_fast = new CrossParameters(
        "CROSS-RSDP-3-FAST", true, 3, FAST,
        187, 111, 0, 239, 125,
        477, 477,
        new int[]{0, 0, 0, 0, 0, 0, 0, 2, 30},
        new int[]{1, 2, 4, 8, 16, 32, 64, 126, 224},
        new int[]{0, 0, 0, 0, 0, 0, 1, 14, 224},
        3,
        new int[]{253, 239, 126},
        new int[]{224, 14, 1},
        125,
        1673, 2163, 60711, 1065, 5264, 41406
    );

    public static final CrossParameters cross_rsdp_3_balanced = new CrossParameters(
        "CROSS-RSDP-3-BALANCED", true, 3, BALANCED,
        187, 111, 0, 384, 321,
        767, 767,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 256},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256, 256},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 128, 256},
        2,
        new int[]{511, 383},
        new int[]{256, 128},
        165,
        1673, 3255, 60711, 1065, 8586, 29853
    );

    public static final CrossParameters cross_rsdp_3_small = new CrossParameters(
        "CROSS-RSDP-3-SMALL", true, 3, SMALL,
        187, 111, 0, 580, 527,
        1159, 1159,
        new int[]{0, 0, 0, 0, 0, 8, 8, 8, 8, 136, 136},
        new int[]{1, 2, 4, 8, 16, 24, 48, 96, 192, 256, 512},
        new int[]{0, 0, 0, 0, 4, 0, 0, 0, 64, 0, 512},
        3,
        new int[]{647, 327, 27},
        new int[]{512, 64, 4},
        184,
        1673, 4718, 60711, 1065, 12880, 28391
    );

    // RSDP Category 5
    public static final CrossParameters cross_rsdp_5_fast = new CrossParameters(
        "CROSS-RSDP-5-FAST", true, 5, FAST,
        251, 150, 0, 321, 167,
        641, 641,
        new int[]{0, 0, 0, 2, 2, 2, 2, 2, 2, 130},
        new int[]{1, 2, 4, 6, 12, 24, 48, 96, 192, 256},
        new int[]{0, 0, 1, 0, 0, 0, 0, 0, 64, 256},
        3,
        new int[]{385, 321, 6},
        new int[]{256, 64, 1},
        167,
        2247, 2905, 108689, 1431, 8343, 74590
    );

    public static final CrossParameters cross_rsdp_5_balanced = new CrossParameters(
        "CROSS-RSDP-5-BALANCED", true, 5, BALANCED,
        251, 150, 0, 512, 427,
        1023, 1023,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256, 512},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 512},
        1,
        new int[]{511},
        new int[]{512},
        220,
        2247, 4347, 108689, 1431, 10746, 53527
    );

    public static final CrossParameters cross_rsdp_5_small = new CrossParameters(
        "CROSS-RSDP-5-SMALL", true, 5, SMALL,
        251, 150, 0, 832, 762,
        1663, 1663,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 128},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256, 384, 768},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 768},
        2,
        new int[]{895, 447},
        new int[]{768, 64},
        251,
        2247, 6734, 108689, 1431, 18150, 50818
    );

    // RSDPG Category 1
    public static final CrossParameters cross_rsdpg_1_fast = new CrossParameters(
        "CROSS-RSDPG-1-FAST", false, 1, FAST,
        55, 36, 25, 147, 76,
        293, 293,
        new int[]{0, 0, 0, 0, 2, 6, 6, 38, 38},
        new int[]{1, 2, 4, 8, 14, 24, 48, 64, 128},
        new int[]{0, 0, 0, 1, 2, 0, 16, 0, 128},
        4,
        new int[]{165, 85, 27, 14},
        new int[]{128, 16, 2, 1},
        76,
        729, 1647, 6624, 343, 3472, 11980
    );

    public static final CrossParameters cross_rsdpg_1_balanced = new CrossParameters(
        "CROSS-RSDPG-1-BALANCED", false, 1, BALANCED,
        55, 36, 25, 256, 220,
        511, 511,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 256},
        1,
        new int[]{255},
        new int[]{256},
        101,
        729, 2682, 6624, 343, 4776, 9120
    );

    public static final CrossParameters cross_rsdpg_1_small = new CrossParameters(
        "CROSS-RSDPG-1-SMALL", false, 1, SMALL,
        55, 36, 25, 512, 484,
        1023, 1023,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256, 512},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 512},
        1,
        new int[]{511},
        new int[]{512},
        117,
        729, 5085, 6624, 343, 9153, 8960
    );

    // RSDPG Category 3
    public static final CrossParameters cross_rsdpg_3_fast = new CrossParameters(
        "CROSS-RSDPG-3-FAST", false, 3, FAST,
        79, 48, 40, 224, 119,
        447, 447,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 64},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 192},
        new int[]{0, 0, 0, 0, 0, 0, 0, 32, 192},
        2,
        new int[]{255, 223},
        new int[]{192, 32},
        119,
        1071, 2502, 14211, 539, 5128, 26772
    );

    public static final CrossParameters cross_rsdpg_3_balanced = new CrossParameters(
        "CROSS-RSDPG-3-BALANCED", false, 3, BALANCED,
        79, 48, 40, 268, 196,
        535, 535,
        new int[]{0, 0, 0, 0, 0, 8, 24, 24, 24, 24},
        new int[]{1, 2, 4, 8, 16, 24, 32, 64, 128, 256},
        new int[]{0, 0, 0, 0, 4, 8, 0, 0, 0, 256},
        3,
        new int[]{279, 47, 27},
        new int[]{256, 8, 4},
        138,
        1071, 2925, 14211, 539, 6444, 22464
    );

    public static final CrossParameters cross_rsdpg_3_small = new CrossParameters(
        "CROSS-RSDPG-3-SMALL", false, 3, SMALL,
        79, 48, 40, 512, 463,
        1023, 1023,
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        new int[]{1, 2, 4, 8, 16, 32, 64, 128, 256, 512},
        new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 512},
        1,
        new int[]{511},
        new int[]{512},
        165,
        1071, 5238, 14211, 539, 9981, 20452
    );

    // RSDPG Category 5
    public static final CrossParameters cross_rsdpg_5_fast = new CrossParameters(
        "CROSS-RSDPG-5-FAST", false, 5, FAST,
        106, 69, 48, 300, 153,
        599, 599,
        new int[]{0, 0, 0, 0, 0, 0, 8, 24, 88, 88},
        new int[]{1, 2, 4, 8, 16, 32, 56, 96, 128, 256},
        new int[]{0, 0, 0, 0, 0, 4, 8, 32, 0, 256},
        4,
        new int[]{343, 183, 111, 59},
        new int[]{256, 32, 8, 4},
        153,
        1431, 3357, 24192, 679, 7929, 48102
    );

    public static final CrossParameters cross_rsdpg_5_balanced = new CrossParameters(
        "CROSS-RSDPG-5-BALANCED", false, 5, BALANCED,
        106, 69, 48, 356, 258,
        711, 711,
        new int[]{0, 0, 0, 0, 0, 0, 8, 8, 8, 200},
        new int[]{1, 2, 4, 8, 16, 32, 56, 112, 224, 256},
        new int[]{0, 0, 0, 0, 0, 4, 0, 0, 96, 256},
        3,
        new int[]{455, 359, 59},
        new int[]{256, 96, 4},
        185,
        1431, 3897, 24192, 679, 8937, 40100
    );

    public static final CrossParameters cross_rsdpg_5_small = new CrossParameters(
        "CROSS-RSDPG-5-SMALL", false, 5, SMALL,
        106, 69, 48, 642, 575,
        1283, 1283,
        new int[]{0, 0, 0, 0, 4, 4, 4, 4, 4, 4, 260},
        new int[]{1, 2, 4, 8, 12, 24, 48, 96, 192, 384, 512},
        new int[]{0, 0, 0, 2, 0, 0, 0, 0, 0, 128, 512},
        3,
        new int[]{771, 643, 13},
        new int[]{512, 128, 2},
        220,
        1431, 6597, 24192, 679, 15140, 36454
    );

    private final String name;
    final boolean rsdp;
    final int category;
    final int variant;
    private final int p;
    private final int z;
    private final int secMarginLambda;
    private final int n;
    private final int k;
    private final int m;
    private final int t;
    private final int w;
    private final int seedLengthBytes;
    private final int keypairSeedLengthBytes;
    // saltLengthBytes
    private final int hashDigestLength;
    private final int numNodesMerkleTree;
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
    private final int signatureSize;

    private CrossParameters(String name, boolean rsdp, int category, int variant,
                            int n, int k, int m, int t, int w,
                            int numNodesMerkleTree,
                            int numNodesSeedTree,
                            int[] treeOffsets, int[] treeNodesPerLevel, int[] treeLeavesPerLevel,
                            int treeSubroots, int[] treeLeavesStartIndices, int[] treeConsecutiveLeaves,
                            int treeNodesToStore, int bitsNFpCtRng, int bitsChall1FpstarCtRng,
                            int bitsVCtRng, int bitsNFzCtRng, int bitsCWStrRng, int signatureSize)
    {
        this.name = name;
        this.rsdp = rsdp;
        this.category = category;
        this.variant = variant;
        if (rsdp)
        {
            this.p = 127;
            this.z = 7;
            this.bitsWCtRng = 0;
            this.bitsMFzCtRng = 0;
        }
        else
        {
            this.p = 509;
            this.z = 127;
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
        switch (category)
        {
        case 1:
            this.keypairSeedLengthBytes = 32;
            this.secMarginLambda = 128;
            this.seedLengthBytes = 16;
            this.hashDigestLength = 32;
            break;
        case 3:
            this.keypairSeedLengthBytes = 48;
            this.secMarginLambda = 192;
            this.seedLengthBytes = 24;
            this.hashDigestLength = 48;
            break;
        case 5:
            this.keypairSeedLengthBytes = 64;
            this.secMarginLambda = 256;
            this.seedLengthBytes = 32;
            this.hashDigestLength = 64;
            break;
        default:
            throw new IllegalArgumentException("Invalid NIST category level");
        }
        this.n = n;
        this.k = k;
        this.m = m;
        this.t = t;
        this.w = w;

        this.numNodesMerkleTree = numNodesMerkleTree;
        this.numNodesSeedTree = numNodesSeedTree;
        this.denselyPackedFpVecSize = (n / 8 * Utils.bitsToRepresent(p - 1) + Utils.roundUp((n % 8) * Utils.bitsToRepresent(p - 1), 8) / 8);
        this.denselyPackedFpSynSize = (n - k) / 8 * Utils.bitsToRepresent(p - 1) +
            Utils.roundUp(((n - k) % 8) * Utils.bitsToRepresent(p - 1), 8) / 8;
        this.denselyPackedFzVecSize = (n / 8 * Utils.bitsToRepresent(z - 1) + Utils.roundUp((n % 8)
            * Utils.bitsToRepresent(z - 1), 8) / 8);
        this.denselyPackedFzRsdpGVecSize = (m / 8) * Utils.bitsToRepresent(z - 1) + Utils.roundUp(m % 8 * Utils.bitsToRepresent(z - 1), 8) / 8;
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
        this.signatureSize = signatureSize;
    }

    public String getName()
    {
        return name;
    }

    public int getVariant()
    {
        return variant;
    }

    public int getP()
    {
        return p;
    }

    public int getZ()
    {
        return z;
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

    public int getNumNodesMerkleTree()
    {
        return numNodesMerkleTree;
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

    public int getSignatureSize()
    {
        return signatureSize;
    }

    public int getCategory()
    {
        return category;
    }
}