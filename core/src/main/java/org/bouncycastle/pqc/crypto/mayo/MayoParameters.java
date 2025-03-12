package org.bouncycastle.pqc.crypto.mayo;

public class MayoParameters
{
    public static final MayoParameters mayo1 = new MayoParameters(
        "MAYO_1",          // name
        86,                 // n
        78,                 // m
        5,                  // m_vec_limbs
        8,                  // o
        86 - 8,             // v = n - o = 78
        10 * 8 + 1,         // A_cols = k * o + 1 = 10 * 8 + 1 = 81
        10,                 // k
        // q
        39,                 // m_bytes
        312,                // O_bytes
        39,                 // v_bytes
        40,                 // r_bytes
        120159,             // P1_bytes
        24336,              // P2_bytes
        24,                 // csk_bytes
        1420,               // cpk_bytes
        454,                // sig_bytes
        new int[]{8, 1, 1, 0},        // F_TAIL_78
        24,                 // salt_bytes
        32,                 // digest_bytes
        24                  // sk_seed_bytes
    );

    public static final MayoParameters mayo2 = new MayoParameters(
        "MAYO_2",          // name
        81,                 // n
        64,                 // m
        4,                  // m_vec_limbs
        17,                 // o
        81 - 17,            // v = 64
        4 * 17 + 1,         // A_cols = 4 * 17 + 1 = 69
        4,                  // k
        32,                 // m_bytes
        544,                // O_bytes
        32,                 // v_bytes
        34,                 // r_bytes
        66560,              // P1_bytes
        34816,              // P2_bytes
        24,                 // csk_bytes
        4912,               // cpk_bytes
        186,                // sig_bytes
        new int[]{8, 0, 2, 8}, //F_TAIL_64
        24,                 // salt_bytes
        32,                 // digest_bytes
        24                  // sk_seed_bytes
    );

    public static final MayoParameters mayo3 = new MayoParameters(
        "MAYO_3",          // name
        118,                // n
        108,                // m
        7,                  // m_vec_limbs
        10,                 // o
        118 - 10,           // v = 108
        11 * 10 + 1,        // A_cols = 11 * 10 + 1 = 111
        11,                 // k
        54,                 // m_bytes
        540,                // O_bytes
        54,                 // v_bytes
        55,                 // r_bytes
        317844,             // P1_bytes
        58320,              // P2_bytes
        32,                 // csk_bytes
        2986,               // cpk_bytes
        681,                // sig_bytes
        new int[]{8, 0, 1, 7}, //F_TAIL_108
        32,                 // salt_bytes
        48,                 // digest_bytes
        32                  // sk_seed_bytes
    );

    public static final MayoParameters mayo5 = new MayoParameters(
        "MAYO_5",          // name
        154,                // n
        142,                // m
        9,                  // m_vec_limbs
        12,                 // o
        154 - 12,           // v = 142
        12 * 12 + 1,        // A_cols = 12 * 12 + 1 = 145
        12,                 // k
        71,                 // m_bytes
        852,                // O_bytes
        71,                 // v_bytes
        72,                 // r_bytes
        720863,             // P1_bytes
        120984,             // P2_bytes
        40,                 // csk_bytes
        5554,               // cpk_bytes
        964,                // sig_bytes
        new int[]{4, 0, 8, 1}, //F_TAIL_142
        40,                 // salt_bytes
        64,                 // digest_bytes
        40                  // sk_seed_bytes
    );

    private final String name;
    private final int n;
    private final int m;
    private final int mVecLimbs;
    private final int o;
    private final int v;
    private final int ACols;
    private final int k;
    //private final int q; q = 16
    private final int mBytes;
    private final int OBytes;
    private final int vBytes;
    private final int rBytes;
    private final int P1Bytes;
    private final int P2Bytes;
    private final int cskBytes;
    private final int cpkBytes;
    private final int sigBytes;
    private final int[] fTail;
    private final int saltBytes;
    private final int digestBytes;
    private static final int pkSeedBytes = 16;
    private final int skSeedBytes;

    private MayoParameters(String name, int n, int m, int mVecLimbs, int o, int v, int ACols, int k,
                           int mBytes, int OBytes, int vBytes, int rBytes, int P1Bytes, int P2Bytes,
                           int cskBytes, int cpkBytes, int sigBytes, int[] fTail,
                           int saltBytes, int digestBytes, int skSeedBytes)
    {
        this.name = name;
        this.n = n;
        this.m = m;
        this.mVecLimbs = mVecLimbs;
        this.o = o;
        this.v = v;
        this.ACols = ACols;
        this.k = k;
        this.mBytes = mBytes;
        this.OBytes = OBytes;
        this.vBytes = vBytes;
        this.rBytes = rBytes;
        this.P1Bytes = P1Bytes;
        this.P2Bytes = P2Bytes;
        this.cskBytes = cskBytes;
        this.cpkBytes = cpkBytes;
        this.sigBytes = sigBytes;
        this.fTail = fTail;
        this.saltBytes = saltBytes;
        this.digestBytes = digestBytes;
        this.skSeedBytes = skSeedBytes;
    }

    public String getName()
    {
        return name;
    }

    public int getN()
    {
        return n;
    }

    public int getM()
    {
        return m;
    }

    public int getMVecLimbs()
    {
        return mVecLimbs;
    }

    public int getO()
    {
        return o;
    }

    public int getV()
    {
        return v;
    }

    public int getACols()
    {
        return ACols;
    }

    public int getK()
    {
        return k;
    }

    public int getMBytes()
    {
        return mBytes;
    }

    public int getOBytes()
    {
        return OBytes;
    }

    public int getVBytes()
    {
        return vBytes;
    }

    public int getRBytes()
    {
        return rBytes;
    }

    public int getP1Bytes()
    {
        return P1Bytes;
    }

    public int getP2Bytes()
    {
        return P2Bytes;
    }

    public int getCskBytes()
    {
        return cskBytes;
    }

    public int getCpkBytes()
    {
        return cpkBytes;
    }

    public int getSigBytes()
    {
        return sigBytes;
    }

    public int[] getFTail()
    {
        return fTail;
    }

    public int getSaltBytes()
    {
        return saltBytes;
    }

    public int getDigestBytes()
    {
        return digestBytes;
    }

    public int getPkSeedBytes()
    {
        return pkSeedBytes;
    }

    public int getSkSeedBytes()
    {
        return skSeedBytes;
    }

    /**
     * Computes: (v * (v + 1) / 2) * mVecLimbs
     */
    public int getP1Limbs()
    {
        return ((v * (v + 1)) >> 1) * mVecLimbs;
    }

    /**
     * Computes: v * o * mVecLimbs
     */
    public int getP2Limbs()
    {
        return v * o * mVecLimbs;
    }

    /**
     * Computes: (o * (o + 1) / 2) * mVecLimbs
     */
    public int getP3Limbs()
    {
        return ((o * (o + 1)) >> 1) * mVecLimbs;
    }
}

