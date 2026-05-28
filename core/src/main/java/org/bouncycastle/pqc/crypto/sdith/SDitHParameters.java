package org.bouncycastle.pqc.crypto.sdith;

/**
 * SDitH parameter set descriptor.
 * <p>
 * SDitH (Syndrome-Decoding-in-the-Head) has 24 NIST-submitted variants formed
 * from the cross of:
 * <ul>
 *   <li>MPC structure: Hypercube or Threshold,</li>
 *   <li>NIST category: 1, 3, or 5,</li>
 *   <li>Field: GF(256) or P251.</li>
 * </ul>
 * The current Bouncy Castle port wires up the Hypercube / Category 1 /
 * GF(256) variant matching the shipped reference KAT vectors. Additional
 * variants can be added by populating new {@code public static final}
 * constants here and adding the corresponding precomputed tables to
 * {@link SDitHPrecomputed}.
 * <p>
 * The numeric fields follow the reference param.h convention:
 * <ul>
 *   <li>{@code m}: code length,</li>
 *   <li>{@code k}: code dimension,</li>
 *   <li>{@code w}: Hamming weight bound on the SD solution,</li>
 *   <li>{@code d}: splitting factor (number of twists),</li>
 *   <li>{@code t}: number of MPC evaluation points per iteration,</li>
 *   <li>{@code tau}: number of parallel MPC repetitions,</li>
 *   <li>{@code dimD}: hypercube dimension (2^D leaf parties),</li>
 *   <li>{@code seedSize}, {@code rhoSize}, {@code saltSize},
 *       {@code commitSize}, {@code hashSize}: in bytes,</li>
 *   <li>{@code fpointSize}: extension-field byte width (3 or 4),</li>
 *   <li>{@code hashBits}: SHA3 variant used for commitments and Fiat-Shamir,</li>
 *   <li>{@code xofBits}: SHAKE variant used as XOF.</li>
 * </ul>
 */
public class SDitHParameters
{
    public static final int VARIANT_HYPERCUBE = 0;
    public static final int VARIANT_THRESHOLD = 1;

    public static final int FIELD_GF256 = 0;
    public static final int FIELD_P251 = 1;

    public static final SDitHParameters sdith_hypercube_cat1_gf256 = new SDitHParameters(
        "sdith-hypercube-cat1-gf256",
        VARIANT_HYPERCUBE, FIELD_GF256, 1,
        242, 126, 87, 1, 3, 17, 8,
        16, 16, 32, 32, 32, 4,
        256, 128);

    public static final SDitHParameters sdith_hypercube_cat3_gf256 = new SDitHParameters(
        "sdith-hypercube-cat3-gf256",
        VARIANT_HYPERCUBE, FIELD_GF256, 3,
        376, 220, 114, 2, 3, 26, 8,
        24, 24, 48, 48, 48, 4,
        384, 256);

    public static final SDitHParameters sdith_hypercube_cat5_gf256 = new SDitHParameters(
        "sdith-hypercube-cat5-gf256",
        VARIANT_HYPERCUBE, FIELD_GF256, 5,
        494, 282, 156, 2, 4, 34, 8,
        32, 32, 64, 64, 64, 4,
        512, 256);

    public static final SDitHParameters sdith_hypercube_cat1_p251 = new SDitHParameters(
        "sdith-hypercube-cat1-p251",
        VARIANT_HYPERCUBE, FIELD_P251, 1,
        242, 126, 87, 1, 3, 17, 8,
        16, 16, 32, 32, 32, 4,
        256, 128);

    public static final SDitHParameters sdith_hypercube_cat3_p251 = new SDitHParameters(
        "sdith-hypercube-cat3-p251",
        VARIANT_HYPERCUBE, FIELD_P251, 3,
        376, 220, 114, 2, 3, 26, 8,
        24, 24, 48, 48, 48, 4,
        384, 256);

    public static final SDitHParameters sdith_hypercube_cat5_p251 = new SDitHParameters(
        "sdith-hypercube-cat5-p251",
        VARIANT_HYPERCUBE, FIELD_P251, 5,
        494, 282, 156, 2, 4, 34, 8,
        32, 32, 64, 64, 64, 4,
        512, 256);

    public static final SDitHParameters sdith_threshold_cat1_gf256 = new SDitHParameters(
        "sdith-threshold-cat1-gf256",
        VARIANT_THRESHOLD, FIELD_GF256, 1,
        242, 126, 87, 1, 7, 6, 8,
        16, 16, 32, 32, 32, 4,
        256, 128, 3, 19);

    public static final SDitHParameters sdith_threshold_cat3_gf256 = new SDitHParameters(
        "sdith-threshold-cat3-gf256",
        VARIANT_THRESHOLD, FIELD_GF256, 3,
        376, 220, 114, 2, 10, 9, 8,
        24, 24, 48, 48, 48, 4,
        384, 256, 3, 19);

    public static final SDitHParameters sdith_threshold_cat5_gf256 = new SDitHParameters(
        "sdith-threshold-cat5-gf256",
        VARIANT_THRESHOLD, FIELD_GF256, 5,
        494, 282, 156, 2, 13, 12, 8,
        32, 32, 64, 64, 64, 4,
        512, 256, 3, 19);

    public static final SDitHParameters sdith_threshold_cat1_p251 = new SDitHParameters(
        "sdith-threshold-cat1-p251",
        VARIANT_THRESHOLD, FIELD_P251, 1,
        242, 126, 87, 1, 7, 6, 8,
        16, 16, 32, 32, 32, 4,
        256, 128, 3, 19);

    public static final SDitHParameters sdith_threshold_cat3_p251 = new SDitHParameters(
        "sdith-threshold-cat3-p251",
        VARIANT_THRESHOLD, FIELD_P251, 3,
        376, 220, 114, 2, 10, 9, 8,
        24, 24, 48, 48, 48, 4,
        384, 256, 3, 19);

    public static final SDitHParameters sdith_threshold_cat5_p251 = new SDitHParameters(
        "sdith-threshold-cat5-p251",
        VARIANT_THRESHOLD, FIELD_P251, 5,
        494, 282, 156, 2, 13, 12, 8,
        32, 32, 64, 64, 64, 4,
        512, 256, 3, 19);

    private final String name;
    private final int variant;
    private final int field;
    private final int category;

    private final int m;
    private final int k;
    private final int w;
    private final int d;
    private final int t;
    private final int tau;
    private final int dimD;

    private final int seedSize;
    private final int rhoSize;
    private final int saltSize;
    private final int commitSize;
    private final int hashSize;
    private final int fpointSize;

    private final int hashBits;
    private final int xofBits;

    /**
     * Threshold-only parameters. Zero for hypercube variants.
     * <ul>
     *   <li>{@code nbRevealed}: number of parties revealed per execution (degree
     *       of the secret-sharing polynomial used by the Threshold MPCitH).</li>
     *   <li>{@code treeMaxOpenLeaves}: upper bound on the number of Merkle
     *       authentication-path nodes per execution.</li>
     * </ul>
     */
    private final int nbRevealed;
    private final int treeMaxOpenLeaves;

    private SDitHParameters(String name, int variant, int field, int category,
                            int m, int k, int w, int d, int t, int tau, int dimD,
                            int seedSize, int rhoSize, int saltSize, int commitSize, int hashSize, int fpointSize,
                            int hashBits, int xofBits)
    {
        this(name, variant, field, category, m, k, w, d, t, tau, dimD,
                seedSize, rhoSize, saltSize, commitSize, hashSize, fpointSize,
                hashBits, xofBits, 0, 0);
    }

    private SDitHParameters(String name, int variant, int field, int category,
                            int m, int k, int w, int d, int t, int tau, int dimD,
                            int seedSize, int rhoSize, int saltSize, int commitSize, int hashSize, int fpointSize,
                            int hashBits, int xofBits, int nbRevealed, int treeMaxOpenLeaves)
    {
        this.name = name;
        this.variant = variant;
        this.field = field;
        this.category = category;
        this.m = m;
        this.k = k;
        this.w = w;
        this.d = d;
        this.t = t;
        this.tau = tau;
        this.dimD = dimD;
        this.seedSize = seedSize;
        this.rhoSize = rhoSize;
        this.saltSize = saltSize;
        this.commitSize = commitSize;
        this.hashSize = hashSize;
        this.fpointSize = fpointSize;
        this.hashBits = hashBits;
        this.xofBits = xofBits;
        this.nbRevealed = nbRevealed;
        this.treeMaxOpenLeaves = treeMaxOpenLeaves;
    }

    /**
     * Threshold variant: number of revealed parties per execution. Zero for
     * hypercube variants.
     */
    public int getNbRevealed()
    {
        return nbRevealed;
    }

    /**
     * Threshold variant: upper bound on Merkle authentication-path nodes per
     * execution. Zero for hypercube variants.
     */
    public int getTreeMaxOpenLeaves()
    {
        return treeMaxOpenLeaves;
    }

    /**
     * Threshold variant: number of MPC parties. For GF(256) this is 256
     * ({@code 1 << dimD}); for GF(p251) it is 251 (= the prime field size).
     * The Merkle tree always has {@code 1 << dimD} max capacity but only
     * {@code getNbParties()} leaves are populated for the p251 variants.
     */
    public int getNbParties()
    {
        return field == FIELD_P251 ? 251 : (1 << dimD);
    }

    public String getName()
    {
        return name;
    }

    public int getVariant()
    {
        return variant;
    }

    public int getField()
    {
        return field;
    }

    public int getCategory()
    {
        return category;
    }

    public int getM()
    {
        return m;
    }

    public int getK()
    {
        return k;
    }

    public int getW()
    {
        return w;
    }

    public int getD()
    {
        return d;
    }

    public int getT()
    {
        return t;
    }

    public int getTau()
    {
        return tau;
    }

    public int getDimD()
    {
        return dimD;
    }

    public int getSeedSize()
    {
        return seedSize;
    }

    public int getRhoSize()
    {
        return rhoSize;
    }

    public int getSaltSize()
    {
        return saltSize;
    }

    public int getCommitSize()
    {
        return commitSize;
    }

    public int getHashSize()
    {
        return hashSize;
    }

    public int getFpointSize()
    {
        return fpointSize;
    }

    public int getHashBits()
    {
        return hashBits;
    }

    public int getXofBits()
    {
        return xofBits;
    }

    public int getWd()
    {
        return w / d;
    }

    public int getYSize()
    {
        return m - k;
    }

    public int getHaNSlice()
    {
        return (getYSize() + 127) / 128;
    }

    public int getMd()
    {
        return m / d;
    }

    public int getFpointMask()
    {
        if (fpointSize >= 4)
        {
            return -1;
        }
        return (1 << (fpointSize * 8)) - 1;
    }
}
