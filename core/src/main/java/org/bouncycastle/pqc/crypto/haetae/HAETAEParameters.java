package org.bouncycastle.pqc.crypto.haetae;

/**
 * Parameters for the HAETAE signature scheme (Modes 2, 3, and 5).
 * <p>
 * This class mirrors the constants defined in <code>params.h</code>.
 * Instances are immutable and can be shared freely.
 * </p>
 */
public class HAETAEParameters
{
    // ==================== Mode Instances ====================

    public static final HAETAEParameters haetae2 = new HAETAEParameters(
        "HAETAE-2",                     // name
        2,                              // k
        4,                              // l
        58,                             // tau
        9846.02,                        // b0
        9838.98,                        // b1
        12777.52,                       // b2
        48.858,                         // gamma
        8192,                           // ln
        4096,                           // lnHalf
        13,                             // lnBits
        39.191835884530846,             // sqnm
        1474,                           // cryptoBytes (signature length)
        132,                            // baseEncHbZ1
        7,                              // baseEncH
        512,                            // alphaHint
        9,                              // logAlphaHint
        480,                            // polyqPackedBytes
        96                              // poly2etaPackedBytes
    );

    public static final HAETAEParameters haetae3 = new HAETAEParameters(
        "HAETAE-3",
        3,                              // k
        6,                              // l
        80,                             // tau
        18314.98,                       // b0
        18307.70,                       // b1
        21906.65,                       // b2
        57.707,                         // gamma
        8192,                           // ln
        4096,                           // lnHalf
        13,                             // lnBits
        48.0,                           // sqnm
        2349,                           // cryptoBytes
        376,                            // baseEncHbZ1
        127,                            // baseEncH
        512,                            // alphaHint
        9,                              // logAlphaHint
        480,                            // polyqPackedBytes
        96                              // poly2etaPackedBytes
    );

    public static final HAETAEParameters haetae5 = new HAETAEParameters(
        "HAETAE-5",
        4,                              // k
        7,                              // l
        128,                            // tau
        22343.66,                       // b0
        22334.95,                       // b1
        24441.49,                       // b2
        55.13,                          // gamma
        8192,                           // ln
        4096,                           // lnHalf
        13,                             // lnBits
        53.0659966456864,               // sqnm
        2948,                           // cryptoBytes
        501,                            // baseEncHbZ1
        358,                            // baseEncH
        256,                            // alphaHint
        8,                              // logAlphaHint
        512,                            // polyqPackedBytes
        64                              // poly2etaPackedBytes
    );

    // ==================== Common Constants (same for all modes) ====================

    /** Size of the seed (bytes) */
    public static final int SEED_BYTES = 32;
    /** Size of the challenge hash (bytes) */
    public static final int CRH_BYTES = 64;
    /** Ring dimension N */
    public static final int N = 256;
    /** Modulus Q */
    public static final int Q = 64513;
    /** 2 * Q */
    public static final int DQ = Q * 2;
    /** η parameter (always 1) */
    public static final int ETA = 1;
    /** Packed size of a polynomial with η‑coefficients */
    public static final int POLYETA_PACKED_BYTES = 64;
    /** Packed size of a challenge polynomial */
    public static final int POLYC_PACKED_BYTES = 32;
    /** Packed size of polynomial high bits (N * 9 / 8) */
    public static final int POLY_HIGHBITS_PACKED_BYTES = N * 9 / 8; // 288

    // ==================== Instance Fields ====================

    private final String name;
    private final int k;
    private final int l;
    private final int m;               // = l - 1
    private final int tau;
    private final double b0;
    private final double b1;
    private final double b2;
    private final double gamma;
    private final int ln;
    private final int lnHalf;
    private final int lnBits;
    private final double sqnm;
    private final int cryptoBytes;      // signature size in bytes
    private final int baseEncHbZ1;
    private final int baseEncH;
    private final int alphaHint;
    private final int logAlphaHint;
    private final int polyqPackedBytes;
    private final int poly2etaPackedBytes;

    // Derived values (computed in constructor)
    private final int halfAlphaHint;
    private final long b0Sq;
    private final long b1Sq;
    private final long b2Sq;
    private final int polyveckHighbitsPackedBytes;
    private final int publicKeyBytes;
    private final int secretKeyBytes;

    // ==================== Constructor ====================

    private HAETAEParameters(
        String name,
        int k,
        int l,
        int tau,
        double b0,
        double b1,
        double b2,
        double gamma,
        int ln,
        int lnHalf,
        int lnBits,
        double sqnm,
        int cryptoBytes,
        int baseEncHbZ1,
        int baseEncH,
        int alphaHint,
        int logAlphaHint,
        int polyqPackedBytes,
        int poly2etaPackedBytes)
    {
        this.name = name;
        this.k = k;
        this.l = l;
        this.m = l - 1;
        this.tau = tau;
        this.b0 = b0;
        this.b1 = b1;
        this.b2 = b2;
        this.gamma = gamma;
        this.ln = ln;
        this.lnHalf = lnHalf;
        this.lnBits = lnBits;
        this.sqnm = sqnm;
        this.cryptoBytes = cryptoBytes;
        this.baseEncHbZ1 = baseEncHbZ1;
        this.baseEncH = baseEncH;
        this.alphaHint = alphaHint;
        this.logAlphaHint = logAlphaHint;
        this.polyqPackedBytes = polyqPackedBytes;
        this.poly2etaPackedBytes = poly2etaPackedBytes;

        // Derived values (matching the C macros)
        this.halfAlphaHint = alphaHint >> 1;
        this.b0Sq = (long)(b0 * b0);
        this.b1Sq = (long)(b1 * b1);
        this.b2Sq = (long)(b2 * b2);
        this.polyveckHighbitsPackedBytes = POLY_HIGHBITS_PACKED_BYTES * k;
        this.publicKeyBytes = SEED_BYTES + k * polyqPackedBytes;
        this.secretKeyBytes = publicKeyBytes + m * POLYETA_PACKED_BYTES + k * poly2etaPackedBytes + SEED_BYTES;
    }

    // ==================== Getters ====================

    public String getName()
    {
        return name;
    }

    public int getK()
    {
        return k;
    }

    public int getL()
    {
        return l;
    }

    public int getM()
    {
        return m;
    }

    public int getTau()
    {
        return tau;
    }

    public double getB0()
    {
        return b0;
    }

    public double getB1()
    {
        return b1;
    }

    public double getB2()
    {
        return b2;
    }

    public double getGamma()
    {
        return gamma;
    }

    public int getLn()
    {
        return ln;
    }

    public int getLnHalf()
    {
        return lnHalf;
    }

    public int getLnBits()
    {
        return lnBits;
    }

    public double getSqnm()
    {
        return sqnm;
    }

    /** Size of the signature in bytes */
    public int getCryptoBytes()
    {
        return cryptoBytes;
    }

    public int getBaseEncHbZ1()
    {
        return baseEncHbZ1;
    }

    public int getBaseEncH()
    {
        return baseEncH;
    }

    public int getAlphaHint()
    {
        return alphaHint;
    }

    public int getLogAlphaHint()
    {
        return logAlphaHint;
    }

    /** Packed size of a polynomial with coefficients modulo Q */
    public int getPolyqPackedBytes()
    {
        return polyqPackedBytes;
    }

    /** Packed size of a polynomial with coefficients in [‑2η, 2η] */
    public int getPoly2etaPackedBytes()
    {
        return poly2etaPackedBytes;
    }

    public int getHalfAlphaHint()
    {
        return halfAlphaHint;
    }

    public long getB0Sq()
    {
        return b0Sq;
    }

    public long getB1Sq()
    {
        return b1Sq;
    }

    public long getB2Sq()
    {
        return b2Sq;
    }

    public int getPolyveckHighbitsPackedBytes()
    {
        return polyveckHighbitsPackedBytes;
    }

    public int getPublicKeyBytes()
    {
        return publicKeyBytes;
    }

    public int getSecretKeyBytes()
    {
        return secretKeyBytes;
    }

    // ==================== Utility ====================

    @Override
    public String toString()
    {
        return name + " (K=" + k + ", L=" + l + ", signature=" + cryptoBytes + " bytes)";
    }
}