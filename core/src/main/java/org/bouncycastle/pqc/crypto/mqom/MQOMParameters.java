package org.bouncycastle.pqc.crypto.mqom;

/**
 * Parameter set descriptors for MQOM v2.1 ("MQ on my Mind"). Naming follows the
 * upstream <code>&lt;category&gt;-&lt;base-field&gt;-&lt;trade-off&gt;-&lt;variant&gt;</code>
 * convention used by <a href="https://github.com/mqom/mqom-v2">mqom-v2</a>.
 *
 * <p>All 48 standardised parameter sets are declared here. Whether a given set
 * is wired through to a working engine is reported by {@link MQOMEngineSupport}
 * (loaded indirectly through {@code MQOMEngine.getInstance}); declaring the
 * constants up front lets callers reference parameter names independently of
 * the engine roadmap.
 */
public class MQOMParameters
{
    public static final int BASE_FIELD_GF2   = 1;
    public static final int BASE_FIELD_GF4   = 2;
    public static final int BASE_FIELD_GF16  = 4;
    public static final int BASE_FIELD_GF256 = 8;

    public static final int EXT_FIELD_GF256   = 8;
    public static final int EXT_FIELD_GF65536 = 16;

    public static final int TRADEOFF_FAST  = 0;
    public static final int TRADEOFF_SHORT = 1;

    public static final int VARIANT_R3 = 3;
    public static final int VARIANT_R5 = 5;

    /* ---------- Category I (lambda = 128, Enc = AES-128) ---------- */

    public static final MQOMParameters mqom2_cat1_gf2_fast_r3 = new MQOMParameters(
        "mqom2-cat1-gf2-fast-r3", 128, BASE_FIELD_GF2, EXT_FIELD_GF256,
        160, 160, 17, 8, 20, 9, TRADEOFF_FAST, VARIANT_R3);
    public static final MQOMParameters mqom2_cat1_gf2_fast_r5 = new MQOMParameters(
        "mqom2-cat1-gf2-fast-r5", 128, BASE_FIELD_GF2, EXT_FIELD_GF256,
        160, 160, 17, 8, 16, 9, TRADEOFF_FAST, VARIANT_R5);
    public static final MQOMParameters mqom2_cat1_gf2_short_r3 = new MQOMParameters(
        "mqom2-cat1-gf2-short-r3", 128, BASE_FIELD_GF2, EXT_FIELD_GF65536,
        160, 160, 12, 11, 10, 8, TRADEOFF_SHORT, VARIANT_R3);
    public static final MQOMParameters mqom2_cat1_gf2_short_r5 = new MQOMParameters(
        "mqom2-cat1-gf2-short-r5", 128, BASE_FIELD_GF2, EXT_FIELD_GF65536,
        160, 160, 12, 11, 8, 8, TRADEOFF_SHORT, VARIANT_R5);

    public static final MQOMParameters mqom2_cat1_gf16_fast_r3 = new MQOMParameters(
        "mqom2-cat1-gf16-fast-r3", 128, BASE_FIELD_GF16, EXT_FIELD_GF256,
        56, 56, 17, 8, 28, 9, TRADEOFF_FAST, VARIANT_R3);
    public static final MQOMParameters mqom2_cat1_gf16_fast_r5 = new MQOMParameters(
        "mqom2-cat1-gf16-fast-r5", 128, BASE_FIELD_GF16, EXT_FIELD_GF256,
        56, 56, 17, 8, 16, 9, TRADEOFF_FAST, VARIANT_R5);
    public static final MQOMParameters mqom2_cat1_gf16_short_r3 = new MQOMParameters(
        "mqom2-cat1-gf16-short-r3", 128, BASE_FIELD_GF16, EXT_FIELD_GF65536,
        56, 56, 12, 11, 14, 8, TRADEOFF_SHORT, VARIANT_R3);
    public static final MQOMParameters mqom2_cat1_gf16_short_r5 = new MQOMParameters(
        "mqom2-cat1-gf16-short-r5", 128, BASE_FIELD_GF16, EXT_FIELD_GF65536,
        56, 56, 12, 11, 8, 8, TRADEOFF_SHORT, VARIANT_R5);

    public static final MQOMParameters mqom2_cat1_gf256_fast_r3 = new MQOMParameters(
        "mqom2-cat1-gf256-fast-r3", 128, BASE_FIELD_GF256, EXT_FIELD_GF256,
        48, 48, 17, 8, 48, 9, TRADEOFF_FAST, VARIANT_R3);
    public static final MQOMParameters mqom2_cat1_gf256_fast_r5 = new MQOMParameters(
        "mqom2-cat1-gf256-fast-r5", 128, BASE_FIELD_GF256, EXT_FIELD_GF256,
        48, 48, 17, 8, 16, 9, TRADEOFF_FAST, VARIANT_R5);
    public static final MQOMParameters mqom2_cat1_gf256_short_r3 = new MQOMParameters(
        "mqom2-cat1-gf256-short-r3", 128, BASE_FIELD_GF256, EXT_FIELD_GF65536,
        48, 48, 12, 11, 24, 8, TRADEOFF_SHORT, VARIANT_R3);
    public static final MQOMParameters mqom2_cat1_gf256_short_r5 = new MQOMParameters(
        "mqom2-cat1-gf256-short-r5", 128, BASE_FIELD_GF256, EXT_FIELD_GF65536,
        48, 48, 12, 11, 8, 8, TRADEOFF_SHORT, VARIANT_R5);

    /* ---------- Category III (lambda = 192, Enc = Rijndael-256 truncated) ---------- */

    public static final MQOMParameters mqom2_cat3_gf2_fast_r3 = new MQOMParameters(
        "mqom2-cat3-gf2-fast-r3", 192, BASE_FIELD_GF2, EXT_FIELD_GF256,
        240, 240, 27, 8, 30, 3, TRADEOFF_FAST, VARIANT_R3);
    public static final MQOMParameters mqom2_cat3_gf2_fast_r5 = new MQOMParameters(
        "mqom2-cat3-gf2-fast-r5", 192, BASE_FIELD_GF2, EXT_FIELD_GF256,
        240, 240, 27, 8, 24, 3, TRADEOFF_FAST, VARIANT_R5);
    public static final MQOMParameters mqom2_cat3_gf2_short_r3 = new MQOMParameters(
        "mqom2-cat3-gf2-short-r3", 192, BASE_FIELD_GF2, EXT_FIELD_GF65536,
        240, 240, 18, 11, 15, 12, TRADEOFF_SHORT, VARIANT_R3);
    public static final MQOMParameters mqom2_cat3_gf2_short_r5 = new MQOMParameters(
        "mqom2-cat3-gf2-short-r5", 192, BASE_FIELD_GF2, EXT_FIELD_GF65536,
        240, 240, 18, 11, 12, 12, TRADEOFF_SHORT, VARIANT_R5);

    public static final MQOMParameters mqom2_cat3_gf16_fast_r3 = new MQOMParameters(
        "mqom2-cat3-gf16-fast-r3", 192, BASE_FIELD_GF16, EXT_FIELD_GF256,
        84, 84, 27, 8, 42, 3, TRADEOFF_FAST, VARIANT_R3);
    public static final MQOMParameters mqom2_cat3_gf16_fast_r5 = new MQOMParameters(
        "mqom2-cat3-gf16-fast-r5", 192, BASE_FIELD_GF16, EXT_FIELD_GF256,
        84, 84, 27, 8, 24, 3, TRADEOFF_FAST, VARIANT_R5);
    public static final MQOMParameters mqom2_cat3_gf16_short_r3 = new MQOMParameters(
        "mqom2-cat3-gf16-short-r3", 192, BASE_FIELD_GF16, EXT_FIELD_GF65536,
        84, 84, 18, 11, 21, 12, TRADEOFF_SHORT, VARIANT_R3);
    public static final MQOMParameters mqom2_cat3_gf16_short_r5 = new MQOMParameters(
        "mqom2-cat3-gf16-short-r5", 192, BASE_FIELD_GF16, EXT_FIELD_GF65536,
        84, 84, 18, 11, 12, 12, TRADEOFF_SHORT, VARIANT_R5);

    public static final MQOMParameters mqom2_cat3_gf256_fast_r3 = new MQOMParameters(
        "mqom2-cat3-gf256-fast-r3", 192, BASE_FIELD_GF256, EXT_FIELD_GF256,
        72, 72, 27, 8, 72, 3, TRADEOFF_FAST, VARIANT_R3);
    public static final MQOMParameters mqom2_cat3_gf256_fast_r5 = new MQOMParameters(
        "mqom2-cat3-gf256-fast-r5", 192, BASE_FIELD_GF256, EXT_FIELD_GF256,
        72, 72, 27, 8, 24, 3, TRADEOFF_FAST, VARIANT_R5);
    public static final MQOMParameters mqom2_cat3_gf256_short_r3 = new MQOMParameters(
        "mqom2-cat3-gf256-short-r3", 192, BASE_FIELD_GF256, EXT_FIELD_GF65536,
        72, 72, 18, 11, 36, 12, TRADEOFF_SHORT, VARIANT_R3);
    public static final MQOMParameters mqom2_cat3_gf256_short_r5 = new MQOMParameters(
        "mqom2-cat3-gf256-short-r5", 192, BASE_FIELD_GF256, EXT_FIELD_GF65536,
        72, 72, 18, 11, 12, 12, TRADEOFF_SHORT, VARIANT_R5);

    /* ---------- Category V (lambda = 256, Enc = Rijndael-256) ---------- */

    public static final MQOMParameters mqom2_cat5_gf2_fast_r3 = new MQOMParameters(
        "mqom2-cat5-gf2-fast-r3", 256, BASE_FIELD_GF2, EXT_FIELD_GF256,
        320, 320, 36, 8, 40, 4, TRADEOFF_FAST, VARIANT_R3);
    public static final MQOMParameters mqom2_cat5_gf2_fast_r5 = new MQOMParameters(
        "mqom2-cat5-gf2-fast-r5", 256, BASE_FIELD_GF2, EXT_FIELD_GF256,
        320, 320, 36, 8, 32, 4, TRADEOFF_FAST, VARIANT_R5);
    public static final MQOMParameters mqom2_cat5_gf2_short_r3 = new MQOMParameters(
        "mqom2-cat5-gf2-short-r3", 256, BASE_FIELD_GF2, EXT_FIELD_GF65536,
        320, 320, 25, 11, 20, 6, TRADEOFF_SHORT, VARIANT_R3);
    public static final MQOMParameters mqom2_cat5_gf2_short_r5 = new MQOMParameters(
        "mqom2-cat5-gf2-short-r5", 256, BASE_FIELD_GF2, EXT_FIELD_GF65536,
        320, 320, 25, 11, 16, 6, TRADEOFF_SHORT, VARIANT_R5);

    public static final MQOMParameters mqom2_cat5_gf16_fast_r3 = new MQOMParameters(
        "mqom2-cat5-gf16-fast-r3", 256, BASE_FIELD_GF16, EXT_FIELD_GF256,
        116, 116, 36, 8, 58, 4, TRADEOFF_FAST, VARIANT_R3);
    public static final MQOMParameters mqom2_cat5_gf16_fast_r5 = new MQOMParameters(
        "mqom2-cat5-gf16-fast-r5", 256, BASE_FIELD_GF16, EXT_FIELD_GF256,
        116, 116, 36, 8, 32, 4, TRADEOFF_FAST, VARIANT_R5);
    public static final MQOMParameters mqom2_cat5_gf16_short_r3 = new MQOMParameters(
        "mqom2-cat5-gf16-short-r3", 256, BASE_FIELD_GF16, EXT_FIELD_GF65536,
        116, 116, 25, 11, 29, 6, TRADEOFF_SHORT, VARIANT_R3);
    public static final MQOMParameters mqom2_cat5_gf16_short_r5 = new MQOMParameters(
        "mqom2-cat5-gf16-short-r5", 256, BASE_FIELD_GF16, EXT_FIELD_GF65536,
        116, 116, 25, 11, 16, 6, TRADEOFF_SHORT, VARIANT_R5);

    public static final MQOMParameters mqom2_cat5_gf256_fast_r3 = new MQOMParameters(
        "mqom2-cat5-gf256-fast-r3", 256, BASE_FIELD_GF256, EXT_FIELD_GF256,
        96, 96, 36, 8, 96, 4, TRADEOFF_FAST, VARIANT_R3);
    public static final MQOMParameters mqom2_cat5_gf256_fast_r5 = new MQOMParameters(
        "mqom2-cat5-gf256-fast-r5", 256, BASE_FIELD_GF256, EXT_FIELD_GF256,
        96, 96, 36, 8, 32, 4, TRADEOFF_FAST, VARIANT_R5);
    public static final MQOMParameters mqom2_cat5_gf256_short_r3 = new MQOMParameters(
        "mqom2-cat5-gf256-short-r3", 256, BASE_FIELD_GF256, EXT_FIELD_GF65536,
        96, 96, 25, 11, 48, 6, TRADEOFF_SHORT, VARIANT_R3);
    public static final MQOMParameters mqom2_cat5_gf256_short_r5 = new MQOMParameters(
        "mqom2-cat5-gf256-short-r5", 256, BASE_FIELD_GF256, EXT_FIELD_GF65536,
        96, 96, 25, 11, 16, 6, TRADEOFF_SHORT, VARIANT_R5);

    private final String name;
    private final int securityBits;
    private final int baseFieldLog2;
    private final int extFieldLog2;
    private final int mqN;
    private final int mqM;
    private final int tau;
    private final int nbEvalsLog;
    private final int eta;
    private final int w;
    private final int tradeoff;
    private final int variant;

    private MQOMParameters(String name,
                           int securityBits,
                           int baseFieldLog2,
                           int extFieldLog2,
                           int mqN,
                           int mqM,
                           int tau,
                           int nbEvalsLog,
                           int eta,
                           int w,
                           int tradeoff,
                           int variant)
    {
        this.name = name;
        this.securityBits = securityBits;
        this.baseFieldLog2 = baseFieldLog2;
        this.extFieldLog2 = extFieldLog2;
        this.mqN = mqN;
        this.mqM = mqM;
        this.tau = tau;
        this.nbEvalsLog = nbEvalsLog;
        this.eta = eta;
        this.w = w;
        this.tradeoff = tradeoff;
        this.variant = variant;
    }

    public String getName()
    {
        return name;
    }

    public int getSecurityBits()
    {
        return securityBits;
    }

    public int getBaseFieldLog2()
    {
        return baseFieldLog2;
    }

    public int getExtFieldLog2()
    {
        return extFieldLog2;
    }

    public int getMu()
    {
        return extFieldLog2 / baseFieldLog2;
    }

    public int getMqN()
    {
        return mqN;
    }

    public int getMqM()
    {
        return mqM;
    }

    public int getTau()
    {
        return tau;
    }

    public int getNbEvalsLog()
    {
        return nbEvalsLog;
    }

    public int getNbEvals()
    {
        return 1 << nbEvalsLog;
    }

    public int getFullTreeSize()
    {
        return (1 << (nbEvalsLog + 1)) - 1;
    }

    public int getEta()
    {
        return eta;
    }

    public int getW()
    {
        return w;
    }

    public int getTradeoff()
    {
        return tradeoff;
    }

    public int getVariant()
    {
        return variant;
    }

    public int getSeedSize()
    {
        return securityBits / 8;
    }

    public int getSaltSize()
    {
        return securityBits / 8;
    }

    public int getDigestSize()
    {
        return 2 * securityBits / 8;
    }

    public int getByteSizeFieldBase(int num)
    {
        return (num * baseFieldLog2) / 8;
    }

    public int getByteSizeFieldExt(int num)
    {
        return (num * extFieldLog2) / 8;
    }

    public int getPublicKeySize()
    {
        return 2 * getSeedSize() + getByteSizeFieldExt(mqM / getMu());
    }

    public int getPrivateKeySize()
    {
        return getPublicKeySize() + getByteSizeFieldBase(mqN);
    }

    public int getOpeningSize()
    {
        return tau * (
            getByteSizeFieldBase(mqN) - getSeedSize()
                + nbEvalsLog * getSeedSize()
                + getDigestSize());
    }

    public int getSignatureSize()
    {
        return 4
            + tau * getByteSizeFieldBase(eta * getMu())
            + getSaltSize()
            + 2 * getDigestSize()
            + getOpeningSize();
    }
}
