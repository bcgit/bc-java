package org.bouncycastle.pqc.crypto.qruov;

/**
 * Parameter sets for the QR-UOV multivariate signature scheme (NIST PQC additional
 * signatures Round 2 submission).
 * <p>
 * QR-UOV is a quotient-ring UOV variant operating over a small prime field
 * F_q with q in {7, 31, 127}, a quotient ring extension F_q^L = F_q[X]/f(X) for
 * a small irreducible f(X) = x^L - fc * x^fe - fc0, and dimensions (v, m).
 * <p>
 * The {@link #qruov_*_shake} constants use SHAKE as the pseudo-random generator
 * (matching the {@code kat_shake} test vectors); the {@link #qruov_*_aes} constants
 * use AES-CTR (matching the {@code kat_aes} test vectors). Algorithm output is
 * otherwise identical apart from the PRG-driven expansions.
 */
public class QRUOVParameters
{
    public static final int PRG_AES = 0;
    public static final int PRG_SHAKE = 1;

    // ---- SHAKE-PRG variants ----
    public static final QRUOVParameters qruov_1_q127_L3_v156_m54_shake = new QRUOVParameters(
        "qruov1q127L3v156m54-shake", 1, 127, 3, 156, 54, 1, 1, 1,
        4267, 2916, 192, 82, PRG_SHAKE);
    public static final QRUOVParameters qruov_1_q31_L3_v165_m60_shake = new QRUOVParameters(
        "qruov1q31L3v165m60-shake", 1, 31, 3, 165, 60, 1, 1, 1,
        4959, 3571, 226, 104, PRG_SHAKE);
    public static final QRUOVParameters qruov_1_q31_L10_v600_m70_shake = new QRUOVParameters(
        "qruov1q31L10v600m70-shake", 1, 31, 10, 600, 70, 5, 3, 1,
        19242, 4518, 704, 116, PRG_SHAKE);
    public static final QRUOVParameters qruov_1_q7_L10_v740_m100_shake = new QRUOVParameters(
        "qruov1q7L10v740m100-shake", 1, 7, 10, 740, 100, 2, 1, 1,
        32629, 8947, 1024, 201, PRG_SHAKE);
    public static final QRUOVParameters qruov_3_q127_L3_v228_m78_shake = new QRUOVParameters(
        "qruov3q127L3v228m78-shake", 3, 127, 3, 228, 78, 1, 1, 1,
        9020, 6123, 283, 120, PRG_SHAKE);
    public static final QRUOVParameters qruov_3_q31_L3_v246_m87_shake = new QRUOVParameters(
        "qruov3q31L3v246m87-shake", 3, 31, 3, 246, 87, 1, 1, 1,
        10878, 7655, 338, 154, PRG_SHAKE);
    public static final QRUOVParameters qruov_3_q31_L10_v890_m100_shake = new QRUOVParameters(
        "qruov3q31L10v890m100-shake", 3, 31, 10, 890, 100, 5, 3, 1,
        41974, 9507, 1046, 169, PRG_SHAKE);
    public static final QRUOVParameters qruov_3_q7_L10_v1100_m140_shake = new QRUOVParameters(
        "qruov3q7L10v1100m140-shake", 3, 7, 10, 1100, 140, 2, 1, 1,
        71432, 18461, 1526, 289, PRG_SHAKE);
    public static final QRUOVParameters qruov_5_q127_L3_v306_m105_shake = new QRUOVParameters(
        "qruov5q127L3v306m105-shake", 5, 127, 3, 306, 105, 1, 1, 1,
        16144, 11018, 380, 162, PRG_SHAKE);
    public static final QRUOVParameters qruov_5_q31_L3_v324_m114_shake = new QRUOVParameters(
        "qruov5q31L3v324m114-shake", 5, 31, 3, 324, 114, 1, 1, 1,
        18738, 13145, 447, 203, PRG_SHAKE);
    public static final QRUOVParameters qruov_5_q31_L10_v1120_m120_shake = new QRUOVParameters(
        "qruov5q31L10v1120m120-shake", 5, 31, 10, 1120, 120, 5, 3, 1,
        66236, 14326, 1324, 210, PRG_SHAKE);
    public static final QRUOVParameters qruov_5_q7_L10_v1490_m190_shake = new QRUOVParameters(
        "qruov5q7L10v1490m190-shake", 5, 7, 10, 1490, 190, 2, 1, 1,
        130305, 33694, 2065, 391, PRG_SHAKE);

    // ---- AES-CTR-PRG variants ----
    public static final QRUOVParameters qruov_1_q127_L3_v156_m54_aes = new QRUOVParameters(
        "qruov1q127L3v156m54-aes", 1, 127, 3, 156, 54, 1, 1, 1,
        4267, 2916, 192, 82, PRG_AES);
    public static final QRUOVParameters qruov_1_q31_L3_v165_m60_aes = new QRUOVParameters(
        "qruov1q31L3v165m60-aes", 1, 31, 3, 165, 60, 1, 1, 1,
        4959, 3571, 226, 104, PRG_AES);
    public static final QRUOVParameters qruov_1_q31_L10_v600_m70_aes = new QRUOVParameters(
        "qruov1q31L10v600m70-aes", 1, 31, 10, 600, 70, 5, 3, 1,
        19242, 4518, 704, 116, PRG_AES);
    public static final QRUOVParameters qruov_1_q7_L10_v740_m100_aes = new QRUOVParameters(
        "qruov1q7L10v740m100-aes", 1, 7, 10, 740, 100, 2, 1, 1,
        32629, 8947, 1024, 201, PRG_AES);
    public static final QRUOVParameters qruov_3_q127_L3_v228_m78_aes = new QRUOVParameters(
        "qruov3q127L3v228m78-aes", 3, 127, 3, 228, 78, 1, 1, 1,
        9020, 6123, 283, 120, PRG_AES);
    public static final QRUOVParameters qruov_3_q31_L3_v246_m87_aes = new QRUOVParameters(
        "qruov3q31L3v246m87-aes", 3, 31, 3, 246, 87, 1, 1, 1,
        10878, 7655, 338, 154, PRG_AES);
    public static final QRUOVParameters qruov_3_q31_L10_v890_m100_aes = new QRUOVParameters(
        "qruov3q31L10v890m100-aes", 3, 31, 10, 890, 100, 5, 3, 1,
        41974, 9507, 1046, 169, PRG_AES);
    public static final QRUOVParameters qruov_3_q7_L10_v1100_m140_aes = new QRUOVParameters(
        "qruov3q7L10v1100m140-aes", 3, 7, 10, 1100, 140, 2, 1, 1,
        71432, 18461, 1526, 289, PRG_AES);
    public static final QRUOVParameters qruov_5_q127_L3_v306_m105_aes = new QRUOVParameters(
        "qruov5q127L3v306m105-aes", 5, 127, 3, 306, 105, 1, 1, 1,
        16144, 11018, 380, 162, PRG_AES);
    public static final QRUOVParameters qruov_5_q31_L3_v324_m114_aes = new QRUOVParameters(
        "qruov5q31L3v324m114-aes", 5, 31, 3, 324, 114, 1, 1, 1,
        18738, 13145, 447, 203, PRG_AES);
    public static final QRUOVParameters qruov_5_q31_L10_v1120_m120_aes = new QRUOVParameters(
        "qruov5q31L10v1120m120-aes", 5, 31, 10, 1120, 120, 5, 3, 1,
        66236, 14326, 1324, 210, PRG_AES);
    public static final QRUOVParameters qruov_5_q7_L10_v1490_m190_aes = new QRUOVParameters(
        "qruov5q7L10v1490m190-aes", 5, 7, 10, 1490, 190, 2, 1, 1,
        130305, 33694, 2065, 391, PRG_AES);

    private final String name;
    private final int cat;
    private final int q;
    private final int L;
    private final int v;
    private final int m;
    private final int fc;
    private final int fe;
    private final int fc0;
    private final int tau1;
    private final int tau2;
    private final int tau3;
    private final int tau4;
    private final int prgType;

    private final int ceilLog2Q;
    private final int seedLen;
    private final int saltLen;
    private final int muLen = 64;
    private final int V;
    private final int M;
    private final int N;
    private final int pkBytes;
    private final int skBytes;
    private final int sigBytes;

    private QRUOVParameters(String name, int cat, int q, int L, int v, int m,
                            int fc, int fe, int fc0,
                            int tau1, int tau2, int tau3, int tau4,
                            int prgType)
    {
        this.name = name;
        this.cat = cat;
        this.q = q;
        this.L = L;
        this.v = v;
        this.m = m;
        this.fc = fc;
        this.fe = fe;
        this.fc0 = fc0;
        this.tau1 = tau1;
        this.tau2 = tau2;
        this.tau3 = tau3;
        this.tau4 = tau4;
        this.prgType = prgType;

        if (q == 7) this.ceilLog2Q = 3;
        else if (q == 31) this.ceilLog2Q = 5;
        else if (q == 127) this.ceilLog2Q = 7;
        else throw new IllegalArgumentException("unsupported q=" + q);

        if (cat == 1) this.seedLen = 16;
        else if (cat == 3) this.seedLen = 24;
        else if (cat == 5) this.seedLen = 32;
        else throw new IllegalArgumentException("unsupported security cat=" + cat);

        this.saltLen = this.seedLen;
        this.V = v / L;
        this.M = m / L;
        this.N = (v + m) / L;

        int p3Bits = m * (M * (M + 1) / 2) * L * ceilLog2Q;
        int p3Bytes = (p3Bits + 7) >>> 3;
        this.pkBytes = seedLen + p3Bytes;
        this.skBytes = 2 * seedLen;
        int sigBits = (saltLen << 3) + N * L * ceilLog2Q;
        this.sigBytes = (sigBits + 7) >>> 3;
    }

    public String getName()
    {
        return name;
    }

    public int getCategory()
    {
        return cat;
    }

    public int getQ()
    {
        return q;
    }

    public int getL()
    {
        return L;
    }

    public int getV()
    {
        return v;
    }

    public int getM()
    {
        return m;
    }

    public int getFc()
    {
        return fc;
    }

    public int getFe()
    {
        return fe;
    }

    public int getFc0()
    {
        return fc0;
    }

    public int getTau1()
    {
        return tau1;
    }

    public int getTau2()
    {
        return tau2;
    }

    public int getTau3()
    {
        return tau3;
    }

    public int getTau4()
    {
        return tau4;
    }

    public int getPrgType()
    {
        return prgType;
    }

    public int getCeilLog2Q()
    {
        return ceilLog2Q;
    }

    public int getSeedLen()
    {
        return seedLen;
    }

    public int getSaltLen()
    {
        return saltLen;
    }

    public int getMuLen()
    {
        return muLen;
    }

    public int getBigV()
    {
        return V;
    }

    public int getBigM()
    {
        return M;
    }

    public int getBigN()
    {
        return N;
    }

    public int getPublicKeyBytes()
    {
        return pkBytes;
    }

    public int getPrivateKeyBytes()
    {
        return skBytes;
    }

    public int getSignatureBytes()
    {
        return sigBytes;
    }

    int perm(int i)
    {
        return i <= (fe - 1) ? (fe - 1 - i) : (L + fe - 1 - i);
    }
}
