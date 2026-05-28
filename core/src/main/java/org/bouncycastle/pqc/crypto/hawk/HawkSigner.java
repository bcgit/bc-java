package org.bouncycastle.pqc.crypto.hawk;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

/**
 * Lightweight Hawk signer / verifier. Implements
 * {@link MessageSigner}: initialise with a {@link HawkPrivateKeyParameters}
 * (optionally wrapped in {@link ParametersWithRandom}) for signing, or with a
 * {@link HawkPublicKeyParameters} for verification, then call
 * {@link #generateSignature(byte[])} / {@link #verifySignature(byte[], byte[])}.
 *
 * <p>{@link #generateSignature(byte[])} returns the signature bytes only; the
 * NIST {@code crypto_sign} "signed message" form ({@code msg || sig}) is
 * reconstructed by callers when needed.</p>
 */
public class HawkSigner
    implements MessageSigner
{
    private SecureRandom random;
    private static final int Q = 18433;
    private SHAKEDigest digest = new SHAKEDigest(256);
    private static final short[] GM = new short[]
        {
            4564, 17110, 12162, 16208, 10701, 9705, 3451, 5078,
            12400, 10202, 8245, 13131, 4631, 3492, 17179, 5622,
            5537, 3399, 2485, 9938, 345, 14064, 10152, 789,
            5092, 15713, 12632, 6516, 16107, 2314, 15385, 17281,
            383, 5515, 5019, 13218, 3293, 4728, 9704, 14263,
            4417, 218, 16011, 2568, 5635, 8516, 18352, 12887,
            13102, 15257, 14316, 12813, 8886, 11051, 13356, 15353,
            12059, 6880, 17926, 11710, 8052, 1737, 16384, 18094,
            3410, 14787, 13788, 14210, 2656, 17550, 7950, 4311,
            18150, 4973, 11548, 7848, 15326, 15517, 97, 11648,
            17990, 17685, 10847, 14695, 282, 1558, 6535, 10743,
            2399, 181, 10165, 8051, 12204, 18401, 13377, 7233,
            10892, 15728, 15002, 11766, 8462, 15245, 12420, 8613,
            5053, 12360, 17415, 12678, 4606, 870, 8429, 9572,
            6542, 1892, 4008, 17045, 371, 10155, 819, 15114,
            1522, 13638, 16576, 17586, 16840, 7671, 13873, 12065,
            7433, 7599, 2497, 5298, 16406, 3443, 9437, 6905,
            14589, 17851, 209, 17496, 1698, 7028, 4444, 8211,
            9159, 16089, 16741, 9085, 2658, 4488, 8650, 3995,
            6532, 11903, 508, 192, 4039, 17347, 12742, 6993,
            14812, 17645, 4527, 695, 8380, 16230, 2153, 3136,
            2133, 4725, 9230, 13213, 6548, 18005, 6108, 16097,
            16952, 13519, 16207, 12802, 16047, 7081, 12818, 8328,
            17091, 8927, 9558, 9273, 9301, 10337, 11142, 5082,
            11846, 15508, 17108, 8498, 16135, 3776, 6752, 12857,
            3590, 486, 3056, 4203, 10364, 17125, 14532, 3025,
            18386, 12029, 1983, 7426, 13553, 623, 6269, 15287,
            16399, 12294, 6987, 8011, 1378, 14019, 3042, 3472,
            4734, 12820, 16363, 7781, 3644, 16472, 3523, 14104,
            11521, 18288, 13956, 4549, 6314, 16320, 16373, 16203,
            15299, 7524, 9080, 15914, 17765, 12520, 5829, 13379,
            9482, 7938, 760, 13350, 9526, 15502, 16160, 6398,
            7067, 1655, 3428, 7827, 10564, 1235, 10800, 8291,
            15614, 14755, 8732, 3010, 12821, 7168, 8131, 1912,
            8093, 10461, 12301, 11616, 13947, 8029, 15138, 8334,
            13345, 13462, 7201, 11285, 8232, 5869, 5652, 8087,
            9232, 151, 5425, 15984, 9061, 10972, 874, 6136,
            9299, 4966, 10442, 5398, 6605, 14398, 7625, 7091,
            10974, 14743, 6836, 17243, 504, 7883, 10503, 12533,
            3111, 13658, 1303, 6153, 12791, 335, 16064, 6652,
            14432, 10970, 558, 5436, 300, 13031, 12835, 7899,
            8435, 7252, 2970, 12879, 2786, 16438, 16584, 2204,
            5974, 6467, 7971, 14624, 9637, 9448, 18144, 7293,
            18121, 10042, 1398, 12430, 157, 6881, 18084, 12060,
            5783, 444, 14853, 7936, 13337, 10411, 4401, 12549,
            17699, 1174, 1162, 5374, 3796, 709, 1424, 8521,
            2238, 991, 9114, 15056, 4900, 16221, 731, 18419,
            14885, 1707, 11644, 7594, 14783, 4281, 12810, 5277,
            10528, 15155, 16633, 13979, 5573, 7912, 15085, 4250,
            13224, 11094, 1717, 11970, 4689, 11787, 613, 14891,
            6892, 1734, 15910, 17044, 1022, 16497, 7473, 4421,
            17061, 2094, 17491, 14013, 1872, 13480, 10045, 17585,
            1562, 10460, 12143, 11266, 2168, 15769, 3047, 7683,
            14260, 9889, 14090, 14179, 4404, 11389, 11461, 4622,
            18349, 14047, 7466, 13272, 5005, 12487, 615, 1829,
            13229, 15305, 3467, 11180, 2855, 8191, 3868, 9735,
            18383, 13189, 933, 7900, 18340, 17527, 4316, 14694,
            5680, 9549, 15669, 5777, 17938, 7070, 11080, 4478,
            1466, 10714, 15409, 8001, 7888, 3707, 14283, 7140,
            3046, 14214, 15419, 16423, 18200, 10217, 10615, 18381,
            13138, 1337, 8483, 7125, 6741, 10966, 18359, 4036,
            11656, 2954, 5907, 1652, 12095, 11393, 12093, 6022,
            11472, 6513, 15239, 12291, 16914, 3635, 2907, 373,
            12897, 8503, 16298, 8337, 10348, 11023, 8932, 5553,
            12984, 11729, 9882, 13024, 556, 65, 10270, 4317,
            14404, 9508, 9191, 9860, 14257, 11049, 13040, 14653,
            13038, 9282, 10349, 4492, 6555, 9154, 8558, 14991,
            4583, 3619, 379, 13206, 11105, 7100, 15820, 14978,
            7277, 12620, 3196, 11513, 7268, 16100, 46, 12935,
            10191, 4142, 9281, 11926, 14900, 14340, 16894, 5224,
            9309, 13388, 13942, 3818, 2937, 7206, 14135, 15212,
            7925, 1689, 8800, 1294, 5524, 14570, 16368, 11992,
            9491, 4458, 3910, 11928, 13598, 1656, 3586, 8177,
            13056, 2322, 16649, 1648, 14699, 18328, 1843, 116,
            10016, 4221, 3330, 2710, 5358, 11169, 13567, 1354,
            8715, 3439, 8805, 5505, 10680, 17825, 14534, 8396,
            4185, 3904, 8543, 2358, 13314, 13160, 14784, 16183,
            3842, 13644, 17524, 1253, 13782, 16530, 12687, 15971,
            13700, 17515, 2420, 10494, 7049, 8615, 15561, 10671,
            10485, 1060, 1583, 2340, 6599, 16718, 5525, 8039,
            12196, 15350, 10577, 8497, 16786, 10118, 13406, 2164,
            696, 7375, 3971, 630, 13829, 4501, 10704, 8545,
            8124, 10763, 4718, 6718, 13636, 11540, 16886, 2173,
            13510, 4961, 9652, 3648, 3009, 16232, 2469, 3836,
            4933, 3461, 12281, 13205, 11756, 13442, 4041, 4285,
            3661, 16043, 9473, 11418, 13814, 10301, 5454, 10915,
            8727, 17232, 13005, 3609, 9965, 5508, 3913, 10768,
            11368, 3716, 15705, 10290, 10822, 12073, 8935, 4393,
            3878, 18157, 11691, 13998, 11637, 16445, 17690, 4654,
            12911, 9234, 2765, 6125, 12586, 12014, 18046, 2176,
            17540, 7355, 811, 12063, 17878, 11837, 8513, 13958,
            16653, 12390, 3722, 4745, 7749, 8299, 2499, 10669,
            16214, 3951, 15969, 375, 13937, 18040, 11638, 9914,
            16136, 15678, 7102, 12699, 9368, 15152, 16159, 12929,
            14186, 13925, 6623, 7438, 5741, 16684, 153, 14572,
            14261, 3358, 14440, 14021, 15097, 18043, 12112, 10964,
            5242, 13012, 9833, 1249, 16386, 5032, 2437, 10065,
            1738, 3850, 11, 1891, 3970, 7161, 7025, 17895,
            6303, 14429, 12523, 17941, 6931, 5087, 11127, 10882,
            13926, 16149, 7788, 11652, 8944, 913, 15223, 6189,
            9511, 2869, 10910, 8768, 6262, 5705, 16606, 5986,
            10784, 2189, 14068, 10397, 14897, 15500, 15844, 5698,
            5743, 3622, 853, 14256, 9576, 2313, 15227, 16931,
            3810, 1440, 6324, 6309, 3400, 6365, 10288, 15790,
            16146, 5667, 10602, 11119, 5700, 7960, 4236, 2617,
            12801, 8757, 1131, 5072, 16068, 17394, 1735, 5010,
            2908, 12275, 3985, 1361, 17206, 13615, 12942, 9536,
            12505, 6468, 8129, 14974, 2983, 1708, 11802, 7944,
            17712, 8436, 5712, 3320, 13774, 13479, 9887, 17235,
            4487, 3873, 3645, 9941, 16825, 13471, 8623, 14435,
            5656, 396, 7269, 9569, 935, 13271, 13889, 18167,
            6320, 14000, 40, 15255, 4382, 7607, 3761, 8098,
            15702, 11450, 2666, 7539, 13722, 2864, 10120, 7018,
            11627, 8023, 14190, 6234, 15359, 2757, 11647, 6434,
            1917, 14513, 7362, 10475, 985, 82, 12956, 10267,
            10798, 2920, 535, 8185, 17135, 16491, 6525, 2321,
            11245, 14410, 9521, 11291, 4326, 4683, 2594, 16946,
            12878, 3561, 9648, 11339, 9944, 13628, 14996, 14086,
            16837, 8831, 12823, 12539, 2930, 16057, 11685, 16318,
            11722, 14300, 10574, 9657, 17379, 8165, 18193, 635,
            17483, 10962, 17727, 2636, 16666, 1219, 8272, 2691,
            15755, 15534, 2783, 17598, 9028, 5299, 7757, 11350,
            9421, 803, 16276, 4555, 2408, 15134, 13315, 6629,
            2575, 12004, 16466, 17109, 14006, 9793, 17355, 17445,
            9993, 6970, 13713, 6344, 17481, 5591, 17027, 2952,
            268, 827, 1635, 12955, 8609, 13704, 8571, 3820,
            15205, 13149, 13046, 12333, 8005, 13766, 18367, 7087,
            5414, 14093, 14734, 10939, 12282, 6674, 3811, 13342
        };
    private static final long Q0I = 3955247103L;
    private static final int R2 = 806;
    //private
    /*
     * Tables for the Gaussian sampler: we have two distributions over 2*Z,
     * with the same standard deviation 2*sigma. Given:
     *    p(x) = exp(-(x^2) / 2*(2*sigma)^2)
     * Then, for integers k:
     *    D0(2*k) = p(2*k) / \sum_j p(2*j)
     *    D1(2*k) = p(2*k-1) / \sum_j p(2*j-1)
     * D0 is centred on 0, while D1 is centred on 1. Both distributions only
     * return even integers.
     *
     * Let P0(x) = P(|X0| >= x)  (with X0 selected with distribution D0).
     * Let P1(x) = P(|X1| >= x)  (with X1 selected with distribution D1).
     * For integers k >= 0, we define the table T:
     *    T[2*k]   = floor(P0(2*(k+1)) * 2^78)
     *    T[2*k+1] = floor(P1(2*(k+1)+1) * 2^78)
     * Each 78-bit value is split into a high part ("hi") of 15 bits, and
     * a low part ("lo") of 63 bits.
     */

    // Hawk-256 (logn = 8, n = 256)
    public static final short[] SIG_GAUSS_HI_HAWK_256 = {
        (short)0x4D70, (short)0x268B,
        (short)0x0F80, (short)0x04FA,
        (short)0x0144, (short)0x0041,
        (short)0x000A, (short)0x0001
    };

    public static final int SG_MAX_HI_HAWK_256 = SIG_GAUSS_HI_HAWK_256.length;

    public static final long[] SIG_GAUSS_LO_HAWK_256 = {
        0x71FBD58485D45050L, 0x1408A4B181C718B1L,
        0x54114F1DC2FA7AC9L, 0x614569CC54722DC9L,
        0x42F74ADDA0B5AE61L, 0x151C5CDCBAFF49A3L,
        0x252E2152AB5D758BL, 0x23460C30AC398322L,
        0x0FDE62196C1718FCL, 0x01355A8330C44097L,
        0x00127325DDF8CEBAL, 0x0000DC8DE401FD12L,
        0x000008100822C548L, 0x0000003B0FFB28F0L,
        0x0000000152A6E9AEL, 0x0000000005EFCD99L,
        0x000000000014DA4AL, 0x0000000000003953L,
        0x000000000000007BL, 0x0000000000000000L
    };

    public static final int SG_MAX_LO_HAWK_256 = SIG_GAUSS_LO_HAWK_256.length;

    // Hawk-512 (logn = 9, n = 512)
    public static final short[] SIG_GAUSS_HI_HAWK_512 = {
        (short)0x580B, (short)0x35F9,
        (short)0x1D34, (short)0x0DD7,
        (short)0x05B7, (short)0x020C,
        (short)0x00A2, (short)0x002B,
        (short)0x000A, (short)0x0001
    };

    public static final int SG_MAX_HI_HAWK_512 = SIG_GAUSS_HI_HAWK_512.length;

    public static final long[] SIG_GAUSS_LO_HAWK_512 = {
        0x0C27920A04F8F267L, 0x3C689D9213449DC9L,
        0x1C4FF17C204AA058L, 0x7B908C81FCE3524FL,
        0x5E63263BE0098FFDL, 0x4EBEFD8FF4F07378L,
        0x56AEDFB0876A3BD8L, 0x4628BC6B23887196L,
        0x061E21D588CC61CCL, 0x7F769211F07B326FL,
        0x2BA568D92EEC18E7L, 0x0668F461693DFF8FL,
        0x00CF0F8687D3B009L, 0x001670DB65964485L,
        0x000216A0C344EB45L, 0x00002AB6E11C2552L,
        0x000002EDF0B98A84L, 0x0000002C253C7E81L,
        0x000000023AF3B2E7L, 0x0000000018C14ABFL,
        0x0000000000EBCC6AL, 0x000000000007876EL,
        0x00000000000034CFL, 0x000000000000013DL,
        0x0000000000000006L, 0x0000000000000000L
    };

    public static final int SG_MAX_LO_HAWK_512 = SIG_GAUSS_LO_HAWK_512.length;

    // Hawk-1024 (logn = 10, n = 1024)
    public static final short[] SIG_GAUSS_HI_HAWK_1024 = {
        (short)0x58B0, (short)0x36FE,
        (short)0x1E3A, (short)0x0EA0,
        (short)0x0632, (short)0x024A,
        (short)0x00BC, (short)0x0034,
        (short)0x000C, (short)0x0002
    };

    public static final int SG_MAX_HI_HAWK_1024 = SIG_GAUSS_HI_HAWK_1024.length;

    public static final long[] SIG_GAUSS_LO_HAWK_1024 = {
        0x3AAA2EB76504E560L, 0x01AE2B17728DF2DEL,
        0x70E1C03E49BB683EL, 0x6A00B82C69624C93L,
        0x55CDA662EF2D1C48L, 0x2685DB30348656A4L,
        0x31E874B355421BB7L, 0x430192770E205503L,
        0x57C0676C029895A7L, 0x5353BD4091AA96DBL,
        0x3D4D67696E51F820L, 0x09915A53D8667BEEL,
        0x014A1A8A93F20738L, 0x0026670030160D5FL,
        0x0003DAF47E8DFB21L, 0x0000557CD1C5F797L,
        0x000006634617B3FFL, 0x0000006965E15B13L,
        0x00000005DBEFB646L, 0x0000000047E9AB38L,
        0x0000000002F93038L, 0x00000000001B2445L,
        0x000000000000D5A7L, 0x00000000000005AAL,
        0x0000000000000021L, 0x0000000000000000L
    };

    public static final int SG_MAX_LO_HAWK_1024 = SIG_GAUSS_LO_HAWK_1024.length;
    private HawkEngine engine;
    private HawkParameters params;
    private HawkPublicKeyParameters pubKey;
    private HawkPrivateKeyParameters privKey;

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (HawkPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (HawkPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
            params = privKey.getParameters();
        }
        else
        {
            pubKey = (HawkPublicKeyParameters)param;
            params = pubKey.getParameters();
            privKey = null;
            random = null;
        }
        engine = new HawkEngine();
    }

    public byte[] generateSignature(byte[] message)
    {
        int logn = params.logn;
        int sigLen = hawkSigSize(logn);
        byte[] sig = new byte[sigLen];

        SHAKEDigest sc = new SHAKEDigest(256);
        sc.update(message, 0, message.length);

        byte[] tmp = new byte[hawkTmpSizeSign(logn)];
        int result = hawkSignFinish(logn, sig, sc, privKey.getEncoded(), tmp, tmp.length);
        if (result == 0)
        {
            throw new IllegalStateException("Signing failed");
        }
        return sig;
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        if (pubKey == null)
        {
            throw new IllegalStateException("HawkSigner not initialized for verification");
        }
        int logn = params.logn;
        if (signature.length != HawkVerifier.hawkSigSize(logn))
        {
            return false;
        }
        SHAKEDigest sc = new SHAKEDigest(256);
        sc.update(message, 0, message.length);
        return HawkVerifier.verifyInner(logn, signature, 0, sc, pubKey.getEncoded());
    }

    // Start signing process
    public static SHAKEDigest hawkSignStart()
    {
        return new SHAKEDigest(256);
    }

    // Finish signing process
    public int hawkSignFinish(int logn, byte[] sig,
                              SHAKEDigest scData, byte[] priv,
                              byte[] tmp, int tmpLen)
    {
        return signFinishInner(logn, 1, sig, scData, priv, hawkPrivKeySize(logn), tmp, tmpLen);
    }

    // Basis multiplication modulo 2
    public static void basisM2Mul(int logn,
                                  byte[] t0, int t0Offset,
                                  byte[] t1, int t1Offset,
                                  byte[] h0, int h0Offset,
                                  byte[] h1, int h1Offset,
                                  byte[] f2, int f2Offset,
                                  byte[] g2, int g2Offset,
                                  byte[] F2, int F2Offset,
                                  byte[] G2, int G2Offset,
                                  byte[] tmp, int tmpOffset)
    {
        int n = 1 << logn;
        int byteLen = n >> 3;

        int w1Offset = tmpOffset;
        int w2Offset = w1Offset + byteLen;

        switch (logn)
        {
        case 8:
            bpMulmod256(t0, t0Offset, h0, h0Offset, f2, f2Offset, tmp, w2Offset);
            bpMulmod256(tmp, w1Offset, h1, h1Offset, F2, F2Offset, tmp, w2Offset);
            bpXor256(t0, t0Offset, t0, t0Offset, tmp, w1Offset);
            bpMulmod256(t1, t1Offset, h0, h0Offset, g2, g2Offset, tmp, w2Offset);
            bpMulmod256(tmp, w1Offset, h1, h1Offset, G2, G2Offset, tmp, w2Offset);
            bpXor256(t1, t1Offset, t1, t1Offset, tmp, w1Offset);
            break;
        case 9:
            bpMulmod512(t0, t0Offset, h0, h0Offset, f2, f2Offset, tmp, w2Offset);
            bpMulmod512(tmp, w1Offset, h1, h1Offset, F2, F2Offset, tmp, w2Offset);
            bpXor512(t0, t0Offset, t0, t0Offset, tmp, w1Offset);
            bpMulmod512(t1, t1Offset, h0, h0Offset, g2, g2Offset, tmp, w2Offset);
            bpMulmod512(tmp, w1Offset, h1, h1Offset, G2, G2Offset, tmp, w2Offset);
            bpXor512(t1, t1Offset, t1, t1Offset, tmp, w1Offset);
            break;
        case 10:
            bpMulmod1024(t0, t0Offset, h0, h0Offset, f2, f2Offset, tmp, w2Offset);
            bpMulmod1024(tmp, w1Offset, h1, h1Offset, F2, F2Offset, tmp, w2Offset);
            bpXor1024(t0, t0Offset, t0, t0Offset, tmp, w1Offset);
            bpMulmod1024(t1, t1Offset, h0, h0Offset, g2, g2Offset, tmp, w2Offset);
            bpMulmod1024(tmp, w1Offset, h1, h1Offset, G2, G2Offset, tmp, w2Offset);
            bpXor1024(t1, t1Offset, t1, t1Offset, tmp, w1Offset);
            break;
        default:
            throw new IllegalArgumentException("Unsupported logn: " + logn);
        }
    }

    // Binary polynomial multiplication modulo x^n + 1 (Karatsuba implementation)
    private static void bpMulmod256(byte[] d, int dOffset, byte[] a, int aOffset,
                                    byte[] b, int bOffset, byte[] tmp, int tmpOffset)
    {
        bpMulmodGeneric(256, 128, d, dOffset, a, aOffset, b, bOffset, tmp, tmpOffset);
    }

    private static void bpMulmod512(byte[] d, int dOffset, byte[] a, int aOffset,
                                    byte[] b, int bOffset, byte[] tmp, int tmpOffset)
    {
        bpMulmodGeneric(512, 256, d, dOffset, a, aOffset, b, bOffset, tmp, tmpOffset);
    }

    private static void bpMulmod1024(byte[] d, int dOffset, byte[] a, int aOffset,
                                     byte[] b, int bOffset, byte[] tmp, int tmpOffset)
    {
        bpMulmodGeneric(1024, 512, d, dOffset, a, aOffset, b, bOffset, tmp, tmpOffset);
    }

    // Generic binary polynomial multiplication using Karatsuba algorithm
    private static void bpMulmodGeneric(int n, int hn, byte[] d, int dOffset,
                                        byte[] a, int aOffset, byte[] b, int bOffset,
                                        byte[] tmp, int tmpOffset)
    {
        int byteLen = n / 8;
        int halfByteLen = hn / 8;

        int t1Offset = tmpOffset;
        int t2Offset = t1Offset + byteLen;

        // t1 <- (a0 + a1)*(b0 + b1)
        bpXor(hn, d, dOffset, a, aOffset, a, aOffset + halfByteLen);
        bpXor(hn, d, dOffset + halfByteLen, b, bOffset, b, bOffset + halfByteLen);
        bpXor(n, tmp, t1Offset, d, dOffset, d, dOffset + halfByteLen);
        Arrays.fill(tmp, t1Offset, t1Offset + byteLen, (byte)0);
        bpMuladd(hn, tmp, t1Offset, d, dOffset, d, dOffset + halfByteLen, tmp, t2Offset);

        // d <- a0*b0 + a1*b1
        Arrays.fill(d, dOffset, dOffset + byteLen, (byte)0);
        bpMuladd(hn, d, dOffset, a, aOffset, b, bOffset, tmp, t2Offset);
        bpMuladd(hn, d, dOffset, a, aOffset + halfByteLen, b, bOffset + halfByteLen, tmp, t2Offset);

        // t1 <- t1 + d = a0*b1 + a1*b0
        bpXor(n, tmp, t1Offset, tmp, t1Offset, d, dOffset);

        // d <- d + rotate_{n/2}(t1)
        bpXor(hn, d, dOffset, d, dOffset, tmp, t1Offset + halfByteLen);
        bpXor(hn, d, dOffset + halfByteLen, d, dOffset + halfByteLen, tmp, t1Offset);
    }

    // Binary polynomial multiplication and accumulation
// Constants for sizes
    public static final int SIZE_64 = 64;
    public static final int SIZE_128 = 128;
    public static final int SIZE_256 = 256;
    public static final int SIZE_512 = 512;

    // Precomputed byte lengths
    private static final int BYTES_64 = SIZE_64 / 8;
    private static final int BYTES_128 = SIZE_128 / 8;
    private static final int BYTES_256 = SIZE_256 / 8;
    private static final int BYTES_512 = SIZE_512 / 8;

    /**
     * Binary polynomial multiplication using Karatsuba algorithm
     * d += a * b (polynomial multiplication in GF(2))
     */
    public static void bpMuladd(int size, byte[] d, int dOffset,
                                byte[] a, int aOffset,
                                byte[] b, int bOffset,
                                byte[] tmp, int tmpOffset)
    {
        switch (size)
        {
        case SIZE_64:
            bpMuladd64(d, dOffset, a, aOffset, b, bOffset, tmp, tmpOffset);
            break;
        case SIZE_128:
            bpMuladd128(d, dOffset, a, aOffset, b, bOffset, tmp, tmpOffset);
            break;
        case SIZE_256:
            bpMuladd256(d, dOffset, a, aOffset, b, bOffset, tmp, tmpOffset);
            break;
        case SIZE_512:
            bpMuladd512(d, dOffset, a, aOffset, b, bOffset, tmp, tmpOffset);
            break;
        default:
            throw new IllegalArgumentException("Unsupported size: " + size);
        }
    }

    // Specialized implementations for better performance
    public static void bpMuladd128(byte[] d, int dOffset,
                                   byte[] a, int aOffset,
                                   byte[] b, int bOffset,
                                   byte[] tmp, int tmpOffset)
    {
        // Use optimized implementation for 128-bit polynomials
        int t1Offset = tmpOffset;
        int t2Offset = t1Offset + BYTES_128;

        // Karatsuba algorithm for 128-bit polynomials (split into 64-bit halves)
        bpXor64(tmp, t2Offset, a, aOffset, a, aOffset + BYTES_64); // a0 + a1
        bpXor64(tmp, t2Offset + BYTES_64, b, bOffset, b, bOffset + BYTES_64); // b0 + b1

        // t1 = (a0+a1)*(b0+b1) + d0 + d1
        bpXor128(tmp, t1Offset, d, dOffset, d, dOffset + BYTES_128);
        bpMuladd64(tmp, t1Offset, tmp, t2Offset, tmp, t2Offset + BYTES_64, tmp, t2Offset + BYTES_128);

        // d0 += a0*b0
        bpMuladd64(d, dOffset, a, aOffset, b, bOffset, tmp, t2Offset);

        // d1 += a1*b1
        bpMuladd64(d, dOffset + BYTES_128, a, aOffset + BYTES_64, b, bOffset + BYTES_64, tmp, t2Offset);

        // t1 = t1 + d0 + d1 = a0*b1 + a1*b0
        bpXor128(tmp, t1Offset, tmp, t1Offset, d, dOffset);
        bpXor128(tmp, t1Offset, tmp, t1Offset, d, dOffset + BYTES_128);

        // d += (x^64)*t1: d[8:24] ⊕= t1[0:16]
        bpXor128(d, dOffset + BYTES_64, d, dOffset + BYTES_64, tmp, t1Offset);
    }

    // Similar optimized implementations for 256 and 512 would follow...

    // Fast XOR implementation using long operations
    public static void bpXor64(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset)
    {
        // Process 64 bits as a single long
        long aVal = bytesToLong(a, aOffset);
        long bVal = bytesToLong(b, bOffset);
        long result = aVal ^ bVal;
        longToBytes(result, d, dOffset);
    }

    public static void bpXor128(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset)
    {
        // Process as two 64-bit chunks
        bpXor64(d, dOffset, a, aOffset, b, bOffset);
        bpXor64(d, dOffset + 8, a, aOffset + 8, b, bOffset + 8);
    }

    // Utility methods for size calculations
    public static int getTmpSize(int polynomialSize)
    {
        switch (polynomialSize)
        {
        case SIZE_64:
            return BYTES_64 * 4;  // t1(8) + t2(8) + t3(8) + extra
        case SIZE_128:
            return BYTES_128 * 3; // t1(16) + t2(16) + t3(16)
        case SIZE_256:
            return BYTES_256 * 3; // t1(32) + t2(32) + t3(32)
        case SIZE_512:
            return BYTES_512 * 3; // t1(64) + t2(64) + t3(64)
        default:
            throw new IllegalArgumentException("Unsupported size: " + polynomialSize);
        }
    }


    private static void bpXor256(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset)
    {
        for (int u = 0; u < 32; u++)
        {
            d[dOffset + u] = (byte)(a[aOffset + u] ^ b[bOffset + u]);
        }
    }

    private static void bpXor512(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset)
    {
        for (int u = 0; u < 64; u++)
        {
            d[dOffset + u] = (byte)(a[aOffset + u] ^ b[bOffset + u]);
        }
    }

    private static void bpXor1024(byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset)
    {
        for (int u = 0; u < 128; u++)
        {
            d[dOffset + u] = (byte)(a[aOffset + u] ^ b[bOffset + u]);
        }
    }

    // Generic XOR for any size
    private static void bpXor(int bitSize, byte[] d, int dOffset, byte[] a, int aOffset, byte[] b, int bOffset)
    {
        int byteSize = bitSize / 8;
        for (int u = 0; u < byteSize; u++)
        {
            d[dOffset + u] = (byte)(a[aOffset + u] ^ b[bOffset + u]);
        }
    }

    /**
     * Binary polynomial multiplication and accumulation for 64-bit polynomials
     * d += a * b (polynomial multiplication in GF(2))
     * <p>
     * This is a direct translation of the C function that uses 32-bit halves
     * for efficient polynomial multiplication in GF(2)
     */
    public static void bpMuladd64(byte[] d, int dOffset,
                                  byte[] a, int aOffset,
                                  byte[] b, int bOffset,
                                  byte[] tmp, int tmpOffset)
    {
        // tmp parameter is unused in this implementation, following the C code

        // Decode 32-bit halves from little-endian bytes
        int a0 = dec32le(a, aOffset);      // First 32 bits of a
        int a1 = dec32le(a, aOffset + 4);  // Second 32 bits of a
        int b0 = dec32le(b, bOffset);      // First 32 bits of b
        int b1 = dec32le(b, bOffset + 4);  // Second 32 bits of b

        // Compute the three 64-bit polynomial products using Karatsuba approach
        long c0 = bpMul32(a0, b0);         // a0 * b0
        long c1 = bpMul32(a1, b1);         // a1 * b1
        // (a0 + a1) * (b0 + b1) - c0 - c1 = a0*b1 + a1*b0
        long c2 = bpMul32(a0 ^ a1, b0 ^ b1) ^ c0 ^ c1;

        // Combine results and accumulate into destination
        // Lower 64 bits: c0 ^ (c2 << 32)
        long lowerResult = dec64le(d, dOffset) ^ c0 ^ (c2 << 32);
        // Upper 64 bits: c1 ^ (c2 >>> 32)
        long upperResult = dec64le(d, dOffset + 8) ^ c1 ^ (c2 >>> 32);

        // Encode results back to little-endian bytes
        enc64le(d, dOffset, lowerResult);
        enc64le(d, dOffset + 8, upperResult);
    }

    /**
     * Decode 32-bit little-endian value from byte array
     * This is a direct translation of the C dec32le function
     */
    public static int dec32le(byte[] src, int srcOffset)
    {
        return (src[srcOffset] & 0xFF) |
            ((src[srcOffset + 1] & 0xFF) << 8) |
            ((src[srcOffset + 2] & 0xFF) << 16) |
            ((src[srcOffset + 3] & 0xFF) << 24);
    }

    /**
     * Optimized binary polynomial multiplication of two 32-bit values in GF(2)
     * Returns 64-bit product (carry-less multiplication)
     * <p>
     * This implements the same "classic technique" as the C code using
     * the 4-way decomposition with masks
     */
    public static long bpMul32(int x, int y)
    {
        // Extract bits with specific masks to create "holes" for carries
        int x0 = x & 0x11111111;  // Every 4th bit, starting at bit 0
        int x1 = x & 0x22222222;  // Every 4th bit, starting at bit 1
        int x2 = x & 0x44444444;  // Every 4th bit, starting at bit 2
        int x3 = x & 0x88888888;  // Every 4th bit, starting at bit 3

        int y0 = y & 0x11111111;
        int y1 = y & 0x22222222;
        int y2 = y & 0x44444444;
        int y3 = y & 0x88888888;

        // Perform the 4x4 multiplication in GF(2) - equivalent to carry-less multiplication
        long z0 = mul64(x0, y0) ^ mul64(x1, y3) ^ mul64(x2, y2) ^ mul64(x3, y1);
        long z1 = mul64(x0, y1) ^ mul64(x1, y0) ^ mul64(x2, y3) ^ mul64(x3, y2);
        long z2 = mul64(x0, y2) ^ mul64(x1, y1) ^ mul64(x2, y0) ^ mul64(x3, y3);
        long z3 = mul64(x0, y3) ^ mul64(x1, y2) ^ mul64(x2, y1) ^ mul64(x3, y0);

        // Apply masks to isolate the bits in their proper positions
        z0 &= 0x1111111111111111L;
        z1 &= 0x2222222222222222L;
        z2 &= 0x4444444444444444L;
        z3 &= 0x8888888888888888L;

        // Combine all the partial results
        return z0 | z1 | z2 | z3;
    }

    private static long mul64(int a, int b)
    {
        // Convert to long to avoid sign extension issues, then multiply
        return (a & 0xFFFFFFFFL) * (b & 0xFFFFFFFFL);
    }

    /**
     * Encode 64-bit value as little-endian bytes
     * This is a direct translation of the C enc64le function
     */
    public static void enc64le(byte[] dst, int dstOffset, long x)
    {
        dst[dstOffset] = (byte)(x & 0xFF);
        dst[dstOffset + 1] = (byte)((x >>> 8) & 0xFF);
        dst[dstOffset + 2] = (byte)((x >>> 16) & 0xFF);
        dst[dstOffset + 3] = (byte)((x >>> 24) & 0xFF);
        dst[dstOffset + 4] = (byte)((x >>> 32) & 0xFF);
        dst[dstOffset + 5] = (byte)((x >>> 40) & 0xFF);
        dst[dstOffset + 6] = (byte)((x >>> 48) & 0xFF);
        dst[dstOffset + 7] = (byte)((x >>> 56) & 0xFF);
    }

    /**
     * Binary polynomial multiplication and accumulation for 256-bit polynomials
     * Uses Karatsuba algorithm with 128-bit halves
     */
    public static void bpMuladd256(byte[] d, int dOffset,
                                   byte[] a, int aOffset,
                                   byte[] b, int bOffset,
                                   byte[] tmp, int tmpOffset)
    {
        final int n = 256;
        final int hn = 128;
        final int byteLen = n / 8;
        final int halfByteLen = hn / 8;

        // Temporary buffers within the provided tmp array
        int t1Offset = tmpOffset;
        int t2Offset = t1Offset + byteLen;
        int t3Offset = t2Offset + byteLen;

        // t1 <- (a0 + a1)*(b0 + b1) + d0 + d1
        bpXor128(tmp, t2Offset, a, aOffset, a, aOffset + halfByteLen);        // a0 + a1
        bpXor128(tmp, t2Offset + halfByteLen, b, bOffset, b, bOffset + halfByteLen); // b0 + b1
        bpXor256(tmp, t1Offset, d, dOffset, d, dOffset + byteLen);            // d0 + d1
        bpMuladd128(tmp, t1Offset, tmp, t2Offset, tmp, t2Offset + halfByteLen, tmp, t3Offset);

        // d0 <- d0 + a0*b0
        bpMuladd128(d, dOffset, a, aOffset, b, bOffset, tmp, t3Offset);

        // d1 <- d1 + a1*b1
        bpMuladd128(d, dOffset + byteLen, a, aOffset + halfByteLen, b, bOffset + halfByteLen, tmp, t3Offset);

        // t1 <- t1 + d0 + d1 = a0*b1 + a1*b0
        bpXor256(tmp, t1Offset, tmp, t1Offset, d, dOffset);
        bpXor256(tmp, t1Offset, tmp, t1Offset, d, dOffset + byteLen);

        // d <- d + (x^{n/2})*t1: d[16:48] ⊕= t1[0:32]
        bpXor256(d, dOffset + halfByteLen, d, dOffset + halfByteLen, tmp, t1Offset);
    }

    /**
     * Binary polynomial multiplication and accumulation for 512-bit polynomials
     * Uses Karatsuba algorithm with 256-bit halves
     */
    public static void bpMuladd512(byte[] d, int dOffset,
                                   byte[] a, int aOffset,
                                   byte[] b, int bOffset,
                                   byte[] tmp, int tmpOffset)
    {
        final int n = 512;
        final int hn = 256;
        final int byteLen = n / 8;
        final int halfByteLen = hn / 8;

        // Temporary buffers within the provided tmp array
        int t1Offset = tmpOffset;
        int t2Offset = t1Offset + byteLen;
        int t3Offset = t2Offset + byteLen;

        // t1 <- (a0 + a1)*(b0 + b1) + d0 + d1
        bpXor256(tmp, t2Offset, a, aOffset, a, aOffset + halfByteLen);        // a0 + a1
        bpXor256(tmp, t2Offset + halfByteLen, b, bOffset, b, bOffset + halfByteLen); // b0 + b1
        bpXor512(tmp, t1Offset, d, dOffset, d, dOffset + byteLen);            // d0 + d1
        bpMuladd256(tmp, t1Offset, tmp, t2Offset, tmp, t2Offset + halfByteLen, tmp, t3Offset);

        // d0 <- d0 + a0*b0
        bpMuladd256(d, dOffset, a, aOffset, b, bOffset, tmp, t3Offset);

        // d1 <- d1 + a1*b1
        bpMuladd256(d, dOffset + byteLen, a, aOffset + halfByteLen, b, bOffset + halfByteLen, tmp, t3Offset);

        // t1 <- t1 + d0 + d1 = a0*b1 + a1*b0
        bpXor512(tmp, t1Offset, tmp, t1Offset, d, dOffset);
        bpXor512(tmp, t1Offset, tmp, t1Offset, d, dOffset + byteLen);

        // d <- d + (x^{n/2})*t1: d[32:96] ⊕= t1[0:64]
        bpXor512(d, dOffset + halfByteLen, d, dOffset + halfByteLen, tmp, t1Offset);
    }

    // Helper methods for long/byte conversion
    private static long bytesToLong(byte[] bytes, int offset)
    {
        long value = 0;
        for (int i = 0; i < 8; i++)
        {
            value |= ((long)(bytes[offset + i] & 0xFF)) << (i * 8);
        }
        return value;
    }

    private static void longToBytes(long value, byte[] bytes, int offset)
    {
        for (int i = 0; i < 8; i++)
        {
            bytes[offset + i] = (byte)((value >> (i * 8)) & 0xFF);
        }
    }

    // Encode 32-bit integer as little-endian bytes
    public static void enc32le(byte[] dst, int dstOffset, int x)
    {
        dst[dstOffset] = (byte)(x & 0xFF);
        dst[dstOffset + 1] = (byte)((x >>> 8) & 0xFF);
        dst[dstOffset + 2] = (byte)((x >>> 16) & 0xFF);
        dst[dstOffset + 3] = (byte)((x >>> 24) & 0xFF);
    }

    // Decode 64-bit little-endian bytes to long
    public static long dec64le(byte[] src, int srcOffset)
    {
        return ((long)(src[srcOffset] & 0xFF)) |
            ((long)(src[srcOffset + 1] & 0xFF) << 8) |
            ((long)(src[srcOffset + 2] & 0xFF) << 16) |
            ((long)(src[srcOffset + 3] & 0xFF) << 24) |
            ((long)(src[srcOffset + 4] & 0xFF) << 32) |
            ((long)(src[srcOffset + 5] & 0xFF) << 40) |
            ((long)(src[srcOffset + 6] & 0xFF) << 48) |
            ((long)(src[srcOffset + 7] & 0xFF) << 56);
    }

    // Decode 16-bit little-endian bytes to int
    public static int dec16le(byte[] src, int srcOffset)
    {
        return (src[srcOffset] & 0xFF) |
            ((src[srcOffset + 1] & 0xFF) << 8);
    }

    /**
     * Generate x with the right Gaussian, for the specified parity bits.
     * x is formally generated with center t/2 and standard deviation sigma_sign
     * (with sigma_sign = 1.010, 1.278 or 1.299, depending on degree); this
     * function generates 2*x.
     * <p>
     * Returned value is the squared norm of x.
     */
    public int sigGauss(int logn, SHAKEDigest scExtra, byte[] x, int xOffset, byte[] t, int tOffset)
    {
        // Select tables based on security level
        short[] tabHi;
        long[] tabLo;
        int hiLen, loLen;

        switch (logn)
        {
        case 8:
            tabHi = SIG_GAUSS_HI_HAWK_256;
            tabLo = SIG_GAUSS_LO_HAWK_256;
            hiLen = SG_MAX_HI_HAWK_256;
            loLen = SG_MAX_LO_HAWK_256;
            break;
        case 9:
            tabHi = SIG_GAUSS_HI_HAWK_512;
            tabLo = SIG_GAUSS_LO_HAWK_512;
            hiLen = SG_MAX_HI_HAWK_512;
            loLen = SG_MAX_LO_HAWK_512;
            break;
        case 10:
            tabHi = SIG_GAUSS_HI_HAWK_1024;
            tabLo = SIG_GAUSS_LO_HAWK_1024;
            hiLen = SG_MAX_HI_HAWK_1024;
            loLen = SG_MAX_LO_HAWK_1024;
            break;
        default:
            throw new IllegalArgumentException("Unsupported logn: " + logn);
        }

        int n = 1 << logn;
        byte[] seed = new byte[41];
        byte[] tmp = new byte[40];
        // Get 40 random bytes from RNG
        random.nextBytes(tmp);
        System.arraycopy(tmp, 0, seed, 0, tmp.length);

        int sn = 0; // squared norm

        for (int j = 0; j < 4; j++)
        {
            SHAKEDigest sc;
            if (scExtra != null)
            {
                sc = new SHAKEDigest(scExtra);
            }
            else
            {
                sc = new SHAKEDigest(256);
            }

            // Set instance identifier and inject seed
            seed[40] = (byte)j;
            sc.update(seed, 0, 41);

            // For SHAKEDigest, we don't need explicit flip - just start reading
            byte[] buffer = new byte[40];

            for (int u = 0; u < (n << 1); u += 16)
            {
                // Extract 40 bytes from SHAKE
                sc.doOutput(buffer, 0, 40);

                for (int k = 0; k < 4; k++)
                {
                    int v = u + (j << 2) + k;
                    long lo = dec64le(buffer, k * 8);
                    int hi = dec16le(buffer, 32 + k * 2);

                    // Extract sign bit
                    int neg = (int)(-(lo >>> 63));
                    lo &= 0x7FFFFFFFFFFFFFFFL;
                    hi &= 0x7FFF;

                    // Get parity bit from t
                    int tByteIndex = tOffset + (v >>> 3);
                    int tBitIndex = v & 7;
                    int pbit = (t[tByteIndex] >>> tBitIndex) & 1;
                    long pOdd = -pbit;
                    int pOddw = (int)pOdd;

                    int r = 0;

                    // Process high table
                    for (int i = 0; i < hiLen; i += 2)
                    {
                        long tlo0 = tabLo[i];
                        long tlo1 = tabLo[i + 1];
                        long tlo = tlo0 ^ (pOdd & (tlo0 ^ tlo1));

                        int thi0 = tabHi[i] & 0xFFFF;
                        int thi1 = tabHi[i + 1] & 0xFFFF;
                        int thi = thi0 ^ (pOddw & (thi0 ^ thi1));

                        // Calculate carry and update r
                        long diff = lo - tlo;
                        int cc = (int)(diff >>> 63); // Carry from low comparison
                        int diffHi = hi - thi - cc;
                        r += (diffHi >>> 31); // Add 1 if hi < (thi + cc)
                    }

                    // Process low table for remaining entries
                    int hinz = (hi - 1) >>> 31; // 0 if hi == 0, -1 if hi > 0
                    for (int i = hiLen; i < loLen; i += 2)
                    {
                        long tlo0 = tabLo[i];
                        long tlo1 = tabLo[i + 1];
                        long tlo = tlo0 ^ (pOdd & (tlo0 ^ tlo1));

                        long diff = lo - tlo;
                        int cc = (int)(diff >>> 63);
                        r += hinz & cc; // Only add if hi > 0
                    }

                    // Multiply by 2 and apply parity
                    r = (r << 1) - pOddw;

                    // Apply sign bit
                    r = (r ^ neg) - neg;
                    // Store as signed byte
                    x[xOffset + v] = (byte)r;
                    sn += r * r;
                }
            }
        }

        return sn;
    }

    // Utility class to get tables based on logn
    private static class GaussianTable
    {
        final short[] hiTable;
        final long[] loTable;
        final int hiLength;
        final int loLength;

        GaussianTable(short[] hiTable, long[] loTable)
        {
            this.hiTable = hiTable;
            this.loTable = loTable;
            this.hiLength = hiTable.length;
            this.loLength = loTable.length;
        }
    }

    // Get the appropriate Gaussian table based on security level
    public static GaussianTable getGaussianTable(int logn)
    {
        switch (logn)
        {
        case 8:
            return new GaussianTable(SIG_GAUSS_HI_HAWK_256, SIG_GAUSS_LO_HAWK_256);
        case 9:
            return new GaussianTable(SIG_GAUSS_HI_HAWK_512, SIG_GAUSS_LO_HAWK_512);
        case 10:
            return new GaussianTable(SIG_GAUSS_HI_HAWK_1024, SIG_GAUSS_LO_HAWK_1024);
        default:
            throw new IllegalArgumentException("Unsupported logn: " + logn +
                ". Supported values are 8, 9, 10.");
        }
    }

    /**
     * Alternate function for sampling x; the same mechanism is used, but the
     * provided RNG is used directly instead of instantiating four SHAKE
     * instances in parallel.
     * <p>
     * Returned value is the squared norm of x.
     */
    public int sigGaussAlt(int logn, byte[] x, int xOffset, byte[] t, int tOffset)
    {
        // Get the appropriate Gaussian tables
        GaussianTable table = getGaussianTable(logn);
        short[] tabHi = table.hiTable;
        long[] tabLo = table.loTable;
        int hiLen = table.hiLength;
        int loLen = table.loLength;

        int n = 1 << logn;
        int sn = 0; // squared norm

        // Process in blocks of 16 samples
        for (int u = 0; u < (n << 1); u += 16)
        {
            // Buffer for 160 bytes (20 * 8 bytes)
            byte[] buf = new byte[160];
            random.nextBytes(buf);

            for (int j = 0; j < 4; j++)
            {
                for (int k = 0; k < 4; k++)
                {
                    int v = u + (j << 2) + k;

                    // Calculate offsets for low and high parts
                    int loOffset = (j << 3) + (k << 5); // j*8 + k*32
                    int hiOffset = (j << 3) + 128 + (k << 1); // j*8 + 128 + k*2

                    long lo = dec64le(buf, loOffset);
                    int hi = dec16le(buf, hiOffset);

                    // Extract sign bit
                    int neg = (int)(-(lo >>> 63));
                    lo &= 0x7FFFFFFFFFFFFFFFL;
                    hi &= 0x7FFF;

                    // Get parity bit from t
                    int tByteIndex = tOffset + (v >>> 3);
                    int tBitIndex = v & 7;
                    int pbit = (t[tByteIndex] >>> tBitIndex) & 1;
                    long pOdd = -pbit;
                    int pOddw = (int)pOdd;

                    int r = 0;

                    // Process high table (entries with both hi and lo thresholds)
                    for (int i = 0; i < hiLen; i += 2)
                    {
                        long tlo0 = tabLo[i];
                        long tlo1 = tabLo[i + 1];
                        long tlo = tlo0 ^ (pOdd & (tlo0 ^ tlo1));

                        int thi0 = tabHi[i] & 0xFFFF;
                        int thi1 = tabHi[i + 1] & 0xFFFF;
                        int thi = thi0 ^ (pOddw & (thi0 ^ thi1));

                        // Calculate carry from low comparison
                        long diffLo = lo - tlo;
                        int cc = (int)(diffLo >>> 63); // 1 if lo < tlo, 0 otherwise

                        // Calculate difference for high part
                        int diffHi = hi - thi - cc;

                        // Add 1 if hi < (thi + cc), i.e., if diffHi is negative
                        r += (diffHi >>> 31);
                    }

                    // Process low table (entries with only lo thresholds)
                    int hinz = (hi - 1) >>> 31; // 0 if hi == 0, 0xFFFFFFFF if hi > 0
                    for (int i = hiLen; i < loLen; i += 2)
                    {
                        long tlo0 = tabLo[i];
                        long tlo1 = tabLo[i + 1];
                        long tlo = tlo0 ^ (pOdd & (tlo0 ^ tlo1));

                        long diffLo = lo - tlo;
                        int cc = (int)(diffLo >>> 63); // 1 if lo < tlo, 0 otherwise

                        // Only add if hi > 0 (hinz is -1 when hi > 0)
                        r += hinz & cc;
                    }

                    // Multiply by 2 and apply parity
                    r = (r << 1) - pOddw;

                    // Apply sign bit: if neg is -1, then r = -r
                    r = (r ^ neg) - neg;

                    // Store as signed byte and update squared norm
                    x[xOffset + v] = (byte)r;
                    sn += r * r;
                }
            }
        }

        return sn;
    }

    /**
     * Convert a small polynomial (signed 8-bit coefficients) to mod q representation.
     * This is the equivalent of Zq(poly_set_small)
     */
    public void mq18433PolySetSmall(int logn, short[] d, int dOffset, byte[] a, int aOffset)
    {
        int n = 1 << logn;
        for (int u = 0; u < n; u++)
        {
            d[dOffset + u] = mq18433SetSmall(a[aOffset + u]);
        }
    }

    /**
     * Convert a small polynomial in-place from packed bytes to mod q representation.
     * This is the equivalent of Zq(poly_set_small_inplace_low)
     * <p>
     * The input is stored as packed bytes in the first n/2 elements of d,
     * and the output is written as mod q values in all n elements of d.
     */
    public void mq18433PolySetSmallInplaceLow(int logn, short[] d, int dOffset)
    {
        int n = 1 << logn;
        int u = n;

        // Process from the end to avoid overwriting data we haven't read yet
        while (u > 0)
        {
            u -= 2;

            // Read packed bytes from the first half of the array
            int packedIndex = dOffset + (u >> 1);
            int packedValue = d[packedIndex] & 0xFFFF;

            // Extract the two bytes
            byte x0 = (byte)(packedValue & 0xFF);
            byte x1 = (byte)((packedValue >> 8) & 0xFF);

            // Convert to mod q and store in the full array
            d[dOffset + u] = mq18433SetSmall(x0);
            d[dOffset + u + 1] = mq18433SetSmall(x1);
        }
    }

    /**
     * Convert a signed byte to a mod q value in the range [0, q-1]
     * This is the equivalent of Zq(set_small)
     */
    public short mq18433SetSmall(byte x)
    {
        // C formula: uint32_t y = (uint32_t)-x; y += Q & (y >> 16); return Q - y;
        // This returns values in [1..Q] where Q represents 0 mod Q.
        int xInt = (int)x;   // sign-extend byte to int
        int y = -xInt;       // same bit pattern as C's (uint32_t)-x
        y += Q & (y >>> 16); // unsigned right shift to detect negative (large unsigned) values
        return (short)(Q - y);
    }

    /**
     * Alternative implementation with bounds checking
     */
    public short mq18433SetSmallSafe(byte x)
    {
        int value = x;

        // For negative values, add q to get into positive range
        if (value < 0)
        {
            value += Q;
        }


        return (short)value;
    }

    /**
     * Batch conversion for multiple polynomials
     */
    public void mq18433PolySetSmallBatch(int logn, short[][] dArray, int[] dOffsets,
                                         byte[][] aArray, int[] aOffsets)
    {
        for (int i = 0; i < dArray.length; i++)
        {
            mq18433PolySetSmall(logn, dArray[i], dOffsets[i], aArray[i], aOffsets[i]);
        }
    }

    /**
     * In-place conversion for multiple polynomials
     */
    public void mq18433PolySetSmallInplaceLowBatch(int logn, short[][] dArray, int[] dOffsets)
    {
        for (int i = 0; i < dArray.length; i++)
        {
            mq18433PolySetSmallInplaceLow(logn, dArray[i], dOffsets[i]);
        }
    }

    /**
     * Convert a small polynomial (signed 8-bit coefficients) to a mod q
     * representation that _ends_ at the same address (i.e. the n last
     * bytes of d are read, and 2*n bytes are written into d).
     */
    public void mq18433PolySetSmallInplaceHigh(int logn, short[] d, int dOffset)
    {
        int n = 1 << logn;
        int hn = n >> 1; // half n

        for (int u = 0; u < n; u += 2)
        {
            // Read packed bytes from the high half of the array
            int packedIndex = dOffset + hn + (u >> 1);
            int packedValue = d[packedIndex] & 0xFFFF;

            // Extract the two bytes
            byte x0 = (byte)(packedValue & 0xFF);
            byte x1 = (byte)((packedValue >> 8) & 0xFF);

            // Convert to mod q and store in the low half of the array
            d[dOffset + u] = mq18433SetSmall(x0);
            d[dOffset + u + 1] = mq18433SetSmall(x1);
        }
    }

    /**
     * Number Theoretic Transform (NTT) for modulus 18433
     */
    public void mq18433NTT(int logn, short[] a, int aOffset)
    {
        if (logn == 0)
        {
            return;
        }

        int t = 1 << logn;

        for (int lm = 0; lm < logn; lm++)
        {
            int m = 1 << lm;
            int ht = t >> 1;
            int v0 = 0;

            for (int u = 0; u < m; u++)
            {
                int s = GM[u + m] & 0xFFFF; // NTT root

                for (int v = 0; v < ht; v++)
                {
                    int k1 = aOffset + v0 + v;
                    int k2 = k1 + ht;

                    int x1 = a[k1] & 0xFFFF;
                    int x2 = a[k2] & 0xFFFF;

                    // Montgomery multiplication
                    int x2_monty = mq18433MontyMul(x2, s);

                    // Butterfly operation
                    a[k1] = (short)mq18433Add(x1, x2_monty);
                    a[k2] = (short)mq18433Sub(x1, x2_monty);
                }
                v0 += t;
            }
            t = ht;
        }
    }

    /**
     * Alternative NTT implementation with explicit bounds checking
     */
    public void mq18433NTTSafe(int logn, short[] a, int aOffset)
    {
        if (logn == 0)
        {
            return;
        }

        int n = 1 << logn;
        int t = n;

        for (int lm = 0; lm < logn; lm++)
        {
            int m = 1 << lm;
            int ht = t >> 1;

            if (GM.length < m * 2)
            {
                throw new IllegalArgumentException("GM table too small for logn=" + logn);
            }

            for (int u = 0; u < m; u++)
            {
                int s = GM[u + m] & 0xFFFF;

                for (int v = 0; v < ht; v++)
                {
                    int baseIndex = u * t;
                    int k1 = aOffset + baseIndex + v;
                    int k2 = k1 + ht;

                    // Bounds checking
                    if (k1 >= a.length || k2 >= a.length)
                    {
                        throw new ArrayIndexOutOfBoundsException(
                            "NTT indices out of bounds: k1=" + k1 + ", k2=" + k2);
                    }

                    int x1 = a[k1] & 0xFFFF;
                    int x2 = a[k2] & 0xFFFF;

                    int x2_monty = mq18433MontyMul(x2, s);
                    a[k1] = (short)mq18433Add(x1, x2_monty);
                    a[k2] = (short)mq18433Sub(x1, x2_monty);
                }
            }
            t = ht;
        }
    }

    /**
     * Montgomery multiplication: returns (x * y) mod Q in Montgomery form
     */
    public int mq18433MontyMul(int x, int y)
    {
        return mq18433MontyRed(x * y);
    }

    /**
     * Montgomery reduction. The Hawk protocol never feeds x == 0 here (NTT/INTT
     * butterfly products in [1..Q] representation, where Q itself represents 0),
     * but the original short-circuit `if (x == 0) return 0;` is a data-dependent
     * branch on a secret-derived intermediate — replaced with a branchless mask
     * to preserve byte-identity while removing the L1 timing channel.
     */
    public int mq18433MontyRed(int x)
    {
        int step1 = (int)((long)x * Q0I);
        int step2 = (step1 >>> 16) * Q;
        int result = (step2 >>> 16) + 1;
        int nonzero = -((x | -x) >>> 31);  // -1 if x != 0, 0 if x == 0
        return result & nonzero;
    }

    /**
     * Modular addition: (x + y) mod Q, result in [1..Q] where Q represents 0 mod Q.
     * Matches the C formula: {@code d = Q-(x+y); d += Q & (d>>16); return Q-d;}
     */
    public int mq18433Add(int x, int y)
    {
        int d = Q - (x + y);
        d += Q & (d >> 16);
        return Q - d;
    }

    /**
     * Modular subtraction: (x - y) mod Q, result in [1..Q] where Q represents 0 mod Q.
     * Matches the C formula: {@code d = y-x; d += Q & (d>>16); return Q-d;}
     */
    public int mq18433Sub(int x, int y)
    {
        int d = y - x;
        d += Q & (d >> 16);
        return Q - d;
    }

    /**
     * Compute Q0I constant for Montgomery reduction
     * Q0I = -Q^{-1} mod 2^16
     */
    private int computeQ0I()
    {
        // Extended Euclidean algorithm to find modular inverse
        int r0 = Q;
        int r1 = 1 << 16;
        int t0 = 0;
        int t1 = 1;

        while (r1 != 0)
        {
            int quotient = r0 / r1;
            int temp = r1;
            r1 = r0 - quotient * r1;
            r0 = temp;

            temp = t1;
            t1 = t0 - quotient * t1;
            t0 = temp;
        }

        if (r0 != 1)
        {
            throw new ArithmeticException("Modular inverse doesn't exist");
        }

        // t0 is the modular inverse, return -t0 mod 2^16
        return (-t0) & 0xFFFF;
    }

    /**
     * Inverse NTT matching C mq18433_iNTT exactly.
     * 1/n normalization is embedded in the iGM twiddle factors.
     */
    public void mq18433INTT(int logn, short[] a, int aOffset)
    {
        if (logn == 0)
        {
            return;
        }

        int t = 1;
        for (int lm = 0; lm < logn; lm++)
        {
            int hm = 1 << (logn - 1 - lm);
            int dt = t << 1;
            int v0 = 0;

            for (int u = 0; u < hm; u++)
            {
                int s = HawkParameters.iGM[u + hm] & 0xFFFF;

                for (int v = 0; v < t; v++)
                {
                    int k1 = aOffset + v0 + v;
                    int k2 = k1 + t;

                    int x1 = a[k1] & 0xFFFF;
                    int x2 = a[k2] & 0xFFFF;

                    a[k1] = (short)mq18433Half(mq18433Add(x1, x2));
                    a[k2] = (short)mq18433MontyMul(s, mq18433Sub(x1, x2));
                }
                v0 += dt;
            }
            t = dt;
        }
    }

    /**
     * Modular inverse using extended Euclidean algorithm
     */
    private static int modInverse(int a, int mod)
    {
        int t = 0, newT = 1;
        int r = mod, newR = a;

        while (newR != 0)
        {
            int quotient = r / newR;
            int temp = newT;
            newT = t - quotient * newT;
            t = temp;
            temp = newR;
            newR = r - quotient * newR;
            r = temp;
        }

        if (r > 1)
        {
            throw new ArithmeticException(a + " is not invertible mod " + mod);
        }
        if (t < 0)
        {
            t += mod;
        }
        return t;
    }

    /**
     * Convert a number to Montgomery form
     */
    public int mq18433ToMonty(int x)
    {
        return mq18433MontyRed(x * R2);
    }


    /**
     * Alias for mq18433INTT kept for compatibility.
     */
    public void mq18433INTTWithScaling(int logn, short[] a, int aOffset)
    {
        mq18433INTT(logn, a, aOffset);
    }

    /**
     * Compute half: x/2 mod Q. Constant-time: x is a secret-derived INTT
     * butterfly intermediate (each butterfly calls this O(n log n) per signing
     * INTT), so the "is x odd" branch must not be data-dependent. Same pattern
     * as HawkEngine.mpHalf — fold the conditional `+ Q` (only applied when x is
     * odd, to keep the result an integer) into a branchless mask.
     */
    public int mq18433Half(int x)
    {
        return (x + (Q & -(x & 1))) >> 1;
    }

    /**
     * Alternative half implementation using modular inverse of 2
     */
    public int mq18433HalfMonty(int x)
    {
        // 2^{-1} mod Q = (Q + 1) / 2 since Q is prime and odd
        int inv2 = (Q + 1) >> 1;
        return mq18433MontyMul(x, inv2);
    }

    /**
     * Compute R2 = (2^16)^2 mod Q for Montgomery conversion
     */
    private int computeR2()
    {
        long r = 1L << 16; // 2^16
        long r2 = r * r;   // (2^16)^2
        return (int)(r2 % Q);
    }

    /**
     * Apply signed normalization to polynomial coefficients
     */
    public static void mq18433PolySnorm(int logn, short[] d, int dOffset)
    {
        int n = 1 << logn;
        for (int u = 0; u < n; u++)
        {
            d[dOffset + u] = (short)mq18433Snorm(d[dOffset + u] & 0xFFFF);
        }
    }

    /**
     * Signed normalization: convert to range [-floor((Q-1)/2), floor((Q-1)/2)].
     * Constant-time: x is a secret-derived NTT coefficient (signing computes
     * f*x1 - g*x0 over secret f, g and sampled x), so the "is x > Q/2" branch
     * must not be data-dependent. We compute a -1/0 mask from the sign of
     * (Q/2 - x) and apply it; byte-identical to the original on all inputs in
     * the polynomial's range.
     */
    public static int mq18433Snorm(int x)
    {
        int mask = ((Q >> 1) - x) >> 31;  // -1 if x > Q/2, 0 otherwise
        return x - (Q & mask);
    }

    /**
     * Alternative signed normalization with proper bounds
     */
    public static int mq18433SnormSafe(int x)
    {
        x %= Q;
        if (x > Q / 2)
        {
            return x - Q;
        }
        else if (x < -(Q / 2))
        {
            return x + Q;
        }
        else
        {
            return x;
        }
    }

    /**
     * Returned value:
     * 1   first non-zero coefficient of s is positive
     * -1   first non-zero coefficient of s is negative
     * 0   s is entirely zero
     */
    public static int polySymBreak(int logn, short[] s, int sOffset)
    {
        // Matches C's poly_symbreak exactly:
        //   returns 0 if polynomial is all-zero
        //   returns 1 if first non-zero coefficient is positive
        //   returns -1 (= 0xFFFFFFFF as uint32) if first non-zero coefficient is negative
        // The caller uses ~tbmask(r-1) to decide negation:
        //   r=0:  tbmask(-1)= -1, ~(-1)=0   -> no negation
        //   r=1:  tbmask(0) =  0, ~0  =-1   -> negate (positive first coeff -> negate)
        //   r=-1: tbmask(-2)= -1, ~(-1)=0   -> no negation (negative first coeff)
        int n = 1 << logn;
        int r = 0;
        int c = 0xFFFFFFFF; // Mask for tracking first non-zero

        for (int u = 0; u < n; u++)
        {
            int x = s[sOffset + u];
            int nz = c & HawkEngine.tbmask(x | -x); // Non-zero mask
            c &= ~nz; // Clear the bit for this coefficient
            r |= nz & (HawkEngine.tbmask(x) | 1); // r=1 if positive, r=-1 if negative
        }

        // Return raw r (same bit pattern as C's uint32_t return value):
        //   0 = all-zero, 1 = positive first coeff, -1 (=0xFFFFFFFF) = negative first coeff
        return r;
    }

    /**
     * Alternative implementation with explicit sign detection
     */
    public static int polySymBreakExplicit(int logn, short[] s, int sOffset)
    {
        int n = 1 << logn;

        for (int u = 0; u < n; u++)
        {
            int coeff = s[sOffset + u];
            if (coeff != 0)
            {
                return coeff > 0 ? 1 : -1;
            }
        }
        return 0;
    }

    /**
     * Encode the signature, with output length exactly sigLen bytes.
     * Padding is applied if necessary. Returned value is 1 on success, 0
     * on error; an error is reported if the signature does not fit in the
     * provided buffer.
     */
    public static boolean encodeSig(int logn, byte[] sig, int sigOffset, int sigLen,
                                    byte[] salt, int saltOffset, int saltLen,
                                    short[] s1, int s1Offset)
    {
        int n = 1 << logn;
        int low = (logn == 10) ? 6 : 5;
        int bufOffset = sigOffset;
        int remainingLen = sigLen;

        // Check minimal size, including at least n bits for the variable part
        int minSize = saltLen + ((low + 2) << (logn - 3));
        if (remainingLen < minSize)
        {
            return false;
        }

        // 1. Copy salt
        System.arraycopy(salt, saltOffset, sig, bufOffset, saltLen);
        bufOffset += saltLen;
        remainingLen -= saltLen;

        // 2. Sign bits (1 bit per coefficient)
        for (int u = 0; u < n; u += 8)
        {
            int x = 0;
            for (int v = 0; v < 8; v++)
            {
                int signBit = (s1[s1Offset + u + v] >> 15) & 1;
                x |= signBit << v;
            }
            sig[bufOffset + (u >> 3)] = (byte)x;
        }
        bufOffset += (n >> 3);
        remainingLen -= (n >> 3);

        // 3. Fixed-size parts (low bits of absolute values)
        int lowMask = (1 << low) - 1;
        for (int u = 0; u < n; u += 8)
        {
            long x = 0;
            for (int v = 0, shift = 0; v < 8; v++, shift += low)
            {
                int w = s1[s1Offset + u + v];
                int mask = HawkEngine.tbmask(w);
                w ^= mask; // Absolute value
                x |= (long)(w & lowMask) << shift;
            }

            // Write bytes (little-endian)
            for (int i = 0; i < low; i++)
            {
                if (remainingLen <= 0)
                {
                    return false;
                }
                sig[bufOffset++] = (byte)(x & 0xFF);
                x >>>= 8;
            }
        }
        remainingLen -= low << (logn - 3);

        // 4. Variable-size parts (remaining bits using unary-like encoding)
        int acc = 0;
        int accLen = 0;

        for (int u = 0; u < n; u++)
        {
            int w = s1[s1Offset + u];
            int mask = HawkEngine.tbmask(w);
            w ^= mask; // Absolute value
            int k = w >>> low; // Remaining bits after low bits

            // Unary encoding: k zeros followed by a one
            acc |= 1 << (accLen + k);
            accLen += 1 + k;

            // Flush complete bytes
            while (accLen >= 8)
            {
                if (remainingLen <= 0)
                {
                    return false;
                }
                sig[bufOffset++] = (byte)(acc & 0xFF);
                remainingLen--;
                acc >>>= 8;
                accLen -= 8;
            }
        }

        // Flush remaining bits
        if (accLen > 0)
        {
            if (remainingLen <= 0)
            {
                return false;
            }
            sig[bufOffset++] = (byte)(acc & 0xFF);
            remainingLen--;
        }

        // 5. Padding with zeros
        for (int i = 0; i < remainingLen; i++)
        {
            sig[bufOffset + i] = 0;
        }

        return true;
    }

    public int signFinishInner(int logn, int useShake,
                               byte[] sig, SHAKEDigest scData, byte[] priv, int privLen,
                               byte[] tmp, int tmpLen)
    {
        // Ensure proper alignment for 64-bit access
        if (tmpLen < 7)
        {
            return 0;
        }
        if (logn < 8 || logn > 10)
        {
            return 0;
        }

        // Align temporary buffer for 64-bit access
        int utmp1 = 0;
        int utmp2 = (utmp1 + 7) & ~7;
        tmpLen -= (int)(utmp2 - utmp1);

        if (tmpLen < (6 << logn))
        {
            return 0;
        }

        // Check private key format
        boolean privDecoded;
        int expectedPrivSize = HAWK_PRIVKEY_SIZE(logn);
        int expectedDecodedSize = HAWK_PRIVKEY_DECODED_SIZE(logn);

        if (privLen == expectedPrivSize)
        {
            privDecoded = false;
        }
        else if (privLen == expectedDecodedSize)
        {
            privDecoded = true;
        }
        else
        {
            return 0;
        }

        // Hawk parameters
        int n = 1 << logn;
        int saltLen;
        int maxXnorm;

        switch (logn)
        {
        case 8:
            saltLen = 14;
            maxXnorm = 2223;
            break;
        case 9:
            saltLen = 24;
            maxXnorm = 8317;
            break;
        case 10:
            saltLen = 40;
            maxXnorm = 20218;
            break;
        default:
            return 0;
        }

        int seedLen = 8 + (1 << (logn - 5));
        int hpubLen = 1 << (logn - 4);

        // Memory layout in tmp buffer
        int offset = 0;
        byte[] g = new byte[n];
        byte[] ww = new byte[2 * n];
        byte[] x0 = new byte[2 * n];
        byte[] x1 = new byte[n];
        byte[] f = new byte[n];

        // Re-expand the private key
        byte[] F2, G2;
        byte[] hpub;

        if (privDecoded)
        {
            // Use the decoded private key directly
            System.arraycopy(priv, 0, f, 0, n);
            System.arraycopy(priv, n, g, 0, n);
            F2 = new byte[n >> 3];
            G2 = new byte[n >> 3];
            hpub = new byte[hpubLen];
            System.arraycopy(priv, 2 * n, F2, 0, n >> 3);
            System.arraycopy(priv, 2 * n + (n >> 3), G2, 0, n >> 3);
            System.arraycopy(priv, 2 * n + 2 * (n >> 3), hpub, 0, hpubLen);
        }
        else
        {
            // Regenerate f and g from seed
            byte[] seed = new byte[seedLen];
            System.arraycopy(priv, 0, seed, 0, seedLen);
            HawkEngine.Hawk_regen_fg(logn, f, 0, g, 0, seed);
            System.arraycopy(seed, 0, tmp, 0, seedLen);
            F2 = new byte[n >> 3];
            G2 = new byte[n >> 3];
            hpub = new byte[hpubLen];
            System.arraycopy(priv, seedLen, F2, 0, n >> 3);
            System.arraycopy(priv, seedLen + (n >> 3), G2, 0, n >> 3);
            System.arraycopy(priv, seedLen + 2 * (n >> 3), hpub, 0, hpubLen);
        }
        // Compute hm = SHAKE256(message || hpub)
        byte[] hm = new byte[64];

        // Copy the state from scData if needed (BouncyCastle doesn't support cloning directly)
        // For now, we'll assume scData contains the message hash state
        scData.update(hpub, 0, hpubLen);
        scData.doFinal(hm, 0, hm.length);

        for (int attempt = 0; ; attempt += 2)
        {
            // Temporary buffers within ww
            int t0Offset = 0;
            int t1Offset = t0Offset + (n >> 3);
            int h0Offset = t1Offset + (n >> 3);
            int h1Offset = h0Offset + (n >> 3);
            int f2Offset = h1Offset + (n >> 3);
            int g2Offset = f2Offset + (n >> 3);
            int xxOffset = g2Offset + (n >> 3);

            // Generate salt
            byte[] salt = new byte[saltLen];
            random.nextBytes(salt);

            if (useShake != 0)
            {
                byte[] tbuf = new byte[4];
                enc32le(tbuf, 0, attempt);

                SHAKEDigest saltShake = new SHAKEDigest(256);
                saltShake.update(hm, 0, hm.length);

                if (privDecoded)
                {
                    saltShake.update(priv, 0, n * 2);
                }
                else
                {
                    saltShake.update(priv, 0, seedLen);
                }

                saltShake.update(tbuf, 0, tbuf.length);
                saltShake.update(salt, 0, saltLen);
                saltShake.doFinal(salt, 0, saltLen);
            }

            // Compute h = SHAKE256(hm || salt)
            SHAKEDigest hShake = new SHAKEDigest(256);
            hShake.update(hm, 0, hm.length);
            hShake.update(salt, 0, saltLen);
            hShake.doFinal(ww, h0Offset, n >> 2);

            // Extract low bits and compute t = B*h (mod 2)
            byte[] f2 = new byte[n >> 3];
            byte[] g2 = new byte[n >> 3];
            extract_lowbit(logn, f2, f);
            extract_lowbit(logn, g2, g);

            basisM2Mul(logn,
                ww, t0Offset, ww, t1Offset,  // t0, t1
                ww, h0Offset, ww, h1Offset,  // h0, h1
                f2, 0, g2, 0,               // f2, g2
                F2, 0, G2, 0,               // F2, G2
                tmp, xxOffset);              // tmp space

            // Sample x using Gaussian distribution
            int xsn;
            if (useShake != 0)
            {
                byte[] tbuf = new byte[4];
                enc32le(tbuf, 0, attempt + 1);

                SHAKEDigest gaussShake = new SHAKEDigest(256);
                gaussShake.update(hm, 0, hm.length);

                if (privDecoded)
                {
                    gaussShake.update(priv, 0, n * 2);
                }
                else
                {
                    gaussShake.update(priv, 0, seedLen);
                }

                gaussShake.update(tbuf, 0, tbuf.length);

                xsn = sigGauss(logn, gaussShake, x0, 0, ww, t0Offset);
            }
            else
            {
                xsn = sigGaussAlt(logn, x0, 0, ww, t0Offset);
            }

            // Reject if squared norm is too large
            if (xsn > maxXnorm)
            {
                if (!privDecoded)
                {
                    HawkEngine.Hawk_regen_fg(logn, f, 0, g, 0, priv);
                }
                continue;
            }

            // Compute s1 = f*x1 - g*x0 using NTT over Q=18433
            short[] w1 = new short[n];
            short[] w2 = new short[n];
            short[] w3 = new short[n];

            // w1 <- g*x0 in NTT domain
            mq18433PolySetSmall(logn, w1, 0, g, 0);
            mq18433PolySetSmall(logn, w2, 0, x0, 0);
            mq18433NTT(logn, w1, 0);
            mq18433NTT(logn, w2, 0);
            for (int u = 0; u < n; u++)
            {
                w1[u] = (short)mq18433MontyMul(w1[u] & 0xFFFF, w2[u] & 0xFFFF);
            }

            // w3 <- f*x1 - g*x0, then INTT to get polynomial
            mq18433PolySetSmall(logn, w2, 0, x0, n);  // x1 = x0[n..2n-1]
            mq18433PolySetSmall(logn, w3, 0, f, 0);
            mq18433NTT(logn, w2, 0);
            mq18433NTT(logn, w3, 0);
            for (int u = 0; u < n; u++)
            {
                w3[u] = (short)mq18433ToMonty(mq18433Sub(
                    mq18433MontyMul(w2[u] & 0xFFFF, w3[u] & 0xFFFF),
                    w1[u] & 0xFFFF));
            }
            mq18433INTT(logn, w3, 0);
            mq18433PolySnorm(logn, w3, 0);

            short[] s1 = w3;

            int ps = polySymBreak(logn, s1, 0);
            int lim = 1 << ((logn == 10) ? 10 : 9);
            int nm = ~HawkEngine.tbmask(ps - 1);

            byte[] h1buf = new byte[n >> 3];
            System.arraycopy(ww, h1Offset, h1buf, 0, n >> 3);

            // Per-coefficient bounds check is constant-time across all u: an
            // early-exit break would leak (via timing) the index of the first
            // out-of-range coefficient on rejected signing attempts. We scan
            // every coefficient unconditionally and accumulate the reject flag
            // via mask. On the accepted path s1[] ends with the same bytes as
            // the early-exit version; on a rejected path s1[] is overwritten
            // beyond the original break point but then discarded by the retry,
            // so the released signature is byte-identical.
            int reject = 0;
            for (int u = 0; u < n; u++)
            {
                int z = s1[u];
                z = ((z ^ nm) - nm) + ((h1buf[u >> 3] >> (u & 7)) & 1);
                int y = z >> 1;

                // -1 if y < -lim or y >= lim, 0 otherwise
                int outOfRange = ((y + lim) >> 31) | ((lim - 1 - y) >> 31);
                reject |= outOfRange;
                s1[u] = (short)y;
            }

            if (reject != 0)
            {
                if (!privDecoded)
                {
                    HawkEngine.Hawk_regen_fg(logn, f, 0, g, 0, priv);
                }
                continue;
            }

            // Encode signature
            int sigLen = HAWK_SIG_SIZE(logn);
            if (encodeSig(logn, tmp, 0, sigLen, salt, 0, saltLen, s1, 0))
            {
                if (sig != null)
                {
                    System.arraycopy(tmp, 0, sig, 0, sigLen);
                }
                return 1;
            }

            if (!privDecoded)
            {
                HawkEngine.Hawk_regen_fg(logn, f, 0, g, 0, priv);
            }
        }
    }

    // Helper method implementations
    private static int HAWK_PRIVKEY_SIZE(int logn)
    {
        int n = 1 << logn;
        return 8 + (1 << (logn - 5)) + 2 * (n >> 3) + (n >> 4);
    }

    private static int HAWK_PRIVKEY_DECODED_SIZE(int logn)
    {
        int n = 1 << logn;
        return 2 * n + 2 * (n >> 3) + (n >> 4);
    }

    private static int HAWK_SIG_SIZE(int logn)
    {
        return 249 + 306 * (2 >> (10 - logn)) + 360 * (1 >> (10 - logn));
    }

    // Placeholder for missing methods - you'll need to implement these based on your existing code
    private static void extract_lowbit(int logn, byte[] dst, byte[] src)
    {
        // Extract the lowest bit of each coefficient
        int n = 1 << logn;
        for (int i = 0; i < n; i += 8)
        {
            byte val = 0;
            for (int j = 0; j < 8; j++)
            {
                val |= ((src[i + j] & 1) << j);
            }
            dst[i >> 3] = val;
        }
    }

    /**
     * Main signing function compatible with the crypto_sign API
     */
    public int cryptoSign(byte[] sm, long[] smlen,
                          byte[] m, long mlen,
                          byte[] sk, int logn)
    {
        // Calculate temporary buffer size
        int tmpSize = hawkTmpSizeSign(logn);
        byte[] tmp = new byte[tmpSize];

        SHAKEDigest sc = new SHAKEDigest(256);

        // If message is not already in the output buffer, copy it
        if (m != sm)
        {
            System.arraycopy(m, 0, sm, 0, (int)mlen);
        }

        // Start the signing process
        hawkSignStart(sc);

        // Inject the message into the shake context
        sc.update(sm, 0, (int)mlen);

        // Sign into a separate buffer, then append to sm after the message
        byte[] sigBuf = new byte[HAWK_SIG_SIZE(logn)];
        int result = hawkSignFinish(logn, sigBuf, sc, sk, tmp, tmp.length);

        if (result == 0)
        {
            return -1; // Signing failed
        }

        System.arraycopy(sigBuf, 0, sm, (int)mlen, sigBuf.length);

        // Calculate total signed message length
        smlen[0] = mlen + HAWK_SIG_SIZE(logn);
        return 0;
    }

    /**
     * Alternative signature with simpler Java-style API
     */
    public byte[] sign(byte[] message, byte[] privateKey, int logn)
    {
        long mlen = message.length;
        long[] smlen = new long[1];
        byte[] sm = new byte[message.length + hawkSigSize(logn)];

        // Copy message to the beginning of sm
        System.arraycopy(message, 0, sm, 0, message.length);

        int result = cryptoSign(sm, smlen, message, mlen, privateKey, logn);

        if (result != 0)
        {
            throw new IllegalStateException("Signing failed");
        }

        // Return only the signed message (original message + signature)
        return sm;
    }

    /**
     * Start the signing process - initialize SHAKE context
     */
    public static void hawkSignStart(SHAKEDigest sc)
    {
        // Reset the SHAKE context for a new signing operation
        sc.reset();
        // You might need additional initialization here based on your implementation
    }

    // Size calculation methods
    public static int hawkPrivKeySize(int logn)
    {
        int n = 1 << logn;
        return 8 + (1 << (logn - 5)) + 2 * (n >> 3) + (n >> 4);
    }

    public static int hawkSigSize(int logn)
    {
        return HAWK_SIG_SIZE(logn);
    }

    public static int hawkTmpSizeSign(int logn)
    {
        // Temporary buffer size for signing operation
        // This should be large enough to hold all intermediate values
        int n = 1 << logn;
        return 6 * n + 1024; // Conservative estimate, adjust based on your needs
    }
}
