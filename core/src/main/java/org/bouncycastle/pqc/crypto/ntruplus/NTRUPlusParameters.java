package org.bouncycastle.pqc.crypto.ntruplus;

public class NTRUPlusParameters
{
    private static final short[] zetas768 = new short[]{
        -147, -1033, -682, -248, -708, 682, 1, -722,
        -723, -257, -1124, -867, -256, 1484, 1262, -1590,
        1611, 222, 1164, -1346, 1716, -1521, -357, 395,
        -455, 639, 502, 655, -699, 541, 95, -1577,
        -1241, 550, -44, 39, -820, -216, -121, -757,
        -348, 937, 893, 387, -603, 1713, -1105, 1058,
        1449, 837, 901, 1637, -569, -1617, -1530, 1199,
        50, -830, -625, 4, 176, -156, 1257, -1507,
        -380, -606, 1293, 661, 1428, -1580, -565, -992,
        548, -800, 64, -371, 961, 641, 87, 630,
        675, -834, 205, 54, -1081, 1351, 1413, -1331,
        -1673, -1267, -1558, 281, -1464, -588, 1015, 436,
        223, 1138, -1059, -397, -183, 1655, 559, -1674,
        277, 933, 1723, 437, -1514, 242, 1640, 432,
        -1583, 696, 774, 1671, 927, 514, 512, 489,
        297, 601, 1473, 1130, 1322, 871, 760, 1212,
        -312, -352, 443, 943, 8, 1250, -100, 1660,
        -31, 1206, -1341, -1247, 444, 235, 1364, -1209,
        361, 230, 673, 582, 1409, 1501, 1401, 251,
        1022, -1063, 1053, 1188, 417, -1391, -27, -1626,
        1685, -315, 1408, -1248, 400, 274, -1543, 32,
        -1550, 1531, -1367, -124, 1458, 1379, -940, -1681,
        22, 1709, -275, 1108, 354, -1728, -968, 858,
        1221, -218, 294, -732, -1095, 892, 1588, -779
    };

    private static final short[] zetas864_1152 = new short[]{
        -147, -1033, -1265, 708, 460, 1265, -467, 727,
        556, 1307, -773, -161, 1200, -1612, 570, 1529,
        1135, -556, 1120, 298, -822, -1556, -93, 1463,
        532, -377, -909, 58, -392, -450, 1722, 1236,
        -486, -491, -1569, -1078, 36, 1289, -1443, 1628,
        1664, -725, -952, 99, -1020, 353, -599, 1119,
        592, 839, 1622, 652, 1244, -783, -1085, -726,
        566, -284, -1369, -1292, 268, -391, 781, -172,
        96, -1172, 211, 737, 473, -445, -234, 264,
        -1536, 1467, -676, -1542, -170, 635, -705, -1332,
        -658, 831, -1712, 1311, 1488, -881, 1087, -1315,
        1245, -75, 791, -6, -875, -697, -70, -1162,
        287, -767, -945, 1598, -882, 1261, 206, 654,
        -1421, -81, 716, -1251, 838, -1300, 1035, -104,
        966, -558, -61, -1704, 404, -899, 862, -1593,
        -1460, -37, 1266, 965, -1584, -1404, -265, -942,
        905, 1195, -619, 787, 118, 576, 286, -1475,
        -194, 928, 1229, -1032, 1608, 1111, -1669, 642,
        -1323, 163, 309, 981, -557, -258, 232, -1680,
        -1657, -1233, 144, 1699, 311, -1060, 578, 1298,
        -403, 1607, 1074, -148, 447, -1568, 1142, -402,
        -1412, -623, 855, 365, -98, -244, 407, 1225,
        416, 683, -105, 1714, -1019, 1061, 1163, 638,
        798, 1493, -351, 396, -542, -9, 1616, -139,
        -987, -482, 889, 238, -1513, 466, -1089, -101,
        849, -426, 1589, 1487, 671, 1459, -776, 255,
        -1014, 1144, 472, -1153, -325, 1519, -26, -1123,
        324, 1230, 1547, -593, -428, 1192, 1072, -1564,
        688, -333, 1023, -1686, 841, 824, -71, 1587,
        522, -323, 1148, 389, 1231, 384, 1343, 169,
        628, -1329, -1056, -936, 24, -293, 1523, -300,
        -1654, 891, -962, -67, 179, -1177, 844, -509,
        -1677, -1565, -549, -1508, 1191, -280, -43, 669,
        -746, 753, 770, -1046, 1711, 1438, 690, 1083,
        1062, 1727, -883, 553, 1670, 66, 825, -133,
        -1586, 637, -680, -917, 644, -372, -1193, -1136
    };

    // Parameter sets for different security levels
    public static final NTRUPlusParameters ntruplus_kem_768 = new NTRUPlusParameters(
        "NTRU+KEM768",      // name
        768,                 // NTRUPLUS_N
        1152,                // NTRUPLUS_PUBLICKEYBYTES
        4,
        64,
        96,
        zetas768
    );

    public static final NTRUPlusParameters ntruplus_kem_864 = new NTRUPlusParameters(
        "NTRU+KEM864",      // name
        864,                 // NTRUPLUS_N
        1296,                // NTRUPLUS_PUBLICKEYBYTES
        3,
        24,
        144,
        zetas864_1152
    );

    public static final NTRUPlusParameters ntruplus_kem_1152 = new NTRUPlusParameters(
        "NTRU+KEM1152",     // name
        1152,                // NTRUPLUS_N
        1728,                // NTRUPLUS_PUBLICKEYBYTES
        4,
        32,
        144,
        zetas864_1152
    );

    // Instance fields
    private final String name;
    private final int n;                    // NTRUPLUS_N
    private final int publicKeyBytes;       // NTRUPLUS_PUBLICKEYBYTES
    private final int secretKeyBytes;       // NTRUPLUS_SECRETKEYBYTES
    private final int minStep;
    private final int baseStep;
    private final int zetasOffset;
    private final short[] zetas;


    private NTRUPlusParameters(String name, int n, int publicKeyBytes, int minStep, int baseStep, int zetasOffset, short[] zetas)
    {
        this.name = name;
        this.n = n;
        this.publicKeyBytes = publicKeyBytes;
        this.secretKeyBytes = (publicKeyBytes << 1) + 32;
        this.minStep = minStep;
        this.baseStep = baseStep;
        this.zetasOffset = zetasOffset;
        this.zetas = zetas;
    }

    // Getters for all parameters
    public String getName()
    {
        return name;
    }

    public int getN()
    {
        return n;
    }

    public int getSsBytes()
    {
        return 32;
    }

    public int getPublicKeyBytes()
    {
        return publicKeyBytes;
    }

    public int getSecretKeyBytes()
    {
        return secretKeyBytes;
    }

    public int getCiphertextBytes()
    {
        return publicKeyBytes;
    }

    public short[] getZetas()
    {
        return zetas;
    }

    int getBaseStep()
    {
        return baseStep;
    }

    int getMinStep()
    {
        return minStep;
    }

    int getZetasOffset()
    {
        return zetasOffset;
    }
}