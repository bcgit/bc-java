package org.bouncycastle.pqc.crypto.haetae;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

class HAETAEEngine
{
    private final HAETAEParameters params;
    private static final int SHAKE128_RATE = 168; // bytes per block
    private static final int SHAKE256_RATE = 136; // bytes per block
    private static final int QINV = 940508161;
    private static final int FFT_N = 256;
    private static final int FFT_LOGN = 8;
    private static final int F = -29720;
    private static final int MONT = 14321;
    private static final int MONTSQ = 4214;
    private static final long MASK48 = (1L << 48) - 1;
    private static final long DQREC = 33287;
    private static final int RANS_BYTE_L = (1 << 23);
    private final int H_CUT;
    private static final int SCALE_BITS = 10;

    private static final int CDTLEN = 64;

    private static final int GAUSS_RAND = 72 + 16 + 48; // 136
    private static final int GAUSS_RAND_BYTES = (GAUSS_RAND + 7) / 8; // 17

    private static final int POLY_HYPERBALL_BUFLEN = GAUSS_RAND_BYTES * HAETAEParameters.N;
    private static final int POLY_HYPERBALL_NBLOCKS =
        (POLY_HYPERBALL_BUFLEN + SHAKE256_RATE - 1) / SHAKE256_RATE;

    // QREC = ceil(2^32 / HAETAE_Q) used in freeze()
    private static final int QREC = 66575;

    private static final int[] ZETAS = {
        0, 26964, -16505, 22229, 30746, 20243, 19064, -31218, 9395,
        -30985, 22859, -8851, 32144, 13744, 21408, 17599, -16039, -22946,
        6241, -19553, 10681, 22935, 22431, -29104, 28147, -27527, -29133,
        -20035, 20143, -11361, 30820, 25252, -22562, -6789, -10049, 9383,
        16304, -12296, 16446, 18239, -1296, -19725, -32076, 11782, -17941,
        29643, -8577, 7893, -21464, -19646, -15130, -2391, 30608, -23970,
        -16608, 19616, -7941, 26533, -19129, 27690, 7597, -11459, 10615,
        -9430, 11591, 7814, 12697, 32114, -3761, -9604, 19813, 20353,
        17456, -16267, -19555, 598, -29942, 4538, 835, 15546, 3970,
        -27685, 1488, 8311, -12442, 31352, -17631, 1806, -5342, 9790,
        29068, 16507, -29051, 22131, 6759, 15510, -14941, 28710, 1160,
        -31327, 24985, 11261, -10623, -27727, 21502, 18731, -16186, -4127,
        -18832, 12050, -14501, 7929, 29563, -31064, 5913, 5322, -16405,
        2844, 29439, 5876, -9522, -18586, -9874, 23844, 30362, -21442,
        9560, 17671, -27989, 3350, 787, -13857, 1657, -21224, -7374,
        -9190, 2464, 25555, -3529, -28772, 16588, -15739, 23475, 13666,
        5764, 30980, 13633, -7401, -30317, 28847, 7682, -11808, -8796,
        14864, -24162, -19194, 689, -1311, -31332, -16319, 1025, 10971,
        -23016, -2648, -21900, -12543, -25921, 28254, 28521, -16160, 12380,
        -12882, -30332, -16630, 23439, 7742, 17182, 17494, 5920, 13642,
        7382, -18166, 21422, -30274, -28190, 13283, -20316, -9939, 10672,
        21454, 6080, -17374, -29735, -25912, -10170, 3808, 10639, -26985,
        -10865, 25636, 17261, -26851, -8253, -3304, 18282, -2202, -31368,
        -22243, 13882, 12069, -11242, -7729, -10226, 1761, -27298, -4800,
        -17737, -22805, -3528, 65, 10770, 8908, -23751, 26934, 21921,
        -27010, -21944, 8889, -1035, 23224, -9488, -5823, -994, -20206,
        7655, -16251, -22820, -27740, 15822, 23078, 13803, -8099, 2931,
        9217, -21126, -14203, 25492, -12831, 7947, 17463, -12979, 29003,
        31612, 26554, 8241, -20175};

    private static final int[] brv8 = {
        0, 128, 64, 192, 32, 160, 96, 224, 16, 144, 80, 208, 48, 176, 112, 240,
        8, 136, 72, 200, 40, 168, 104, 232, 24, 152, 88, 216, 56, 184, 120, 248,
        4, 132, 68, 196, 36, 164, 100, 228, 20, 148, 84, 212, 52, 180, 116, 244,
        12, 140, 76, 204, 44, 172, 108, 236, 28, 156, 92, 220, 60, 188, 124, 252,
        2, 130, 66, 194, 34, 162, 98, 226, 18, 146, 82, 210, 50, 178, 114, 242,
        10, 138, 74, 202, 42, 170, 106, 234, 26, 154, 90, 218, 58, 186, 122, 250,
        6, 134, 70, 198, 38, 166, 102, 230, 22, 150, 86, 214, 54, 182, 118, 246,
        14, 142, 78, 206, 46, 174, 110, 238, 30, 158, 94, 222, 62, 190, 126, 254,
        1, 129, 65, 193, 33, 161, 97, 225, 17, 145, 81, 209, 49, 177, 113, 241,
        9, 137, 73, 201, 41, 169, 105, 233, 25, 153, 89, 217, 57, 185, 121, 249,
        5, 133, 69, 197, 37, 165, 101, 229, 21, 149, 85, 213, 53, 181, 117, 245,
        13, 141, 77, 205, 45, 173, 109, 237, 29, 157, 93, 221, 61, 189, 125, 253,
        3, 131, 67, 195, 35, 163, 99, 227, 19, 147, 83, 211, 51, 179, 115, 243,
        11, 139, 75, 203, 43, 171, 107, 235, 27, 155, 91, 219, 59, 187, 123, 251,
        7, 135, 71, 199, 39, 167, 103, 231, 23, 151, 87, 215, 55, 183, 119, 247,
        15, 143, 79, 207, 47, 175, 111, 239, 31, 159, 95, 223, 63, 191, 127, 255};

    private static final long[] CDT = {
        3266L, 6520L, 9748L, 12938L, 16079L, 19159L, 22168L, 25096L, 27934L, 30674L, 33309L,
        35833L, 38241L, 40531L, 42698L, 44742L, 46663L, 48460L, 50135L, 51690L, 53128L, 54454L,
        55670L, 56781L, 57794L, 58712L, 59541L, 60287L, 60956L, 61554L, 62085L, 62556L, 62972L,
        63337L, 63657L, 63936L, 64178L, 64388L, 64569L, 64724L, 64857L, 64970L, 65066L, 65148L,
        65216L, 65273L, 65321L, 65361L, 65394L, 65422L, 65444L, 65463L, 65478L, 65490L, 65500L,
        65508L, 65514L, 65519L, 65523L, 65527L, 65529L, 65531L, 65533L, 65534L};
    // Static array of precomputed twiddle factors for the FFT
    private static final ComplexFp32_16[] roots = new ComplexFp32_16[256];

    static
    {
        // Initialize all 256 entries from the C array
        roots[0] = new ComplexFp32_16(65536, 0);
        roots[1] = new ComplexFp32_16(65531, -804);
        roots[2] = new ComplexFp32_16(65516, -1608);
        roots[3] = new ComplexFp32_16(65492, -2412);
        roots[4] = new ComplexFp32_16(65457, -3216);
        roots[5] = new ComplexFp32_16(65413, -4019);
        roots[6] = new ComplexFp32_16(65358, -4821);
        roots[7] = new ComplexFp32_16(65294, -5623);
        roots[8] = new ComplexFp32_16(65220, -6424);
        roots[9] = new ComplexFp32_16(65137, -7224);
        roots[10] = new ComplexFp32_16(65043, -8022);
        roots[11] = new ComplexFp32_16(64940, -8820);
        roots[12] = new ComplexFp32_16(64827, -9616);
        roots[13] = new ComplexFp32_16(64704, -10411);
        roots[14] = new ComplexFp32_16(64571, -11204);
        roots[15] = new ComplexFp32_16(64429, -11996);
        roots[16] = new ComplexFp32_16(64277, -12785);
        roots[17] = new ComplexFp32_16(64115, -13573);
        roots[18] = new ComplexFp32_16(63944, -14359);
        roots[19] = new ComplexFp32_16(63763, -15143);
        roots[20] = new ComplexFp32_16(63572, -15924);
        roots[21] = new ComplexFp32_16(63372, -16703);
        roots[22] = new ComplexFp32_16(63162, -17479);
        roots[23] = new ComplexFp32_16(62943, -18253);
        roots[24] = new ComplexFp32_16(62714, -19024);
        roots[25] = new ComplexFp32_16(62476, -19792);
        roots[26] = new ComplexFp32_16(62228, -20557);
        roots[27] = new ComplexFp32_16(61971, -21320);
        roots[28] = new ComplexFp32_16(61705, -22078);
        roots[29] = new ComplexFp32_16(61429, -22834);
        roots[30] = new ComplexFp32_16(61145, -23586);
        roots[31] = new ComplexFp32_16(60851, -24335);
        roots[32] = new ComplexFp32_16(60547, -25080);
        roots[33] = new ComplexFp32_16(60235, -25821);
        roots[34] = new ComplexFp32_16(59914, -26558);
        roots[35] = new ComplexFp32_16(59583, -27291);
        roots[36] = new ComplexFp32_16(59244, -28020);
        roots[37] = new ComplexFp32_16(58896, -28745);
        roots[38] = new ComplexFp32_16(58538, -29466);
        roots[39] = new ComplexFp32_16(58172, -30182);
        roots[40] = new ComplexFp32_16(57798, -30893);
        roots[41] = new ComplexFp32_16(57414, -31600);
        roots[42] = new ComplexFp32_16(57022, -32303);
        roots[43] = new ComplexFp32_16(56621, -33000);
        roots[44] = new ComplexFp32_16(56212, -33692);
        roots[45] = new ComplexFp32_16(55794, -34380);
        roots[46] = new ComplexFp32_16(55368, -35062);
        roots[47] = new ComplexFp32_16(54934, -35738);
        roots[48] = new ComplexFp32_16(54491, -36410);
        roots[49] = new ComplexFp32_16(54040, -37076);
        roots[50] = new ComplexFp32_16(53581, -37736);
        roots[51] = new ComplexFp32_16(53114, -38391);
        roots[52] = new ComplexFp32_16(52639, -39040);
        roots[53] = new ComplexFp32_16(52156, -39683);
        roots[54] = new ComplexFp32_16(51665, -40320);
        roots[55] = new ComplexFp32_16(51166, -40951);
        roots[56] = new ComplexFp32_16(50660, -41576);
        roots[57] = new ComplexFp32_16(50146, -42194);
        roots[58] = new ComplexFp32_16(49624, -42806);
        roots[59] = new ComplexFp32_16(49095, -43412);
        roots[60] = new ComplexFp32_16(48559, -44011);
        roots[61] = new ComplexFp32_16(48015, -44604);
        roots[62] = new ComplexFp32_16(47464, -45190);
        roots[63] = new ComplexFp32_16(46906, -45769);
        roots[64] = new ComplexFp32_16(46341, -46341);
        roots[65] = new ComplexFp32_16(45769, -46906);
        roots[66] = new ComplexFp32_16(45190, -47464);
        roots[67] = new ComplexFp32_16(44604, -48015);
        roots[68] = new ComplexFp32_16(44011, -48559);
        roots[69] = new ComplexFp32_16(43412, -49095);
        roots[70] = new ComplexFp32_16(42806, -49624);
        roots[71] = new ComplexFp32_16(42194, -50146);
        roots[72] = new ComplexFp32_16(41576, -50660);
        roots[73] = new ComplexFp32_16(40951, -51166);
        roots[74] = new ComplexFp32_16(40320, -51665);
        roots[75] = new ComplexFp32_16(39683, -52156);
        roots[76] = new ComplexFp32_16(39040, -52639);
        roots[77] = new ComplexFp32_16(38391, -53114);
        roots[78] = new ComplexFp32_16(37736, -53581);
        roots[79] = new ComplexFp32_16(37076, -54040);
        roots[80] = new ComplexFp32_16(36410, -54491);
        roots[81] = new ComplexFp32_16(35738, -54934);
        roots[82] = new ComplexFp32_16(35062, -55368);
        roots[83] = new ComplexFp32_16(34380, -55794);
        roots[84] = new ComplexFp32_16(33692, -56212);
        roots[85] = new ComplexFp32_16(33000, -56621);
        roots[86] = new ComplexFp32_16(32303, -57022);
        roots[87] = new ComplexFp32_16(31600, -57414);
        roots[88] = new ComplexFp32_16(30893, -57798);
        roots[89] = new ComplexFp32_16(30182, -58172);
        roots[90] = new ComplexFp32_16(29466, -58538);
        roots[91] = new ComplexFp32_16(28745, -58896);
        roots[92] = new ComplexFp32_16(28020, -59244);
        roots[93] = new ComplexFp32_16(27291, -59583);
        roots[94] = new ComplexFp32_16(26558, -59914);
        roots[95] = new ComplexFp32_16(25821, -60235);
        roots[96] = new ComplexFp32_16(25080, -60547);
        roots[97] = new ComplexFp32_16(24335, -60851);
        roots[98] = new ComplexFp32_16(23586, -61145);
        roots[99] = new ComplexFp32_16(22834, -61429);
        roots[100] = new ComplexFp32_16(22078, -61705);
        roots[101] = new ComplexFp32_16(21320, -61971);
        roots[102] = new ComplexFp32_16(20557, -62228);
        roots[103] = new ComplexFp32_16(19792, -62476);
        roots[104] = new ComplexFp32_16(19024, -62714);
        roots[105] = new ComplexFp32_16(18253, -62943);
        roots[106] = new ComplexFp32_16(17479, -63162);
        roots[107] = new ComplexFp32_16(16703, -63372);
        roots[108] = new ComplexFp32_16(15924, -63572);
        roots[109] = new ComplexFp32_16(15143, -63763);
        roots[110] = new ComplexFp32_16(14359, -63944);
        roots[111] = new ComplexFp32_16(13573, -64115);
        roots[112] = new ComplexFp32_16(12785, -64277);
        roots[113] = new ComplexFp32_16(11996, -64429);
        roots[114] = new ComplexFp32_16(11204, -64571);
        roots[115] = new ComplexFp32_16(10411, -64704);
        roots[116] = new ComplexFp32_16(9616, -64827);
        roots[117] = new ComplexFp32_16(8820, -64940);
        roots[118] = new ComplexFp32_16(8022, -65043);
        roots[119] = new ComplexFp32_16(7224, -65137);
        roots[120] = new ComplexFp32_16(6424, -65220);
        roots[121] = new ComplexFp32_16(5623, -65294);
        roots[122] = new ComplexFp32_16(4821, -65358);
        roots[123] = new ComplexFp32_16(4019, -65413);
        roots[124] = new ComplexFp32_16(3216, -65457);
        roots[125] = new ComplexFp32_16(2412, -65492);
        roots[126] = new ComplexFp32_16(1608, -65516);
        roots[127] = new ComplexFp32_16(804, -65531);
        roots[128] = new ComplexFp32_16(0, -65536);
        roots[129] = new ComplexFp32_16(-804, -65531);
        roots[130] = new ComplexFp32_16(-1608, -65516);
        roots[131] = new ComplexFp32_16(-2412, -65492);
        roots[132] = new ComplexFp32_16(-3216, -65457);
        roots[133] = new ComplexFp32_16(-4019, -65413);
        roots[134] = new ComplexFp32_16(-4821, -65358);
        roots[135] = new ComplexFp32_16(-5623, -65294);
        roots[136] = new ComplexFp32_16(-6424, -65220);
        roots[137] = new ComplexFp32_16(-7224, -65137);
        roots[138] = new ComplexFp32_16(-8022, -65043);
        roots[139] = new ComplexFp32_16(-8820, -64940);
        roots[140] = new ComplexFp32_16(-9616, -64827);
        roots[141] = new ComplexFp32_16(-10411, -64704);
        roots[142] = new ComplexFp32_16(-11204, -64571);
        roots[143] = new ComplexFp32_16(-11996, -64429);
        roots[144] = new ComplexFp32_16(-12785, -64277);
        roots[145] = new ComplexFp32_16(-13573, -64115);
        roots[146] = new ComplexFp32_16(-14359, -63944);
        roots[147] = new ComplexFp32_16(-15143, -63763);
        roots[148] = new ComplexFp32_16(-15924, -63572);
        roots[149] = new ComplexFp32_16(-16703, -63372);
        roots[150] = new ComplexFp32_16(-17479, -63162);
        roots[151] = new ComplexFp32_16(-18253, -62943);
        roots[152] = new ComplexFp32_16(-19024, -62714);
        roots[153] = new ComplexFp32_16(-19792, -62476);
        roots[154] = new ComplexFp32_16(-20557, -62228);
        roots[155] = new ComplexFp32_16(-21320, -61971);
        roots[156] = new ComplexFp32_16(-22078, -61705);
        roots[157] = new ComplexFp32_16(-22834, -61429);
        roots[158] = new ComplexFp32_16(-23586, -61145);
        roots[159] = new ComplexFp32_16(-24335, -60851);
        roots[160] = new ComplexFp32_16(-25080, -60547);
        roots[161] = new ComplexFp32_16(-25821, -60235);
        roots[162] = new ComplexFp32_16(-26558, -59914);
        roots[163] = new ComplexFp32_16(-27291, -59583);
        roots[164] = new ComplexFp32_16(-28020, -59244);
        roots[165] = new ComplexFp32_16(-28745, -58896);
        roots[166] = new ComplexFp32_16(-29466, -58538);
        roots[167] = new ComplexFp32_16(-30182, -58172);
        roots[168] = new ComplexFp32_16(-30893, -57798);
        roots[169] = new ComplexFp32_16(-31600, -57414);
        roots[170] = new ComplexFp32_16(-32303, -57022);
        roots[171] = new ComplexFp32_16(-33000, -56621);
        roots[172] = new ComplexFp32_16(-33692, -56212);
        roots[173] = new ComplexFp32_16(-34380, -55794);
        roots[174] = new ComplexFp32_16(-35062, -55368);
        roots[175] = new ComplexFp32_16(-35738, -54934);
        roots[176] = new ComplexFp32_16(-36410, -54491);
        roots[177] = new ComplexFp32_16(-37076, -54040);
        roots[178] = new ComplexFp32_16(-37736, -53581);
        roots[179] = new ComplexFp32_16(-38391, -53114);
        roots[180] = new ComplexFp32_16(-39040, -52639);
        roots[181] = new ComplexFp32_16(-39683, -52156);
        roots[182] = new ComplexFp32_16(-40320, -51665);
        roots[183] = new ComplexFp32_16(-40951, -51166);
        roots[184] = new ComplexFp32_16(-41576, -50660);
        roots[185] = new ComplexFp32_16(-42194, -50146);
        roots[186] = new ComplexFp32_16(-42806, -49624);
        roots[187] = new ComplexFp32_16(-43412, -49095);
        roots[188] = new ComplexFp32_16(-44011, -48559);
        roots[189] = new ComplexFp32_16(-44604, -48015);
        roots[190] = new ComplexFp32_16(-45190, -47464);
        roots[191] = new ComplexFp32_16(-45769, -46906);
        roots[192] = new ComplexFp32_16(-46341, -46341);
        roots[193] = new ComplexFp32_16(-46906, -45769);
        roots[194] = new ComplexFp32_16(-47464, -45190);
        roots[195] = new ComplexFp32_16(-48015, -44604);
        roots[196] = new ComplexFp32_16(-48559, -44011);
        roots[197] = new ComplexFp32_16(-49095, -43412);
        roots[198] = new ComplexFp32_16(-49624, -42806);
        roots[199] = new ComplexFp32_16(-50146, -42194);
        roots[200] = new ComplexFp32_16(-50660, -41576);
        roots[201] = new ComplexFp32_16(-51166, -40951);
        roots[202] = new ComplexFp32_16(-51665, -40320);
        roots[203] = new ComplexFp32_16(-52156, -39683);
        roots[204] = new ComplexFp32_16(-52639, -39040);
        roots[205] = new ComplexFp32_16(-53114, -38391);
        roots[206] = new ComplexFp32_16(-53581, -37736);
        roots[207] = new ComplexFp32_16(-54040, -37076);
        roots[208] = new ComplexFp32_16(-54491, -36410);
        roots[209] = new ComplexFp32_16(-54934, -35738);
        roots[210] = new ComplexFp32_16(-55368, -35062);
        roots[211] = new ComplexFp32_16(-55794, -34380);
        roots[212] = new ComplexFp32_16(-56212, -33692);
        roots[213] = new ComplexFp32_16(-56621, -33000);
        roots[214] = new ComplexFp32_16(-57022, -32303);
        roots[215] = new ComplexFp32_16(-57414, -31600);
        roots[216] = new ComplexFp32_16(-57798, -30893);
        roots[217] = new ComplexFp32_16(-58172, -30182);
        roots[218] = new ComplexFp32_16(-58538, -29466);
        roots[219] = new ComplexFp32_16(-58896, -28745);
        roots[220] = new ComplexFp32_16(-59244, -28020);
        roots[221] = new ComplexFp32_16(-59583, -27291);
        roots[222] = new ComplexFp32_16(-59914, -26558);
        roots[223] = new ComplexFp32_16(-60235, -25821);
        roots[224] = new ComplexFp32_16(-60547, -25080);
        roots[225] = new ComplexFp32_16(-60851, -24335);
        roots[226] = new ComplexFp32_16(-61145, -23586);
        roots[227] = new ComplexFp32_16(-61429, -22834);
        roots[228] = new ComplexFp32_16(-61705, -22078);
        roots[229] = new ComplexFp32_16(-61971, -21320);
        roots[230] = new ComplexFp32_16(-62228, -20557);
        roots[231] = new ComplexFp32_16(-62476, -19792);
        roots[232] = new ComplexFp32_16(-62714, -19024);
        roots[233] = new ComplexFp32_16(-62943, -18253);
        roots[234] = new ComplexFp32_16(-63162, -17479);
        roots[235] = new ComplexFp32_16(-63372, -16703);
        roots[236] = new ComplexFp32_16(-63572, -15924);
        roots[237] = new ComplexFp32_16(-63763, -15143);
        roots[238] = new ComplexFp32_16(-63944, -14359);
        roots[239] = new ComplexFp32_16(-64115, -13573);
        roots[240] = new ComplexFp32_16(-64277, -12785);
        roots[241] = new ComplexFp32_16(-64429, -11996);
        roots[242] = new ComplexFp32_16(-64571, -11204);
        roots[243] = new ComplexFp32_16(-64704, -10411);
        roots[244] = new ComplexFp32_16(-64827, -9616);
        roots[245] = new ComplexFp32_16(-64940, -8820);
        roots[246] = new ComplexFp32_16(-65043, -8022);
        roots[247] = new ComplexFp32_16(-65137, -7224);
        roots[248] = new ComplexFp32_16(-65220, -6424);
        roots[249] = new ComplexFp32_16(-65294, -5623);
        roots[250] = new ComplexFp32_16(-65358, -4821);
        roots[251] = new ComplexFp32_16(-65413, -4019);
        roots[252] = new ComplexFp32_16(-65457, -3216);
        roots[253] = new ComplexFp32_16(-65492, -2412);
        roots[254] = new ComplexFp32_16(-65516, -1608);
        roots[255] = new ComplexFp32_16(-65531, -804);
    }

    HAETAEEngine(HAETAEParameters params)
    {
        this.params = params;
        this.H_CUT = ((params.getM_h() - 1) >> 1);
    }

    /**
     * Expands matrix A of size K x M using seed rho.
     * matA[i][j] is a polynomial (int array of length N).
     *
     * @param matA output array: [K][M][N]
     * @param rho  seed of length SEED_BYTES
     */
    public void polymatkm_expand_matA(int[][][] matA, byte[] rho)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < params.getM(); j++)
            {
                poly_uniform(matA[i][j], rho, (short)((i << 8) + j));
            }
        }
    }

    /**
     * Fills polynomial a with coefficients uniformly in [0, Q-1].
     *
     * @param a     output polynomial (length N)
     * @param seed  seed of length SEED_BYTES
     * @param nonce 16-bit domain separator
     */
    public void poly_uniform(int[] a, byte[] seed, short nonce)
    {
        // Initialize SHAKE-128 with seed and nonce
        SHAKEDigest shake = new SHAKEDigest(128);
        shake.update(seed, 0, HAETAEParameters.SEED_BYTES);
        // nonce as 2 bytes little-endian
        shake.update((byte)(nonce & 0xFF));
        shake.update((byte)((nonce >> 8) & 0xFF));

        // Buffer to hold one block plus leftover bytes
        byte[] buf = new byte[SHAKE128_RATE + 2];
        int bufPos = 0;
        int bufLen = 0;
        int ctr = 0;

        while (ctr < HAETAEParameters.N)
        {
            // If not enough bytes for next coefficient, refill buffer
            if (bufLen - bufPos < 2)
            {
                // Move remaining bytes to start of buffer
                int rem = bufLen - bufPos;
                if (rem > 0)
                {
                    System.arraycopy(buf, bufPos, buf, 0, rem);
                }
                // Squeeze one full block (SHAKE128_RATE bytes) after the remainder
                shake.doOutput(buf, rem, SHAKE128_RATE);
                bufPos = 0;
                bufLen = rem + SHAKE128_RATE;
            }

            // Read 16-bit little-endian value
            int t = (buf[bufPos++] & 0xFF) | ((buf[bufPos++] & 0xFF) << 8);
            if (t < HAETAEParameters.Q)
            {
                a[ctr++] = t;
            }
        }
    }

    /**
     * Rejection sampling helper (used internally).
     * Returns number of accepted coefficients.
     */
    private int rej_uniform(int[] a, int start, int len, byte[] buf, int buflen)
    {
        int ctr = 0;
        int pos = 0;
        while (ctr < len && pos + 1 < buflen)
        {
            int t = (buf[pos++] & 0xFF) | ((buf[pos++] & 0xFF) << 8);
            if (t < HAETAEParameters.Q)
            {
                a[start + ctr] = t;
                ctr++;
            }
        }
        return ctr;
    }


    /**
     * Expands secret vectors u (size M) and v (size K) using SHAKE-256.
     *
     * @param u     output vector u: [M][N]
     * @param v     output vector v: [K][N]
     * @param seed  seed of length CRH_BYTES (64 bytes)
     * @param nonce starting nonce (incremented for each polynomial)
     */
    public void polyvecmk_expand_S(int[][] u, int[][] v, byte[] seed, short nonce)
    {
        int n = nonce & 0xFFFF;
        for (int i = 0; i < params.getM(); i++)
        {
            poly_uniform_eta(u[i], seed, (short)n++);
        }
        for (int i = 0; i < params.getK(); i++)
        {
            poly_uniform_eta(v[i], seed, (short)n++);
        }
    }

    /**
     * Fills polynomial a with coefficients in {-1, 0, 1} using rejection sampling.
     *
     * @param a     output polynomial (length N)
     * @param seed  seed of length CRH_BYTES
     * @param nonce 16-bit domain separator
     */
    public void poly_uniform_eta(int[] a, byte[] seed, short nonce)
    {
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(seed, 0, HAETAEParameters.CRH_BYTES);
        shake.update((byte)(nonce & 0xFF));
        shake.update((byte)((nonce >> 8) & 0xFF));

        // Buffer large enough for one block plus leftover bytes
        byte[] buf = new byte[SHAKE256_RATE + 4];
        int bufPos = 0;
        int bufLen = 0;
        int ctr = 0;

        while (ctr < HAETAEParameters.N)
        {
            // If buffer is empty or nearly exhausted, refill
            if (bufLen - bufPos < 1)
            {
                // Move any remaining bytes to the start
                int rem = bufLen - bufPos;
                if (rem > 0)
                {
                    System.arraycopy(buf, bufPos, buf, 0, rem);
                }
                // Squeeze one full block (SHAKE256_RATE bytes)
                shake.doOutput(buf, rem, SHAKE256_RATE);
                bufPos = 0;
                bufLen = rem + SHAKE256_RATE;
            }

            int t = buf[bufPos++] & 0xFF;
            if (t < 243)
            {
                // Process up to 5 coefficients from this byte
                // First coefficient
                a[ctr++] = mod3(t);
                if (ctr >= HAETAEParameters.N)
                {
                    break;
                }

                // Second coefficient
                int t2 = (t * 171) >>> 9;  // equivalent to (t * 171) >> 9
                a[ctr++] = mod3(t2);
                if (ctr >= HAETAEParameters.N)
                {
                    break;
                }

                // Third coefficient
                t2 = (t2 * 171) >>> 9;
                a[ctr++] = mod3_leq26(t2);
                if (ctr >= HAETAEParameters.N)
                {
                    break;
                }

                // Fourth coefficient
                t2 = (t2 * 171) >>> 9;
                a[ctr++] = mod3_leq8(t2);
                if (ctr >= HAETAEParameters.N)
                {
                    break;
                }

                // Fifth coefficient
                t2 = (t2 * 171) >>> 9;
                a[ctr++] = t2 - 3 * (t2 >>> 1);
            }
        }
    }

    /**
     * Reduce an unsigned byte modulo 3 (value may be up to 255).
     * Returns a value in {0, 1, 2}.
     */
    private static int mod3(int t)
    {
        int r = (t >>> 4) + (t & 0xF);
        r = (r >>> 2) + (r & 3);
        r = (r >>> 2) + (r & 3);
        r = (r >>> 2) + (r & 3);
        return r - 3 * (r >>> 1);
    }

    /**
     * Reduce a value t ≤ 26 modulo 3.
     */
    private static int mod3_leq26(int t)
    {
        int r = (t >>> 4) + (t & 0xF);
        r = (r >>> 2) + (r & 3);
        r = (r >>> 2) + (r & 3);
        return r - 3 * (r >>> 1);
    }

    /**
     * Reduce a value t ≤ 8 modulo 3.
     */
    private static int mod3_leq8(int t)
    {
        int r = (t >>> 2) + (t & 3);
        r = (r >>> 2) + (r & 3);
        return r - 3 * (r >>> 1);
    }

    /**
     * Montgomery reduction: maps a 64‑bit value to [0, Q-1].
     * <p>
     * Computes (a * QINV) mod 2^32, multiplies by Q, subtracts from a,
     * and takes the upper 32 bits.
     * </p>
     *
     * @param a 64‑bit signed integer (product of two ints)
     * @return reduced value modulo Q in [0, Q-1]
     */
    private static int montgomeryReduce(long a)
    {
        int t = (int)a * QINV;          // low 32 bits of a * QINV
        long tt = a - ((long)t * HAETAEParameters.Q);
        return (int)(tt >> 32);
    }

    /**
     * In‑place forward NTT on an array of length N = 256.
     *
     * @param a input/output array (modified in place)
     */
    private void ntt(int[] a)
    {
        int k = 0, j;
        for (int len = 128; len > 0; len >>= 1)
        {
            for (int start = 0; start < HAETAEParameters.N; start = j + len)
            {
                int zeta = ZETAS[++k];
                for (j = start; j < start + len; ++j)
                {
                    int t = montgomeryReduce((long)zeta * a[j + len]);
                    a[j + len] = a[j] - t;
                    a[j] = a[j] + t;
                }
            }
        }
    }

    /**
     * Applies NTT to a single polynomial.
     *
     * @param a polynomial (int array of length N)
     */
    public void polyNtt(int[] a)
    {
        ntt(a);
    }

    /**
     * Applies NTT to a polynomial vector of length M.
     *
     * @param x vector of M polynomials (2D int array: [M][N])
     */
    public void polyvecmNtt(int[][] x)
    {
        for (int i = 0; i < params.getM(); i++)
        {
            polyNtt(x[i]);
        }
    }

    /**
     * Applies NTT to a polynomial vector of length K.
     *
     * @param x vector of K polynomials (2D int array: [K][N])
     */
    public void polyveckNtt(int[][] x)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyNtt(x[i]);
        }
    }

    /**
     * Computes t = mat * v  (matrix-vector product in NTT domain).
     *
     * @param t   output vector of length K (each polynomial of length N)
     * @param mat matrix of size K x M (each entry is a polynomial)
     * @param v   input vector of length M
     */
    public void polymatkmPointwiseMontgomery(int[][] t, int[][][] mat, int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyvecmPointwiseAccMontgomery(t[i], mat[i], v);
        }
    }

    /**
     * Accumulates pointwise products of two polynomial vectors u and v into w.
     * w = sum_{j=0}^{M-1} (u_j ∘ v_j)   (pointwise multiplication)
     *
     * @param w output polynomial (length N)
     * @param u first vector (M polynomials)
     * @param v second vector (M polynomials)
     */
    private void polyvecmPointwiseAccMontgomery(int[] w, int[][] u, int[][] v)
    {
        polyPointwiseMontgomery(w, u[0], v[0]);

        for (int j = 1; j < params.getM(); j++)
        {
            polyAccPointwiseMontgomery(w, u[j], v[j]);
        }
    }

    /**
     * Pointwise multiplication of two polynomials: c[i] = a[i] * b[i] mod Q.
     * Coefficients are assumed to be in Montgomery domain.
     *
     * @param c output polynomial (length N)
     * @param a first input polynomial
     * @param b second input polynomial
     */
    private void polyPointwiseMontgomery(int[] c, int[] a, int[] b)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            c[i] = montgomeryReduce((long)a[i] * b[i]);
        }
    }

    private void polyAccPointwiseMontgomery(int[] w, int[] a, int[] b)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            w[i] += montgomeryReduce((long)a[i] * b[i]);
        }
    }

    /**
     * Adds two polynomials: c = a + b.
     * No modular reduction is performed; coefficients may exceed Q.
     * (Used internally in accumulation.)
     *
     * @param c result polynomial (may alias a or b)
     * @param a first polynomial
     * @param b second polynomial
     */
    private void polyAdd(int[] c, int[] a, int[] b)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            c[i] = a[i] + b[i];
        }
    }

    /**
     * Inverse NTT and multiplication by Montgomery factor 2^32.
     * In-place. Input coefficients are expected to be small enough.
     *
     * @param a polynomial coefficients (length N)
     */
    private void invnttTomont(int[] a)
    {
        int k = 256, j;
        for (int len = 1; len < HAETAEParameters.N; len <<= 1)
        {
            for (int start = 0; start < HAETAEParameters.N; start = j + len)
            {
                int zeta = -ZETAS[--k];
                for (j = start; j < start + len; j++)
                {
                    int t = a[j];
                    a[j] = t + a[j + len];
                    a[j + len] = t - a[j + len];
                    a[j + len] = montgomeryReduce((long)zeta * a[j + len]);
                }
            }
        }

        // Multiply by f = mont^2 / 256
        for (j = 0; j < HAETAEParameters.N; j++)
        {
            a[j] = montgomeryReduce((long)F * a[j]);
        }
    }

    /**
     * Applies inverse NTT + Montgomery factor to a single polynomial.
     *
     * @param a polynomial (length N)
     */
    public void polyInvnttTomont(int[] a)
    {
        invnttTomont(a);
    }

    /**
     * Applies inverse NTT + Montgomery factor to a polynomial vector of length K.
     *
     * @param x vector of K polynomials (K x N)
     */
    public void polyveckInvnttTomont(int[][] x)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyInvnttTomont(x[i]);
        }
    }

    /**
     * Vector addition: w = u + v (element-wise, no reduction).
     *
     * @param w result vector (may alias u or v)
     * @param u first operand
     * @param v second operand
     */
    public void polyveckAdd(int[][] w, int[][] u, int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyAdd(w[i], u[i], v[i]);
        }
    }

    /**
     * Freezes a polynomial vector: reduces each coefficient to [0, Q-1].
     *
     * @param v vector of K polynomials
     */
    public void polyveckFreeze(int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyFreeze(v[i]);
        }
    }

    /**
     * Freezes a polynomial: reduces each coefficient to [0, Q-1].
     *
     * @param a polynomial (length N)
     */
    public void polyFreeze(int[] a)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            a[i] = freeze(a[i]);
        }
    }

    /**
     * Standard representative r = a mod^+ Q.
     * Assumes input is in range [-2Q, 2Q] (or similar).
     *
     * @param a finite field element
     * @return r in [0, Q-1]
     */
    private int freeze(int a)
    {
        // t = (a * QREC) >> 32  (approximate division by Q)
        long t = ((long)a * QREC) >> 32;
        long r = a - t * HAETAEParameters.Q;          // -2Q < r < 2Q
        r += (r >> 31) & HAETAEParameters.DQ;         // 0 <= r < 2Q
        r -= ~((r - HAETAEParameters.Q) >> 31) & HAETAEParameters.Q; // 0 <= r < Q
        return (int)r;
    }

    /**
     * Decomposes a coefficient into high and low parts.
     * <p>
     * The low part is in {-1, 0, 1} and satisfies: {@code a = 2 * high + low}.
     * Returned packed as {@code ((high & 0xFFFFFFFFL) << 32) | (low & 0xFFFFFFFFL)}.
     * </p>
     */
    private static long decomposeVkPacked(int a)
    {
        int low = a & 1;
        low -= (((a >> 1) & low) << 1);
        return (((long)((a - low) >> 1)) << 32) | (low & 0xFFFFFFFFL);
    }

    /**
     * Decomposes a polynomial vector v into high and low parts.
     * <p>
     * On return, {@code v} contains the high parts and {@code v0} contains the low parts.
     * </p>
     *
     * @param v0 output vector for low parts (modified in place)
     * @param v  input/output vector for high parts (modified in place)
     */
    public void polyveckDecomposeVk(int[][] v0, int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            int[] vi = v[i];
            int[] v0i = v0[i];
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                long packed = decomposeVkPacked(vi[j]);
                vi[j] = (int)(packed >>> 32);
                v0i[j] = (int)packed;
            }
        }
    }

    /**
     * Vector subtraction: w = u - v (element-wise, no modular reduction).
     *
     * @param w result vector (may alias u or v)
     * @param u first operand
     * @param v second operand
     */
    public void polyveckSub(int[][] w, int[][] u, int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polySub(w[i], u[i], v[i]);
        }
    }

    /**
     * Polynomial subtraction: c = a - b (element-wise, no reduction).
     *
     * @param c result polynomial
     * @param a first operand
     * @param b second operand
     */
    private void polySub(int[] c, int[] a, int[] b)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            c[i] = a[i] - b[i];
        }
    }

    /**
     * Multiply two fixed‑point numbers and round to 16 fractional bits.
     * Equivalent to: (x * y + (1 << 15)) >> 16
     */
    private static int mulrnd16(int x, int y)
    {
        long r = ((long)x * (long)y) + (1L << 15);
        return (int)(r >> 16);
    }

    /**
     * Real part of complex multiplication: a.real * b.real - a.imag * b.imag
     */
    private static int complexMulReal(ComplexFp32_16 a, ComplexFp32_16 b)
    {
        return mulrnd16(a.real, b.real) - mulrnd16(a.imag, b.imag);
    }

    /**
     * Imaginary part of complex multiplication: a.real * b.imag + a.imag * b.real
     */
    private static int complexMulImag(ComplexFp32_16 a, ComplexFp32_16 b)
    {
        return mulrnd16(a.real, b.imag) + mulrnd16(a.imag, b.real);
    }

    /**
     * Multiply two complex numbers, store result in r.
     */
    private static void complexMul(ComplexFp32_16 r, ComplexFp32_16 x, ComplexFp32_16 y)
    {
        r.real = complexMulReal(x, y);
        r.imag = complexMulImag(x, y);
    }

    /**
     * Squared absolute value of a complex number (real² + imag²).
     */
    private static int complexFpSqabs(ComplexFp32_16 x)
    {
        return mulrnd16(x.real, x.real) + mulrnd16(x.imag, x.imag);
    }

    // ---------- FFT ----------

    /**
     * Initializes FFT input array with polynomial coefficients multiplied by twiddle factors.
     * Performs bit‑reversal permutation.
     *
     * @param r output complex array (size FFT_N)
     * @param x input polynomial (length N = 256)
     */
    private void fftInitAndBitrev(ComplexFp32_16[] r, int[] x)
    {
        for (int i = 0; i < FFT_N; i++)
        {
            int invI = brv8[i]; // placeholder – actual bit‑reversal may differ
            int c = x[i];       // polynomial coefficient
            r[invI].real = c * roots[i].real;
            r[invI].imag = c * roots[i].imag;
        }
    }

    /**
     * In‑place decimation‑in‑time FFT.
     *
     * @param data input/output array (size FFT_N)
     */
    private void fft(ComplexFp32_16[] data)
    {
        for (int r = 1; r <= FFT_LOGN; r++)
        {
            int m = 1 << r;
            int md2 = m >>> 1;
            for (int n = 0; n < FFT_N; n += m)
            {
                for (int k = 0; k < md2; k++)
                {
                    int even = n + k;
                    int odd = even + md2;
                    int twid = k << (FFT_LOGN - r + 1);

                    ComplexFp32_16 u = new ComplexFp32_16(data[even].real, data[even].imag);
                    ComplexFp32_16 t = new ComplexFp32_16();
                    complexMul(t, roots[twid], data[odd]);
//                    System.out.print("r: "+ r + " n: "+ n + " k: "+ k+ " even: "+ even + " odd: "+ odd +
//                        " data[" +even+"]: "+data[even].real + " "+data[even].imag + " data[" +odd+"]: "+data[odd].real + " "+data[odd].imag +
//                        "roots[" +twid+"]: "+ roots[twid].real + " "+ roots[twid].imag);
                    data[even].real = u.real + t.real;
                    data[even].imag = u.imag + t.imag;
                    data[odd].real = u.real - t.real;
                    data[odd].imag = u.imag - t.imag;
                    //System.out.println(" data[" +even+"]: "+data[even].real + " "+data[even].imag + " data[" +odd+"]: "+data[odd].real + " "+data[odd].imag);

                }
            }
        }
    }

    // ---------- Branchless min/max swap (djbsort) ----------

    /**
     * Branchless min/max swap (djbsort). Returns packed
     * {@code (max << 32) | (min & 0xFFFFFFFFL)}.
     */
    private static long minmaxPacked(int a, int b)
    {
        int ab = b ^ a;
        int c = b - a;
        c ^= ab & (c ^ b);
        c >>= 31;
        c &= ab;
        return ((long)(b ^ c) << 32) | ((a ^ c) & 0xFFFFFFFFL);
    }

    // ---------- Singular Value Computation ----------

    /**
     * Computes the singular value of the secret key (s1, s2).
     * Used during key generation to reject weak keys.
     *
     * @param s1 secret vector of length M (M x N)
     * @param s2 secret vector of length K (K x N)
     * @return the squared singular value metric
     */
    public long polyvecmkSkSingularValue(int[][] s1, int[][] s2)
    {
        ComplexFp32_16[] input = new ComplexFp32_16[FFT_N];
        for (int i = 0; i < FFT_N; i++)
        {
            input[i] = new ComplexFp32_16();
        }

        int[] sum = new int[HAETAEParameters.N];
        int tau = params.getTau();
        int bestmSize = HAETAEParameters.N / tau + 1;
        int[] bestm = new int[bestmSize];

        // Process s1 (M polynomials)
        for (int i = 0; i < params.getM(); i++)
        {
            fftInitAndBitrev(input, s1[i]);
            fft(input);
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                sum[j] += complexFpSqabs(input[j]);
            }
        }

        // Process s2 (K polynomials)
        for (int i = 0; i < params.getK(); i++)
        {
            fftInitAndBitrev(input, s2[i]);
            fft(input);
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                sum[j] += complexFpSqabs(input[j]);
            }
        }

        // Compute bestm (maximum of subsets of size tau)
        System.arraycopy(sum, 0, bestm, 0, bestmSize);
        for (int i = bestmSize; i < HAETAEParameters.N; i++)
        {
            int val = sum[i];
            for (int j = 0; j < bestmSize; j++)
            {
                long packed = minmaxPacked(val, bestm[j]);
                val = (int)packed;
                bestm[j] = (int)(packed >>> 32);
            }
        }

        // Find minimum among bestm
        int min = bestm[0];
        for (int i = 1; i < bestmSize; i++)
        {
            min = (int)minmaxPacked(min, bestm[i]);
        }

        // Multiply by appropriate factor and accumulate result
        long res = 0;
        int nModTau = HAETAEParameters.N % tau;
        for (int i = 0; i < bestmSize; i++)
        {
            // fac = (min != bestm[i]) ? tau : nModTau
            int diff = min - bestm[i];
            int fac = (diff >> 31);               // all ones if bestm[i] != min
            fac = (fac & tau) | ((~fac) & nModTau);

            int val = bestm[i] + 0x10200;          // add bias and prepare rounding
            val >>= 10;                            // round off 10 bits
            val *= fac;
            res += val;
        }

        return (res + (1L << 5)) >> 6;            // final rounding
    }

    /**
     * Packs a public key: [seed (32 bytes) | b (K * polyq_packed_bytes)].
     *
     * @param vk   output byte array of length CRYPTO_PUBLICKEYBYTES
     * @param b    vector b (K polynomials)
     * @param seed 32-byte seed
     */
    public void packVk(byte[] vk, int[][] b, byte[] seed)
    {
        System.arraycopy(seed, 0, vk, 0, HAETAEParameters.SEED_BYTES);
        int offset = HAETAEParameters.SEED_BYTES;
        int polyqPackedBytes = params.getPolyqPackedBytes();
        for (int i = 0; i < params.getK(); i++)
        {
            packPolyQ(vk, offset + i * polyqPackedBytes, b[i]);
        }
    }

    /**
     * Packs a polynomial with coefficients modulo Q.
     */
    private void packPolyQ(byte[] r, int offset, int[] a)
    {
        if (params == HAETAEParameters.haetae5)
        {
            // Mode 5: simple 2 bytes per coefficient (16 bits)
            for (int i = 0; i < HAETAEParameters.N; i++)
            {
                int coeff = a[i];
                r[offset + 2 * i] = (byte)(coeff & 0xFF);
                r[offset + 2 * i + 1] = (byte)((coeff >> 8) & 0xFF);
            }
        }
        else
        {
            // Mode 2 & 3: compress 8 coefficients into 15 bytes
            for (int i = 0; i < (HAETAEParameters.N >> 3); i++)
            {
                int bIdx = offset + 15 * i;
                int dIdx = 8 * i;

                int c0 = a[dIdx];
                int c1 = a[dIdx + 1];
                int c2 = a[dIdx + 2];
                int c3 = a[dIdx + 3];
                int c4 = a[dIdx + 4];
                int c5 = a[dIdx + 5];
                int c6 = a[dIdx + 6];
                int c7 = a[dIdx + 7];

                r[bIdx] = (byte)(c0 & 0xFF);
                r[bIdx + 1] = (byte)(((c0 >> 8) & 0x7F) | ((c1 & 0x01) << 7));
                r[bIdx + 2] = (byte)((c1 >> 1) & 0xFF);
                r[bIdx + 3] = (byte)(((c1 >> 9) & 0x3F) | ((c2 & 0x03) << 6));
                r[bIdx + 4] = (byte)((c2 >> 2) & 0xFF);
                r[bIdx + 5] = (byte)(((c2 >> 10) & 0x1F) | ((c3 & 0x07) << 5));
                r[bIdx + 6] = (byte)((c3 >> 3) & 0xFF);
                r[bIdx + 7] = (byte)(((c3 >> 11) & 0x0F) | ((c4 & 0x0F) << 4));
                r[bIdx + 8] = (byte)((c4 >> 4) & 0xFF);
                r[bIdx + 9] = (byte)(((c4 >> 12) & 0x07) | ((c5 & 0x1F) << 3));
                r[bIdx + 10] = (byte)((c5 >> 5) & 0xFF);
                r[bIdx + 11] = (byte)(((c5 >> 13) & 0x03) | ((c6 & 0x3F) << 2));
                r[bIdx + 12] = (byte)((c6 >> 6) & 0xFF);
                r[bIdx + 13] = (byte)(((c6 >> 14) & 0x01) | ((c7 & 0x7F) << 1));
                r[bIdx + 14] = (byte)((c7 >> 7) & 0xFF);
            }
        }
    }

    /**
     * Packs a secret key: [vk | s0 | s1 | key].
     */
    public void packSk(byte[] sk, byte[] vk, int[][] s0, int[][] s1, byte[] key)
    {
        // Copy public key first
        System.arraycopy(vk, 0, sk, 0, params.getPublicKeyBytes());

        int offset = params.getPublicKeyBytes();

        // Pack s0 (M polynomials) with eta packing
        int polyEtaPackedBytes = HAETAEParameters.POLYETA_PACKED_BYTES;
        for (int i = 0; i < params.getM(); i++)
        {
            packPolyEta(sk, offset + i * polyEtaPackedBytes, s0[i]);
        }
        offset += params.getM() * polyEtaPackedBytes;

        // Pack s1 (K polynomials) with eta or 2*eta packing
        if (params == HAETAEParameters.haetae2 || params == HAETAEParameters.haetae3)
        {
            int poly2EtaPackedBytes = params.getPoly2etaPackedBytes();
            for (int i = 0; i < params.getK(); i++)
            {
                packPoly2Eta(sk, offset + i * poly2EtaPackedBytes, s1[i]);
            }
            offset += params.getK() * poly2EtaPackedBytes;
        }
        else
        { // haetae5
            for (int i = 0; i < params.getK(); i++)
            {
                packPolyEta(sk, offset + i * polyEtaPackedBytes, s1[i]);
            }
            offset += params.getK() * polyEtaPackedBytes;
        }

        // Copy the key seed
        System.arraycopy(key, 0, sk, offset, HAETAEParameters.SEED_BYTES);
    }

    /**
     * Packs a polynomial with coefficients in {-1,0,1}.
     * Each coefficient is mapped to 2 bits: (eta - coeff) -> {0,1,2}.
     */
    private void packPolyEta(byte[] r, int offset, int[] a)
    {
        for (int i = 0; i < HAETAEParameters.N / 4; i++)
        {
            int t0 = HAETAEParameters.ETA - a[4 * i];
            int t1 = HAETAEParameters.ETA - a[4 * i + 1];
            int t2 = HAETAEParameters.ETA - a[4 * i + 2];
            int t3 = HAETAEParameters.ETA - a[4 * i + 3];
            r[offset + i] = (byte)(t0 | (t1 << 2) | (t2 << 4) | (t3 << 6));
        }
    }

    /**
     * Packs a polynomial with coefficients in {-2,-1,0,1,2} (for mode 2 & 3).
     * Each coefficient is mapped to 3 bits: (2*eta - coeff) -> {0,1,2,3,4}.
     */
    private void packPoly2Eta(byte[] r, int offset, int[] a)
    {
        for (int i = 0; i < HAETAEParameters.N / 8; i++)
        {
            int t0 = 2 * HAETAEParameters.ETA - a[8 * i];
            int t1 = 2 * HAETAEParameters.ETA - a[8 * i + 1];
            int t2 = 2 * HAETAEParameters.ETA - a[8 * i + 2];
            int t3 = 2 * HAETAEParameters.ETA - a[8 * i + 3];
            int t4 = 2 * HAETAEParameters.ETA - a[8 * i + 4];
            int t5 = 2 * HAETAEParameters.ETA - a[8 * i + 5];
            int t6 = 2 * HAETAEParameters.ETA - a[8 * i + 6];
            int t7 = 2 * HAETAEParameters.ETA - a[8 * i + 7];

            int idx = offset + 3 * i;
            r[idx] = (byte)(t0 | (t1 << 3) | (t2 << 6));
            r[idx + 1] = (byte)((t2 >> 2) | (t3 << 1) | (t4 << 4) | (t5 << 7));
            r[idx + 2] = (byte)((t5 >> 1) | (t6 << 2) | (t7 << 5));
        }
    }

    /**
     * Internal key pair generation.
     *
     * @param vk   output public key byte array (length = CRYPTO_PUBLICKEYBYTES)
     * @param sk   output secret key byte array (length = CRYPTO_SECRETKEYBYTES)
     * @param seed input 32-byte seed (can be randomly generated)
     * @return 0 on success
     */
    public int cryptoSignKeypairInternal(byte[] vk, byte[] sk, byte[] seed)
    {
        // Buffers for derived seeds
        byte[] seedbuf = new byte[2 * HAETAEParameters.SEED_BYTES + HAETAEParameters.CRH_BYTES];
        short counter = 0;

        // Copy initial seed to seedbuf
        System.arraycopy(seed, 0, seedbuf, 0, HAETAEParameters.SEED_BYTES);

        // Sample seeds using SHAKE-256 (absorb once, then squeeze)
        SHAKEDigest shake256 = new SHAKEDigest(256);
        shake256.update(seedbuf, 0, HAETAEParameters.SEED_BYTES);
        // Finalize and squeeze
        shake256.doFinal(seedbuf, 0, seedbuf.length);
        // Actually, we need to call doOutput properly. Let's implement xof256_absorb_once.
        // For simplicity, we'll use a helper method.

        byte[] rhoprime = new byte[HAETAEParameters.SEED_BYTES];
        byte[] sigma = new byte[HAETAEParameters.CRH_BYTES];
        byte[] key = new byte[HAETAEParameters.SEED_BYTES];
        System.arraycopy(seedbuf, 0, rhoprime, 0, HAETAEParameters.SEED_BYTES);
        System.arraycopy(seedbuf, HAETAEParameters.SEED_BYTES, sigma, 0, HAETAEParameters.CRH_BYTES);
        System.arraycopy(seedbuf, HAETAEParameters.SEED_BYTES + HAETAEParameters.CRH_BYTES, key, 0, HAETAEParameters.SEED_BYTES);

        // Expand matrix A (K x M) from rhoprime
        int[][][] A = new int[params.getK()][params.getM()][HAETAEParameters.N];
        polymatkm_expand_matA(A, rhoprime);

        // Secret vectors
        int[][] s1 = new int[params.getM()][HAETAEParameters.N];
        int[][] s2 = new int[params.getK()][HAETAEParameters.N];
        int[][] b = new int[params.getK()][HAETAEParameters.N];

        if (params == HAETAEParameters.haetae2 || params == HAETAEParameters.haetae3)
        {
            // For modes 2 and 3, expand additional vector a
            int[][] a = new int[params.getK()][HAETAEParameters.N];
            polyveckExpandVecA(a, rhoprime);

            long squaredSingularValue;
            do
            {
                // Sample secret vectors s1 and s2
                polyvecmk_expand_S(s1, s2, sigma, counter);
                counter += (short)(params.getM() + params.getK());

                // s1hat = NTT(s1)
                int[][] s1hat = deepCopy(s1);
                polyvecmNtt(s1hat);

                // b = A * s1hat (pointwise in Montgomery domain)
                polymatkmPointwiseMontgomery(b, A, s1hat);

                // Inverse NTT + to Montgomery
                polyveckInvnttTomont(b);

                // b = b + s2
                polyveckAdd(b, b, s2);
                // b = b + a
                polyveckAdd(b, b, a);
                // Freeze (reduce mod Q)
                polyveckFreeze(b);

                // Decompose: b0 = low bits, b = high bits
                int[][] b0 = new int[params.getK()][HAETAEParameters.N];
                polyveckDecomposeVk(b0, b);

                // s2 = s2 - b0
                polyveckSub(s2, s2, b0);

                // Compute singular value and check
                squaredSingularValue = polyvecmkSkSingularValue(s1, s2);

                //System.out.println("counter: " + counter + " b[0][0]: " + b[0][0] + " " + squaredSingularValue);
            }
            while (squaredSingularValue > params.getGamma() * params.getGamma() * HAETAEParameters.N);

        }
        else
        { // haetae5
            long squaredSingularValue;
            do
            {
                polyvecmk_expand_S(s1, s2, sigma, counter);
                counter += params.getM() + params.getK();

                squaredSingularValue = polyvecmkSkSingularValue(s1, s2);
            }
            while (squaredSingularValue > params.getGamma() * params.getGamma() * HAETAEParameters.N);

            // b = A * NTT(s1) + NTT(s2)   (in Montgomery domain)
            // deep-copy: cloning the outer array would alias each row's int[]
            // with s1/s2, and the NTT below would corrupt the secret key.
            int[][] s1hat = deepCopy(s1);
            int[][] s2hat = deepCopy(s2);
            polyvecmNtt(s1hat);
            polyveckNtt(s2hat);

            polymatkmPointwiseMontgomery(b, A, s1hat);
            polyveckFromMontgomery(b);        // convert from Montgomery to normal
            polyveckAdd(b, b, s2hat);
            polyveckDoubleNegate(b);          // b = -2 * b
            polyveckCaddQ(b);                 // conditional add Q to make positive
        }

        // Pack keys
        packVk(vk, b, rhoprime);
        packSk(sk, vk, s1, s2, key);

        return 0;
    }

    /**
     * Deep copy of a 2D int array.
     */
    private int[][] deepCopy(int[][] src)
    {
        int[][] dst = new int[src.length][];
        for (int i = 0; i < src.length; i++)
        {
            dst[i] = (int[])src[i].clone();
        }
        return dst;
    }

    /**
     * Expands a polynomial vector v of length K from seed.
     * Nonce starts at (K << 8) + M.
     *
     * @param v    output vector (K x N)
     * @param seed 32‑byte seed
     */
    public void polyveckExpandVecA(int[][] v, byte[] seed)
    {
        short nonce = (short)((params.getK() << 8) + params.getM());
        for (int i = 0; i < params.getK(); i++)
        {
            poly_uniform(v[i], seed, (short)(nonce + i));
        }
    }

    /**
     * Converts a polynomial vector from Montgomery domain to normal representation.
     * Each coefficient is multiplied by MONTSQ and reduced.
     *
     * @param v vector in Montgomery domain (modified in place)
     */
    public void polyveckFromMontgomery(int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                v[i][j] = montgomeryReduce((long)v[i][j] * MONTSQ);
            }
        }
    }

    /**
     * Multiplies each coefficient by -2 * MONT and reduces.
     * This is used in Mode 5 to compute -2b in the NTT domain.
     *
     * @param v vector (modified in place)
     */
    public void polyveckDoubleNegate(int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                v[i][j] = montgomeryReduce((long)v[i][j] * MONT * -2);
            }
        }
    }

    /**
     * Conditionally adds Q to each coefficient to ensure it is in [0, Q-1].
     * Assumes input is in range (-Q, Q) or similar.
     *
     * @param v vector (modified in place)
     */
    public void polyveckCaddQ(int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                v[i][j] = caddq(v[i][j]);
            }
        }
    }

    /**
     * If a is negative, add Q; otherwise keep a.
     */
    private static int caddq(int a)
    {
        a += (a >> 31) & HAETAEParameters.Q;
        return a;
    }

    /**
     * Unpacks a polynomial with coefficients modulo Q.
     *
     * @param r      output polynomial (length N)
     * @param a      input byte array (packed format)
     * @param offset starting offset in a
     */
    public void unpackPolyQ(int[] r, byte[] a, int offset)
    {
        if (params == HAETAEParameters.haetae5)
        {
            // Mode 5: 2 bytes per coefficient
            for (int i = 0; i < HAETAEParameters.N; i++)
            {
                int lo = a[offset + 2 * i] & 0xFF;
                int hi = a[offset + 2 * i + 1] & 0xFF;
                r[i] = (lo | (hi << 8)) & 0xFFFF;
            }
        }
        else
        {
            // Modes 2 & 3: 8 coefficients in 15 bytes
            for (int i = 0; i < (HAETAEParameters.N >> 3); i++)
            {
                int bIdx = offset + 15 * i;
                int dIdx = 8 * i;

                r[dIdx] = (a[bIdx] & 0xFF) | ((a[bIdx + 1] & 0x7F) << 8);
                r[dIdx + 1] = ((a[bIdx + 1] >> 7) & 0x01) |
                    ((a[bIdx + 2] & 0xFF) << 1) |
                    ((a[bIdx + 3] & 0x3F) << 9);
                r[dIdx + 2] = ((a[bIdx + 3] >> 6) & 0x03) |
                    ((a[bIdx + 4] & 0xFF) << 2) |
                    ((a[bIdx + 5] & 0x1F) << 10);
                r[dIdx + 3] = ((a[bIdx + 5] >> 5) & 0x07) |
                    ((a[bIdx + 6] & 0xFF) << 3) |
                    ((a[bIdx + 7] & 0x0F) << 11);
                r[dIdx + 4] = ((a[bIdx + 7] >> 4) & 0x0F) |
                    ((a[bIdx + 8] & 0xFF) << 4) |
                    ((a[bIdx + 9] & 0x07) << 12);
                r[dIdx + 5] = ((a[bIdx + 9] >> 3) & 0x1F) |
                    ((a[bIdx + 10] & 0xFF) << 5) |
                    ((a[bIdx + 11] & 0x03) << 13);
                r[dIdx + 6] = ((a[bIdx + 11] >> 2) & 0x3F) |
                    ((a[bIdx + 12] & 0xFF) << 6) |
                    ((a[bIdx + 13] & 0x01) << 14);
                r[dIdx + 7] = ((a[bIdx + 13] >> 1) & 0x7F) |
                    ((a[bIdx + 14] & 0xFF) << 7);
            }
        }
    }

    /**
     * Expands matrix A of size K x L (where first column is b, others from seed).
     * This matrix is used in signing (A = [b | 2*A']).
     *
     * @param A  output matrix: K x L polynomials (2D array [K][L][N])
     * @param vk public key byte array
     */
    public void unpackVk(int[][][] A, byte[] vk)
    {
        // Extract seed and packed b from vk
        byte[] seed = new byte[HAETAEParameters.SEED_BYTES];
        System.arraycopy(vk, 0, seed, 0, HAETAEParameters.SEED_BYTES);

        int[][] b = new int[params.getK()][HAETAEParameters.N];
        int offset = HAETAEParameters.SEED_BYTES;
        int polyqPackedBytes = params.getPolyqPackedBytes();

        for (int i = 0; i < params.getK(); i++)
        {
            unpackPolyQ(b[i], vk, offset + i * polyqPackedBytes);
        }

        // Expand A' = PRG(seed) for columns 1..L-1
        polymatklExpandMatA(A, seed);
        polymatklDouble(A);   // multiply all but first column by 2

        // Adjust first column b based on mode
        if (params == HAETAEParameters.haetae2 || params == HAETAEParameters.haetae3)
        {
            // a = expand vector a (size K)
            int[][] a = new int[params.getK()][HAETAEParameters.N];
            polyveckExpandVecA(a, seed);
            // b = a - 2*b  (since b was doubled first)
            polyveckDouble(b);
            polyveckSub(b, a, b);
            polyveckDouble(b);
            polyveckNtt(b);
        }

        // Set first column of A to b
        for (int i = 0; i < params.getK(); i++)
        {
            A[i][0] = b[i];
        }
    }

    /**
     * Expands the matrix A' of size K x M (M = L-1) from seed.
     * Places result into columns 1..L-1 of A.
     *
     * @param A    matrix to fill (K x L)
     * @param seed 32-byte seed
     */
    private void polymatklExpandMatA(int[][][] A, byte[] seed)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < params.getM(); j++)
            {
                // nonce = (i << 8) + j
                short nonce = (short)((i << 8) + j);
                poly_uniform(A[i][j + 1], seed, nonce);
            }
        }
    }

    /**
     * Multiplies every polynomial in columns 1..L-1 by 2.
     */
    private void polymatklDouble(int[][][] A)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 1; j < params.getL(); j++)
            {
                int[] poly = A[i][j];
                for (int k = 0; k < HAETAEParameters.N; k++)
                {
                    poly[k] *= 2;
                }
            }
        }
    }

    /**
     * Multiplies every coefficient in the polynomial vector by 2.
     * No modular reduction is performed.
     *
     * @param v vector of K polynomials (modified in place)
     */
    public void polyveckDouble(int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                v[i][j] *= 2;
            }
        }
    }

    /**
     * Unpacks a polynomial with coefficients in {-1,0,1} (η = 1).
     * Each byte contains four 2‑bit values.
     *
     * @param r      output polynomial (length N)
     * @param a      input byte array (packed format)
     * @param offset starting offset in a
     */
    public void unpackPolyEta(int[] r, byte[] a, int offset)
    {
        for (int i = 0; i < HAETAEParameters.N / 4; i++)
        {
            int b = a[offset + i] & 0xFF;
            int t0 = (b) & 0x3;
            int t1 = (b >> 2) & 0x3;
            int t2 = (b >> 4) & 0x3;
            int t3 = (b >> 6) & 0x3;

            r[4 * i] = HAETAEParameters.ETA - t0;
            r[4 * i + 1] = HAETAEParameters.ETA - t1;
            r[4 * i + 2] = HAETAEParameters.ETA - t2;
            r[4 * i + 3] = HAETAEParameters.ETA - t3;
        }
    }

    /**
     * Unpacks a polynomial with coefficients in {-2,-1,0,1,2} (for modes 2 & 3).
     * 8 coefficients are stored in 3 bytes (24 bits = 8 * 3 bits).
     *
     * @param r      output polynomial (length N)
     * @param a      input byte array (packed format)
     * @param offset starting offset in a
     */
    public void unpackPoly2Eta(int[] r, byte[] a, int offset)
    {
        for (int i = 0; i < HAETAEParameters.N / 8; i++)
        {
            int idx = offset + 3 * i;
            int b0 = a[idx] & 0xFF;
            int b1 = a[idx + 1] & 0xFF;
            int b2 = a[idx + 2] & 0xFF;

            int t0 = (b0) & 0x7;
            int t1 = (b0 >> 3) & 0x7;
            int t2 = ((b0 >> 6) | (b1 << 2)) & 0x7;
            int t3 = (b1 >> 1) & 0x7;
            int t4 = (b1 >> 4) & 0x7;
            int t5 = ((b1 >> 7) | (b2 << 1)) & 0x7;
            int t6 = (b2 >> 2) & 0x7;
            int t7 = (b2 >> 5) & 0x7;

            r[8 * i] = 2 * HAETAEParameters.ETA - t0;
            r[8 * i + 1] = 2 * HAETAEParameters.ETA - t1;
            r[8 * i + 2] = 2 * HAETAEParameters.ETA - t2;
            r[8 * i + 3] = 2 * HAETAEParameters.ETA - t3;
            r[8 * i + 4] = 2 * HAETAEParameters.ETA - t4;
            r[8 * i + 5] = 2 * HAETAEParameters.ETA - t5;
            r[8 * i + 6] = 2 * HAETAEParameters.ETA - t6;
            r[8 * i + 7] = 2 * HAETAEParameters.ETA - t7;
        }
    }

    /**
     * Unpacks a full secret key into the expanded matrix A, secret vectors s0, s1, and the key seed.
     *
     * @param A   output expanded matrix of size K x L (from public part)
     * @param s0  output secret vector s0 (length M)
     * @param s1  output secret vector s1 (length K)
     * @param key output key seed (32 bytes)
     * @param sk  input secret key byte array
     */
    public void unpackSk(int[][][] A, int[][] s0, int[][] s1, byte[] key, byte[] sk)
    {
        // Unpack public key part (fills A)
        unpackVk(A, sk);

        int offset = params.getPublicKeyBytes();

        // Unpack s0 (M polynomials, eta‑packed)
        int polyEtaPackedBytes = HAETAEParameters.POLYETA_PACKED_BYTES;
        for (int i = 0; i < params.getM(); i++)
        {
            unpackPolyEta(s0[i], sk, offset + i * polyEtaPackedBytes);
        }
        offset += params.getM() * polyEtaPackedBytes;

        // Unpack s1 (K polynomials, 2*eta‑packed for modes 2/3, eta‑packed for mode 5)
        if (params == HAETAEParameters.haetae2 || params == HAETAEParameters.haetae3)
        {
            int poly2EtaPackedBytes = params.getPoly2etaPackedBytes();
            for (int i = 0; i < params.getK(); i++)
            {
                unpackPoly2Eta(s1[i], sk, offset + i * poly2EtaPackedBytes);
            }
            offset += params.getK() * poly2EtaPackedBytes;
        }
        else
        { // haetae5
            for (int i = 0; i < params.getK(); i++)
            {
                unpackPolyEta(s1[i], sk, offset + i * polyEtaPackedBytes);
            }
            offset += params.getK() * polyEtaPackedBytes;
        }

        // Copy the remaining 32‑byte key seed
        System.arraycopy(sk, offset, key, 0, HAETAEParameters.SEED_BYTES);
    }

    /**
     * Renormalizes a fp96_76 number: carries from low limb to high limb.
     */
    private static void renormalize(long[] x)
    {
        x[1] += (x[0] >>> 48);
        x[0] &= (1L << 48) - 1;
    }

    /**
     * 64‑bit multiplication returning 128‑bit result in r[0] (low) and r[1] (high).
     */
    private static void sq64(long[] r, long a)
    {
        long al = a & 0xFFFFFFFFL;           // low 32 bits
        long ah = a >>> 32;                  // high 32 bits (unsigned shift)

        // Low 64 bits of the product (a * a)
        r[0] = a * a;

        // Compute high 64 bits: 2 * ah * al + (al*al >> 32), then shift right by 32 and add ah*ah
        long alSqHigh = (al * al) >>> 32;    // (al*al) >> 32 (unsigned)
        long cross = ah * al * 2;            // 2 * ah * al (may overflow, but we handle as signed)
        long high = cross + alSqHigh;
        high = high >>> 32;                  // (cross + alSqHigh) >> 32 (unsigned)
        high += ah * ah;

        r[1] = high;
    }

    /**
     * Multiply two 64‑bit values, 128‑bit result.
     */
    private static void mul64(long[] r, long b, long a)
    {
        long al = a & 0xFFFFFFFFL;          // low 32 bits of a
        long ah = a >>> 32;                 // high 32 bits of a
        long bl = b & 0xFFFFFFFFL;          // low 32 bits of b
        long bh = b >>> 32;                 // high 32 bits of b

        // Low 64 bits of the product
        r[0] = a * b;

        // Compute high part: (ah*bl + al*bh + (al*bl)>>32) >> 32  +  ah*bh
        long albl = al * bl;
        long albl_high = albl >>> 32;               // (al * bl) >> 32
        long cross = ah * bl + al * bh + albl_high; // sum may overflow, but that's fine
        r[1] = (cross >>> 32) + (ah * bh);
    }

    /**
     * Multiply two 48‑bit values, produce 96‑bit result with 48‑bit limbs.
     */
    private static void mul48(long[] r, long b, long a)
    {
        mul64(r, b, a);
        r[1] <<= 16;
        r[1] ^= r[0] >>> 48;
        r[0] &= 0xFFFFFFFFFFFFL;
    }

    /**
     * Signed multiply high: (a * b + 2^47) >> 48, with rounding.
     */
    private static long smulh48(long a, long b)
    {
        // Use 128-bit multiplication emulation
        long a_high = a >> 24;
        long a_low = a - (a_high << 24);
        long b_high = b >> 24;
        long b_low = b - (b_high << 24);

        long res = (a_low * b_low) >> 24;
        res += a_low * b_high + a_high * b_low + (1L << 23); // rounding
        res >>= 24;
        return res + a_high * b_high;
    }

    /**
     * Approximate exp(x) for fixed‑point input x.
     */
    private static long approxExp(long x)
    {
        long result = 0xFFFFFFFFFFF5A74AL; // -0x0000B6C6340925AELL as signed
        result = ((smulh48(result, x) + (1L << 2)) >> 3) + 0x0000B4BD4DF85227L;
        result = ((smulh48(result, x) + (1L << 2)) >> 3) - 0x0000887F727491E2L;
        result = ((smulh48(result, x) + (1L << 1)) >> 2) + 0x0000AAAA643C7E8DL;
        result = ((smulh48(result, x) + (1L << 1)) >> 2) - 0x0000AAAAA98179E6L;
        result = ((smulh48(result, x) + 1L) >> 1) + 0x0000FFFFFFFB2E7AL;
        result = ((smulh48(result, x) + 1L) >> 1) - 0x0000FFFFFFFFF85FL;
        result = ((smulh48(result, x))) + 0x0000FFFFFFFFFFFCL;
        return result;
    }

    /**
     * Sample from a discrete Gaussian using CDT.
     */
    private static long sampleGauss16(long rand16)
    {
        long r = 0;
        for (int i = 0; i < CDTLEN; i++)
        {
            r += ((CDT[i] - rand16) >> 63) & 1L;
        }
        return r;
    }


    /**
     * Samples a Gaussian value and returns a rejection bit.
     *
     * @param r    output sampled value (modified via 1‑element array)
     * @param sqr  output squared value (fp96_76)
     * @param rand 17‑byte random array
     * @return 1 if accepted, 0 if rejected
     */
    public static long sampleGaussSigma76(long[] r, long[] sqr, byte[] rand, int pos)
    {
        // Extract random bits
        long rand_gauss16 = (rand[pos + 0] & 0xFFL) | ((rand[pos + 1] & 0xFFL) << 8);
        long rand_rej = (rand[pos + 2] & 0xFFL) | ((rand[pos + 3] & 0xFFL) << 8) |
            ((rand[pos + 4] & 0xFFL) << 16) | ((rand[pos + 5] & 0xFFL) << 24) |
            ((rand[pos + 6] & 0xFFL) << 32) | ((rand[pos + 7] & 0xFFL) << 40);

        long x = sampleGauss16(rand_gauss16);

        long[] y = new long[2];
        y[0] = (rand[pos + 8] & 0xFFL) | ((rand[pos + 9] & 0xFFL) << 8) |
            ((rand[pos + 10] & 0xFFL) << 16) | ((rand[pos + 11] & 0xFFL) << 24) |
            ((rand[pos + 12] & 0xFFL) << 32) | ((rand[pos + 13] & 0xFFL) << 40);
        y[1] = (rand[pos + 14] & 0xFFL) | ((rand[pos + 15] & 0xFFL) << 8) |
            ((rand[pos + 16] & 0xFFL) << 16) | (x << 24);

        // r := round y
        long sample = (y[0] >>> 15) ^ (y[1] << 33);
        sample += 1;
        sample >>>= 1;
        r[0] = sample;

        fixpointSquare(sqr, y);

        long exp_in = sqr[1] - ((x * x) << (68 - 48));
        exp_in <<= 20;
        exp_in |= sqr[0] >>> 28;
        exp_in += 1;
        exp_in >>>= 1;

        // Rejection logic
        long rand_rej_even = rand_rej ^ (rand_rej & 1L); // clear lowest bit
        long exp_val = approxExp(exp_in);
        long reject = ((rand_rej_even - exp_val) >> 63) & 1L;
        long clear = ((sample | -sample) >> 63) | rand_rej;
        return ((reject & clear) & 1L);
    }

    private static long sampleGauss(long[] r, int rOff, long[] sqsum, byte[] buf, int bufOffset,
                                    int bufLen, int len, int dontWriteLast)
    {
        int pos = bufOffset;
        int bytecnt = bufLen;
        long coefcnt = 0;

        while (coefcnt < len)
        {
            if (bytecnt < GAUSS_RAND_BYTES)
            {
                renormalize(sqsum);
                return coefcnt;
            }

            long[] sampleHolder = new long[1];
            long[] sqr = new long[2];
            long accepted;

            // For the last coefficient when dontWriteLast is set, use a dummy holder
            if (dontWriteLast != 0 && coefcnt == len - 1)
            {
                accepted = sampleGaussSigma76(sampleHolder, sqr, buf, pos);
            }
            else
            {
                accepted = sampleGaussSigma76(sampleHolder, sqr, buf, pos);
                r[rOff + (int)coefcnt] = sampleHolder[0];
            }

            coefcnt += accepted;
            pos += GAUSS_RAND_BYTES;
            bytecnt -= GAUSS_RAND_BYTES;

            sqsum[0] += sqr[0] & -accepted;
            sqsum[1] += sqr[1] & -accepted;
        }

        renormalize(sqsum);
        return len;
    }

    /**
     * Samples a full polynomial of Gaussian values (length N).
     *
     * @param r     output array of sampled values (length N)
     * @param signs output sign bytes (length N/8) – each bit indicates sign of corresponding coefficient
     * @param sqsum output accumulated squared sum (fp96_76)
     * @param seed  64‑byte seed (CRH_BYTES)
     * @param nonce 16‑bit nonce
     * @param len   number of coefficients to sample (usually N)
     */
    public static void sampleGaussN(long[] r, int rOff, byte[] signs, int signsOff, long[] sqsum,
                                    byte[] seed, short nonce, int len)
    {
        // Initialize SHAKE‑256 stream
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(seed, 0, HAETAEParameters.CRH_BYTES);
        shake.update((byte)(nonce & 0xFF));
        shake.update((byte)((nonce >> 8) & 0xFF));

        byte[] buf = new byte[POLY_HYPERBALL_NBLOCKS * SHAKE256_RATE];
        shake.doOutput(buf, 0, buf.length);

        // Copy sign bytes (first len/8 bytes)
        int signBytesLen = len / 8;
        System.arraycopy(buf, 0, signs, signsOff, signBytesLen);

        int bytecnt = buf.length - signBytesLen;
        long coefcnt = sampleGauss(r, rOff, sqsum, buf, signBytesLen, bytecnt, len, len % HAETAEParameters.N);

        int firstflag = 1;
        while (coefcnt < len)
        {
            int off = bytecnt % GAUSS_RAND_BYTES;
            // Move leftover bytes to beginning
            for (int i = 0; i < off; i++)
            {
                buf[i] = buf[bytecnt + signBytesLen * firstflag - off + i];
            }
            // Squeeze one more block
            shake.doOutput(buf, off, SHAKE256_RATE);
            bytecnt = SHAKE256_RATE + off;

            long added = sampleGauss(r, rOff + (int)coefcnt, sqsum, buf, 0, bytecnt, (int)(len - coefcnt), len % HAETAEParameters.N);
            coefcnt += added;
            firstflag = 0;
        }
    }

    /**
     * Multiply‑accumulate: r += a * b (with 48‑bit limbs).
     */
    static void mulacc48(long[] r, long a, long b)
    {
        long[] tmp = new long[2];
        mul48(tmp, a, b);
        r[0] += tmp[0];
        r[1] += tmp[1];
    }

    /**
     * Square a 48‑bit value, produce 96‑bit result with 48‑bit limbs.
     */
    static void sq48(long[] r, long a)
    {
        sq64(r, a);
        r[1] <<= 16;
        r[1] ^= r[0] >>> 48;
        r[0] &= MASK48;
    }

    /**
     * Fixed‑point square: sqx = x * x.
     */
    public static void fixpointSquare(long[] sqx, long[] x)
    {
        long[] tmp = new long[2];
        sq48(sqx, x[0]);

        // shift right by 48, rounding (implicit)
        sqx[0] >>>= 48;
        sqx[0] += sqx[1];

        mul48(tmp, x[0], x[1]);
        sqx[0] += tmp[0] << 1;
        sqx[1] = tmp[1] << 1;

        // shift right by 28, rounding
        sqx[0] >>>= 28;
        sqx[0] += (sqx[1] << 20) & MASK48;
        sqx[1] >>>= 28;

        sq64(tmp, x[1]);
        sqx[0] += (tmp[0] << 20) & MASK48;
        sqx[1] += (tmp[0] >>> 28) + (tmp[1] << 36);

        renormalize(sqx);
    }

    /**
     * Fixed‑point multiplication: xy = x * y.
     */
    public static void fixpointMul(long[] xy, long[] x, long[] y)
    {
        long[] tmp = new long[2];
        mul48(xy, x[0], y[0]);

        // shift right by 48, rounding
        xy[0] = xy[1] + (((xy[0] >>> 47) + 1) >>> 1);

        mul48(tmp, x[0], y[1]);
        xy[0] += tmp[0];
        xy[1] = tmp[1];
        mulacc48(xy, x[1], y[0]);

        // shift right by 28, rounding
        xy[0] += 1L << 27;
        xy[0] >>>= 28;
        xy[0] += (xy[1] << 20) & MASK48;
        xy[1] >>>= 28;

        mul64(tmp, x[1], y[1]);
        xy[0] += (tmp[0] << 20) & MASK48;
        xy[1] += (tmp[0] >>> 28) + (tmp[1] << 36);

        renormalize(xy);
    }

    /**
     * Fixed‑point addition: xy = x + y.
     */
    public static void fixpointAdd(long[] xy, long[] x, long[] y)
    {
        xy[0] = x[0] + y[0];
        xy[1] = x[1] + y[1];
    }

    /**
     * Fixed‑point subtraction: xminy = x - y.
     */
    public static void fixpointSub(long[] xminy, long[] x, long[] y)
    {
        long[] yneg = new long[2];
        copyCneg(yneg, y, 1);
        fixpointAdd(xminy, x, yneg);
    }

    /**
     * Copy with conditional negation: y = (sign ? -x : x).
     */
    private static void copyCneg(long[] y, long[] x, int sign)
    {
        long mask = -(long)sign;
        y[0] = (mask & MASK48) ^ x[0];
        y[1] = mask ^ x[1];
        y[0] += sign;
        renormalize(y);
    }

    /**
     * In‑place conditional negation: x = (sign ? -x : x).
     */
    private static void cneg(long[] x, int sign)
    {
        long mask = -(long)sign;
        x[0] ^= mask & MASK48;
        x[1] ^= mask;
        x[0] += sign;
        renormalize(x);
    }

    /**
     * In‑place: x = 3/2 - x.
     */
    private static void fixpointSubFromThreeHalves(long[] x)
    {
        cneg(x, 1);
        x[1] += 3L << 27; // 3/2 in fp96_76 (left shift by 28 would be "3")
        renormalize(x);
    }

    /**
     * Multiply xy (signed) by y (unsigned) with conditional sign of y.
     * xy = xy * y   where y may be negative (interpreted as signed).
     */
    private static void fixpointUnsignedSignedMul(long[] xy, long[] y)
    {
        long[] x = new long[2];
        long[] z = new long[2];
        int sign = (int)(y[1] >> 63) & 1;
        copyCneg(x, y, sign);
        fixpointMul(z, x, xy);
        copyCneg(xy, z, sign);
    }

    /**
     * Newton's method to compute 1/sqrt(xhalf).
     *
     * @param invsqrtx output: 1/sqrt(xhalf)
     * @param xhalf    input: x/2 (positive)
     */
    public void fixpointNewtonInvSqrt(long[] invsqrtx, long[] xhalf)
    {
        long[] tmp = new long[2];
        long[] tmp2 = new long[2];

        // First iteration: start_times_threehalves - start_cube * xhalf
        fixpointMul(tmp, xhalf, params.getStartCube());
        fixpointSub(invsqrtx, params.getStartTimesThreehalves(), tmp);

        for (int i = 0; i < 6; i++)
        {
            fixpointSquare(tmp, invsqrtx);          // tmp = y^2
            fixpointMul(tmp2, xhalf, tmp);          // tmp2 = x/2 * y^2
            fixpointSubFromThreeHalves(tmp2);       // tmp2 = 3/2 - x/2 * y^2
            fixpointUnsignedSignedMul(invsqrtx, tmp2); // y = y * (3/2 - x/2 * y^2)
        }
    }

    /**
     * Rounds a fixed‑point number: (num + LN/2) >> LN_BITS.
     */
    private int fixRound(int num)
    {
        return (num + params.getLnHalf()) >> params.getLnBits();
    }

    /**
     * Converts a polynomial in fixed‑point representation to a standard polynomial.
     *
     * @param a output polynomial (length N)
     * @param b input fixed‑point polynomial (length N)
     */
    public void polyfixRound(int[] a, int[] b)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            a[i] = fixRound(b[i]);
        }
    }

    /**
     * Converts a vector of length L from fixed‑point to standard representation.
     *
     * @param a output vector (L x N)
     * @param b input fixed‑point vector (L x N)
     */
    public void polyfixveclRound(int[][] a, int[][] b)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            polyfixRound(a[i], b[i]);
        }
    }

    /**
     * Converts a vector of length K from fixed‑point to standard representation.
     *
     * @param a output vector (K x N)
     * @param b input fixed‑point vector (K x N)
     */
    public void polyfixveckRound(int[][] a, int[][] b)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyfixRound(a[i], b[i]);
        }
    }

    /**
     * Applies forward NTT to a polynomial vector of length L.
     *
     * @param x vector of L polynomials (L x N)
     */
    public void polyveclNtt(int[][] x)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            polyNtt(x[i]);
        }
    }

    /**
     * Pointwise multiplication and accumulation for two vectors of length L.
     * w = sum_{j=0}^{L-1} (u_j ∘ v_j)   (pointwise multiplication)
     *
     * @param w output polynomial (length N)
     * @param u first vector (L x N)
     * @param v second vector (L x N)
     */
    private void polyveclPointwiseAccMontgomery(int[] w, int[][] u, int[][] v)
    {
        polyPointwiseMontgomery(w, u[0], v[0]);

        for (int j = 1; j < params.getL(); j++)
        {
            polyAccPointwiseMontgomery(w, u[j], v[j]);
        }
    }

    /**
     * Matrix‑vector multiplication: t = mat * v  where mat is K x L, v is length L.
     *
     * @param t   output vector of length K (each polynomial of length N)
     * @param mat matrix of size K x L (each entry is a polynomial)
     * @param v   input vector of length L
     */
    public void polymatklPointwiseMontgomery(int[][] t, int[][][] mat, int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyveclPointwiseAccMontgomery(t[i], mat[i], v);
        }
    }

    /**
     * Standard representative modulo 2Q: returns a value in [0, 2Q-1].
     */
    public int freeze2q(int a)
    {
        long t = ((long)a * DQREC) >> 32;
        long r = a - t * HAETAEParameters.DQ;          // -4Q < r < 4Q
        r += (r >> 31) & (HAETAEParameters.DQ * 2);    // 0 <= r < 4Q
        r -= ~((r - HAETAEParameters.DQ) >> 31) & HAETAEParameters.DQ; // 0 <= r < 2Q
        return (int)r;
    }

    /**
     * Applies freeze2q to a polynomial.
     */
    public void polyFreeze2q(int[] a)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            a[i] = freeze2q(a[i]);
        }
    }

    /**
     * Applies freeze2q to a vector of length K.
     */
    public void polyveckFreeze2q(int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyFreeze2q(v[i]);
        }
    }

    // ---------- CRT Reconstruction ----------

    /**
     * Reconstructs a coefficient from modulo Q and modulo 2 representations.
     * w = u + Q if (u XOR v) is odd; else w = u.
     */
    private void polyFromcrt(int[] w, int[] u, int[] v)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            int xq = u[i];
            int x2 = v[i];
            w[i] = xq + (HAETAEParameters.Q & -(((xq ^ x2) & 1)));
        }
    }

    /**
     * Reconstructs from modulo Q only (assuming the modulo 2 part is zero).
     * w = u + Q if u is odd; else w = u.
     */
    private void polyFromcrt0(int[] w, int[] u)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            int xq = u[i];
            w[i] = xq + (HAETAEParameters.Q & -(xq & 1));
        }
    }

    /**
     * Vector version: first polynomial uses polyFromcrt with v,
     * the remaining use polyFromcrt0.
     */
    public void polyveckPolyFromcrt(int[][] w, int[][] u, int[] v)
    {
        polyFromcrt(w[0], u[0], v);
        for (int i = 1; i < params.getK(); i++)
        {
            polyFromcrt0(w[i], u[i]);
        }
    }

    // ---------- Hint Decomposition ----------

    /**
     * Decomposes a coefficient r into its high bits (hint).
     * highbits = (r + half_alpha) >> log_alpha, capped at max value.
     */
    private int decomposeHint(int r)
    {
        int hb = (r + params.getHalfAlphaHint()) >> params.getLogAlphaHint();
        int maxHint = (HAETAEParameters.DQ - 2) / params.getAlphaHint();
        int edgecase = (maxHint - (hb + 1)) >> 31;
        hb -= maxHint & edgecase;
        return hb;
    }

    /**
     * Computes hint high bits for a whole vector of length K.
     */
    public void polyveckHighbitsHint(int[][] w, int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            int[] wi = w[i];
            int[] vi = v[i];
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                wi[j] = decomposeHint(vi[j]);
            }
        }
    }

    // ---------- LSB Extraction ----------

    /**
     * Extracts the least significant bit of each coefficient.
     */
    public void polyLsb(int[] a0, int[] a)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            a0[i] = a[i] & 1;
        }
    }

    // ---------- Packing High Bits ----------

    /**
     * Packs the high bits of a polynomial vector into bytes.
     * Assumes high bits are in [0, 2^9-1] (for modes 2/3) or [0, 2^8-1] (for mode 5).
     */
    public void packVecHighbits(byte[] buf, int offset, int[][] v)
    {
        int packedBytesPerPoly = HAETAEParameters.POLY_HIGHBITS_PACKED_BYTES;
        for (int i = 0; i < params.getK(); i++)
        {
            packPolyHighbits(buf, offset + i * packedBytesPerPoly, v[i]);
        }
    }

    /**
     * Packs the high bits of a single polynomial.
     * Each coefficient is 9 bits (modes 2/3) or 8 bits (mode 5), packed tightly.
     */
    private void packPolyHighbits(byte[] buf, int offset, int[] a)
    {
        if (params != HAETAEParameters.haetae5)
        {
            // Mode 5: 8 bits per coefficient -> simple
            for (int i = 0; i < HAETAEParameters.N; i++)
            {
                buf[offset + i] = (byte)(a[i] & 0xFF);
            }
        }
        else
        {
            // Modes 2 & 3: 9 bits per coefficient, 8 coefficients -> 9 bytes
            for (int i = 0; i < HAETAEParameters.N / 8; i++)
            {
                int base = i * 8;
                int b0 = a[base];
                int b1 = a[base + 1];
                int b2 = a[base + 2];
                int b3 = a[base + 3];
                int b4 = a[base + 4];
                int b5 = a[base + 5];
                int b6 = a[base + 6];
                int b7 = a[base + 7];

                int outOffset = offset + 9 * i;
                buf[outOffset] = (byte)(b0 & 0xFF);
                buf[outOffset + 1] = (byte)(((b0 >> 8) & 0x01) | ((b1 & 0x7F) << 1));
                buf[outOffset + 2] = (byte)(((b1 >> 7) & 0x03) | ((b2 & 0x3F) << 2));
                buf[outOffset + 3] = (byte)(((b2 >> 6) & 0x07) | ((b3 & 0x1F) << 3));
                buf[outOffset + 4] = (byte)(((b3 >> 5) & 0x0F) | ((b4 & 0x0F) << 4));
                buf[outOffset + 5] = (byte)(((b4 >> 4) & 0x1F) | ((b5 & 0x07) << 5));
                buf[outOffset + 6] = (byte)(((b5 >> 3) & 0x3F) | ((b6 & 0x03) << 6));
                buf[outOffset + 7] = (byte)(((b6 >> 2) & 0x7F) | ((b7 & 0x01) << 7));
                buf[outOffset + 8] = (byte)((b7 >> 1) & 0xFF);
            }
        }
    }

    // ---------- Packing LSBs ----------

    /**
     * Packs the LSB of each coefficient into bytes (1 bit per coefficient).
     */
    public void packPolyLsb(byte[] buf, int offset, int[] a)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            if ((i % 8) == 0)
            {
                buf[offset + i / 8] = 0;
            }
            buf[offset + i / 8] |= (a[i] & 1) << (i % 8);
        }
    }

    /**
     * Complex number with 32‑bit fixed‑point real and imaginary parts
     * (16 fractional bits).
     */
    public static class ComplexFp32_16
    {
        public int real;
        public int imag;

        public ComplexFp32_16()
        {
            this.real = 0;
            this.imag = 0;
        }

        public ComplexFp32_16(int real, int imag)
        {
            this.real = real;
            this.imag = imag;
        }
    }

    // ---------- Challenge Generation ----------

    /**
     * Generates the challenge polynomial c from the high bits and LSB of w1, and message mu.
     *
     * @param c           output challenge polynomial (length N)
     * @param highbitsLsb packed high bits and LSB (length = POLYVECK_HIGHBITS_PACKEDBYTES + POLYC_PACKEDBYTES)
     * @param mu          message hash (SEED_BYTES)
     */
    public void polyChallenge(int[] c, byte[] highbitsLsb, byte[] mu)
    {
        if (params == HAETAEParameters.haetae2 || params == HAETAEParameters.haetae3)
        {
            // Modes 2 & 3: generate a sparse polynomial with exactly TAU ones
            SHAKEDigest shake = new SHAKEDigest(256);
            shake.update(highbitsLsb, 0, highbitsLsb.length);
            shake.update(mu, 0, HAETAEParameters.SEED_BYTES);

            byte[] buf = new byte[SHAKE256_RATE];
            shake.doOutput(buf, 0, SHAKE256_RATE);
            int pos = 0;

            // Initialize c to zeros
            for (int i = 0; i < HAETAEParameters.N; i++)
            {
                c[i] = 0;
            }

            for (int i = HAETAEParameters.N - params.getTau(); i < HAETAEParameters.N; i++)
            {
                int b;
                do
                {
                    if (pos >= SHAKE256_RATE)
                    {
                        shake.doOutput(buf, 0, SHAKE256_RATE);
                        pos = 0;
                    }
                    b = buf[pos++] & 0xFF;
                }
                while (b > i);
                c[i] = c[b];
                c[b] = 1;
            }
        }
        else
        { // haetae5
            // Mode 5: generate a 256-bit string with exactly TAU ones (TAU = 128)
            SHAKEDigest shake = new SHAKEDigest(256);
            shake.update(highbitsLsb, 0, highbitsLsb.length);
            shake.update(mu, 0, HAETAEParameters.SEED_BYTES);

            byte[] buf = new byte[32];
            shake.doFinal(buf, 0, 32);

            int hwt = 0;
            for (int i = 0; i < 32; i++)
            {
                hwt += hammingWeight8(buf[i]);
            }

            int cond = 128 - hwt;
            int mask = 0xFF & (cond >> 8); // 0xFF if cond < 0, else 0
            int w0 = -(buf[0] & 1);        // -1 if LSB set, else 0
            // Branchless select: mask = (cond != 0) ? mask : w0
            // condNonZero is -1 if cond != 0 (any bit set), else 0.
            int condNonZero = -((cond | -cond) >>> 31);
            mask = w0 ^ (condNonZero & (mask ^ w0));

            for (int i = 0; i < 32; i++)
            {
                int b = (buf[i] ^ mask) & 0xFF;
                buf[i] = (byte)b;
                c[8 * i] = (b) & 1;
                c[8 * i + 1] = (b >> 1) & 1;
                c[8 * i + 2] = (b >> 2) & 1;
                c[8 * i + 3] = (b >> 3) & 1;
                c[8 * i + 4] = (b >> 4) & 1;
                c[8 * i + 5] = (b >> 5) & 1;
                c[8 * i + 6] = (b >> 6) & 1;
                c[8 * i + 7] = (b >> 7) & 1;
            }
        }
    }

    /**
     * Hamming weight (population count) of an 8‑bit integer.
     */
    private static int hammingWeight8(int x)
    {
        x = (x & 0x55) + ((x >> 1) & 0x55);
        x = (x & 0x33) + ((x >> 2) & 0x33);
        x = (x & 0x0F) + ((x >> 4) & 0x0F);
        return x;
    }

    // ---------- Vector Pointwise Multiplication with a Single Polynomial ----------

    /**
     * Pointwise multiplication of each polynomial in vector u (length K) by polynomial v.
     * Result stored in w.
     */
    public void polyveckPolyPointwiseMontgomery(int[][] w, int[][] u, int[] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyPointwiseMontgomery(w[i], u[i], v);
        }
    }

    /**
     * Conditionally negates a vector of length L.
     * If b == 0, coefficients unchanged; if b == 1, coefficients are negated.
     *
     * @param v vector to modify (L x N)
     * @param b condition byte (0 or 1)
     */
    public void polyveclCneg(int[][] v, int b)
    {
        int factor = 1 - 2 * b; // 1 if b==0, -1 if b==1
        for (int i = 0; i < params.getL(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                v[i][j] *= factor;
            }
        }
    }

    /**
     * Conditionally negates a vector of length K.
     */
    public void polyveckCneg(int[][] v, int b)
    {
        int factor = 1 - 2 * b;
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                v[i][j] *= factor;
            }
        }
    }

    /**
     * Adds a regular polynomial (scaled by LN) to a fixed‑point polynomial.
     * c[i] = a[i] + LN * b[i]
     *
     * @param c output fixed‑point polynomial
     * @param a input fixed‑point polynomial
     * @param b input regular polynomial
     */
    private void polyfixAdd(int[] c, int[] a, int[] b)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            c[i] = a[i] + params.getLn() * b[i];
        }
    }

    /**
     * Vector version for length L.
     */
    public void polyfixveclAdd(int[][] w, int[][] u, int[][] v)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            polyfixAdd(w[i], u[i], v[i]);
        }
    }

    /**
     * Vector version for length K.
     */
    public void polyfixveckAdd(int[][] w, int[][] u, int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyfixAdd(w[i], u[i], v[i]);
        }
    }

    public long polyfixveclkSqnorm2(int[][] a, int[][] b)
    {
        long ret = 0;
        for (int i = 0; i < params.getL(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                long coeff = a[i][j];
                ret += coeff * coeff;
            }
        }
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                long coeff = b[i][j];
                ret += coeff * coeff;
            }
        }
        return ret;
    }

    /**
     * Doubles each element of a fixed‑point vector of length L.
     * b = 2 * a
     */
    public void polyfixveclDouble(int[][] b, int[][] a)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                b[i][j] = 2 * a[i][j];
            }
        }
    }

    /**
     * Doubles each element of a fixed‑point vector of length K.
     */
    public void polyfixveckDouble(int[][] b, int[][] a)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                b[i][j] = 2 * a[i][j];
            }
        }
    }

    /**
     * Subtracts two fixed‑point polynomials: c = a - b.
     */
    private void polyfixfixSub(int[] c, int[] a, int[] b)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            c[i] = a[i] - b[i];
        }
    }

    /**
     * Subtracts two fixed‑point vectors of length L: w = u - v.
     */
    public void polyfixfixveclSub(int[][] w, int[][] u, int[][] v)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            polyfixfixSub(w[i], u[i], v[i]);
        }
    }

    /**
     * Subtracts two fixed‑point vectors of length K: w = u - v.
     */
    public void polyfixfixveckSub(int[][] w, int[][] u, int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyfixfixSub(w[i], u[i], v[i]);
        }
    }

    /**
     * Conditionally adds the maximum hint value to negative coefficients.
     * This ensures that high‑bits are non‑negative.
     * h.coeffs += (h.coeffs < 0) ? ((DQ-2)/ALPHA_HINT) : 0
     */
    public void polyveckCaddDQ2ALPHA(int[][] h)
    {
        int maxHint = (HAETAEParameters.DQ - 2) / params.getAlphaHint();
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                int coeff = h[i][j];
                // (coeff >> 31) is -1 if negative, 0 otherwise
                h[i][j] = coeff + ((coeff >> 31) & maxHint);
            }
        }
    }

    // ---------- Decomposition for z1 ----------
    // z1 decompose uses alpha=256: lowbits = r mod 256 centred to [-128, 127];
    // highbits = round(r/256). Inlined into polyLowbits / polyHighbits.

    /**
     * Extracts the low bits of a polynomial (z1 part).
     */
    public void polyLowbits(int[] a1, int[] a)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            int lb = a[i] & 0xFF;
            int center = (128 - (lb + 1)) >> 31;
            a1[i] = lb - (256 & center);
        }
    }

    /**
     * Extracts the low bits of a vector of length L.
     */
    public void polyveclLowbits(int[][] v1, int[][] v)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            polyLowbits(v1[i], v[i]);
        }
    }

    /**
     * Extracts the high bits of a polynomial (z1 part).
     */
    public void polyHighbits(int[] a2, int[] a)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            a2[i] = (a[i] + 128) >> 8;
        }
    }

    /**
     * Extracts the high bits of a vector of length L.
     */
    public void polyveclHighbits(int[][] v2, int[][] v)
    {
        for (int i = 0; i < params.getL(); i++)
        {
            polyHighbits(v2[i], v[i]);
        }
    }

    // ---------- Signature Packing ----------

    /**
     * Packs the signature into the output byte array.
     *
     * @param sig        output signature (length CRYPTO_BYTES)
     * @param c          challenge polynomial (coefficients in {0,1})
     * @param lowbitsZ1  low bits of z1 (L x N)
     * @param highbitsZ1 high bits of z1 (L x N)
     * @param h          hint vector (K x N)
     * @return 0 on success, 1 if encoding fails
     */
    public int packSig(byte[] sig, int[] c, int[][] lowbitsZ1, int[][] highbitsZ1, int[][] h)
    {
        int offset = 0;


        // 1. Pack challenge c (N bits -> N/8 bytes). Branchless: c[i] in {-1, 0, +1},
        // so ((c[i] | -c[i]) >>> 31) is 1 iff c[i] != 0, else 0.
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            int ci = c[i];
            int nonzero = (ci | -ci) >>> 31;
            sig[offset + i / 8] |= (byte)(nonzero << (i % 8));
        }
        offset += HAETAEParameters.N / 8;

        // 2. Pack lowbits of z1 (L * N bytes) – each coefficient is exactly one byte (since lowbits in [-128,127] fits in signed byte)
        for (int i = 0; i < params.getL(); i++)
        {
            polyDecomposedPack(sig, offset + HAETAEParameters.N * i, lowbitsZ1[i]);
        }
        offset += params.getL() * HAETAEParameters.N;

        // 3. Encode highbits_z1 and h using custom compression
        byte[] encodedHbZ1 = new byte[HAETAEParameters.N * params.getL()]; // max possible size
        byte[] encodedH = new byte[HAETAEParameters.N * params.getK()];

        int sizeEncHbZ1 = encodeHbZ1(encodedHbZ1, highbitsZ1);
        int sizeEncH = encodeH(encodedH, h);

        if (sizeEncH == 0 || sizeEncHbZ1 == 0)
        {
            return 1; // encoding failed
        }

        // Check that size offsets are within one byte
        if (sizeEncH < params.getBaseEncH() ||
            sizeEncHbZ1 < params.getBaseEncHbZ1() ||
            sizeEncH > params.getBaseEncH() + 255 ||
            sizeEncHbZ1 > params.getBaseEncHbZ1() + 255)
        {
            return 1;
        }

        int offsetEncHbZ1 = sizeEncHbZ1 - params.getBaseEncHbZ1();
        int offsetEncH = sizeEncH - params.getBaseEncH();

        // Check total size
        if (HAETAEParameters.SEED_BYTES + params.getL() * HAETAEParameters.N + 2 + sizeEncHbZ1 + sizeEncH >
            params.getCryptoBytes())
        {
            return 1;
        }

        sig[offset] = (byte)offsetEncHbZ1;
        sig[offset + 1] = (byte)offsetEncH;
        offset += 2;

        System.arraycopy(encodedHbZ1, 0, sig, offset, sizeEncHbZ1);
        offset += sizeEncHbZ1;

        System.arraycopy(encodedH, 0, sig, offset, sizeEncH);

        return 0;
    }

    /**
     * Packs a polynomial of decomposed low bits (each coefficient fits in a byte).
     * Assumes coefficients are already in the range [-128, 127] and just casts to byte.
     */
    private void polyDecomposedPack(byte[] out, int outOff, int[] a)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            out[outOff + i] = (byte)a[i];
        }
    }

    /**
     * Initializes the rANS state.
     */
    private static int ransEncInit()
    {
        return RANS_BYTE_L;
    }

    /**
     * Encodes a single symbol.
     *
     * @param r   current rANS state (modified in place via array)
     * @param ptr pointer to current output position (wrapped in an array of byte[])
     * @param sym symbol descriptor
     */
    private static int ransEncPutSymbol(int[] r, byte[] ptr, int ptrOff, RansEncSymbol sym)
    {
        int x = r[0];
        int x_max = sym.x_max;
        if (x >= x_max)
        {
            do
            {
                ptr[--ptrOff] = (byte)(x & 0xFF);
                x >>>= 8;
            }
            while (x >= x_max);
        }

        // x = C(s,x)
        long product = ((x & 0xFFFFFFFFL) * (sym.rcp_freq & 0xFFFFFFFFL)) >>> 32;
        int q = (int)(product >>> sym.rcp_shift);
        r[0] = x + sym.bias + q * sym.cmpl_freq;
        return ptrOff;
    }

    /**
     * Flushes the remaining rANS state to output (4 bytes, little‑endian).
     */
    private static int ransEncFlush(int[] state, byte[] ptr, int ptrOff)
    {
        int x = state[0];
        ptrOff -= 4;
        ptr[ptrOff] = (byte)(x);
        ptr[ptrOff + 1] = (byte)(x >>> 8);
        ptr[ptrOff + 2] = (byte)(x >>> 16);
        ptr[ptrOff + 3] = (byte)(x >>> 24);
        return ptrOff;
    }

    /**
     * Instance version using HAETAEParameters.
     * <p>
     * <b>Constant-time note (matches reference C, not regressed):</b> the rANS
     * encoder is inherently variable-time — {@code ransEncPutSymbol}'s
     * normalisation do-while loop iterates a data-dependent number of times,
     * and the symbol-table lookup {@code params.getEsyms_h()[s]} indexes by a
     * secret-derived hint coefficient (L3 leak via cache-line side channel).
     * The early-return at the out-of-range check is a validity check that
     * triggers a rejection-sampling retry; it leaks "this attempt failed",
     * which is also leaked by the surrounding loop iteration count. The hint
     * coefficients themselves are fully recoverable from a released signature,
     * so the cache-timing leak is information-equivalent to the signature.
     * Making this routine fully L3 would require constant-time table read
     * (mask-and-fold over all 256 entries) and an unconditional full traversal
     * — both substantial perf costs not in the reference C either.
     */
    public int encodeH(byte[] buf, int[][] h)
    {
        int sizeH = HAETAEParameters.N * params.getK();
        byte[] encoding = new byte[sizeH]; // upper bound
        int[] state = new int[1];
        int ptr = encoding.length;

        state[0] = ransEncInit();

        for (int i = sizeH; i > 0; i--)
        {
            int idx = i - 1;
            int polyIdx = idx / HAETAEParameters.N;
            int coeffIdx = idx % HAETAEParameters.N;
            int tmp = h[polyIdx][coeffIdx];

            // Check for out‑of‑range values
            if (H_CUT < tmp && tmp <= H_CUT + params.getOffset_h())
            {
                return 0;
            }
            // Map to dense symbol index (branchless: subtract offset iff tmp > H_CUT+offset_h)
            // diff = (H_CUT + offset_h) - tmp;  sign bit set (-1) iff tmp > H_CUT+offset_h.
            int diff = (H_CUT + params.getOffset_h()) - tmp;
            int over = diff >> 31;
            tmp -= over & params.getOffset_h();
            int s = tmp; // s is in 0..255 for valid inputs

            ptr = ransEncPutSymbol(state, encoding, ptr, params.getEsyms_h()[s]);
            if (ptr < 4)
            {
                return 0; // safety
            }
        }

        ptr = ransEncFlush(state, encoding, ptr);
        int sizeEncoded = encoding.length - ptr;
        System.arraycopy(encoding, ptr, buf, 0, sizeEncoded);
        return sizeEncoded;
    }

    /**
     * Encodes the high‑bits of z1 (size L×N).
     * <p>
     * <b>Constant-time note:</b> same caveats as {@link #encodeH} — the rANS
     * encoder and {@code getEsyms_hb_z1()[s]} table lookup are inherently
     * variable-time / L3-leaking, matching the reference C implementation. The
     * encoded hbZ1 coefficients are fully recoverable from a released
     * signature, so the cache-timing leak is information-equivalent to the
     * eventual signature output.
     */
    public int encodeHbZ1(byte[] buf, int[][] hbZ1)
    {
        int sizeHbZ1 = HAETAEParameters.N * params.getL();
        byte[] encoding = new byte[sizeHbZ1];
        int[] state = new int[1];
        int ptr = encoding.length;

        state[0] = ransEncInit();


        for (int i = sizeHbZ1; i > 0; i--)
        {
            int idx = i - 1;
            int polyIdx = idx / HAETAEParameters.N;
            int coeffIdx = idx % HAETAEParameters.N;
            int tmp = hbZ1[polyIdx][coeffIdx] + params.getOffset_hb_z1();

            if (tmp < 0 || params.getM_hb_z1() <= tmp)
            {
                return 0;
            }
            int s = tmp;

            ptr = ransEncPutSymbol(state, encoding, ptr, params.getEsyms_hb_z1()[s]);
            if (ptr < 4)
            {
                return 0;
            }
        }

        ptr = ransEncFlush(state, encoding, ptr);
        int sizeEncoded = encoding.length - ptr;
        System.arraycopy(encoding, ptr, buf, 0, sizeEncoded);
        return sizeEncoded;
    }

    /**
     * Multiplies an fp96_76 by a uint64_t scalar and stores the high part (shifted right by 28).
     */
    private void fixpointMulHigh(long[] xy, long[] x, long y)
    {
        long[] tmp = new long[2];
        mul48(xy, x[0], y);

        mul48(tmp, x[1], y);
        xy[1] += tmp[0];

        // Shift right by 28 with rounding
        xy[0] += 1L << 27;
        xy[0] >>>= 28;
        xy[0] += (xy[1] << 20) & MASK48;
        xy[1] >>>= 28;

        xy[1] += tmp[1] << 20;

        renormalize(xy);
    }

    /**
     * Computes (sample * sqsum + 2^12) >> 13, with sign applied.
     * This matches the C function fixpoint_mul_rnd13.
     */
    public static int fixpointMulRnd13(long x, long[] y, int sign)
    {
        // Convert x to fp96_76 format: effectively x * 2^16
        long[] xx = new long[2];
        xx[1] = x >>> 32;                       // high 32 bits
        xx[0] = (x & 0xFFFFFFFFL) << 16;        // low 32 bits shifted left by 16

        long[] tmp = new long[2];
        fixpointMul(tmp, xx, y);

        // Round: (tmp.high + 2^14) >> 15
        long res = (tmp[1] + (1L << 14)) >> 15;

        // Apply sign: (1 - 2*sign) * res
        return (int)((1L - 2L * sign) * res);
    }

    public short polyfixveclkSampleHyperball(int[][] y1, int[][] y2, byte[] b,
                                             byte[] seed, short nonce)
    {
        short ni = nonce;
        int totalPolys = params.getL() + params.getK();
        long[] samples = new long[HAETAEParameters.N * totalPolys];
        byte[] signs = new byte[(HAETAEParameters.N * totalPolys) / 8];
        long[] sqsum = new long[2];
        long[] invsqrt = new long[2];

        long b0SqLn2 = ((long)(params.getB0() * params.getB0())) *
            params.getLn() * params.getLn();

        do
        {
            // Reset squared sum
            sqsum[0] = 0;
            sqsum[1] = 0;

            // Sample first two polynomials with N+1 coefficients
            sampleGaussN(samples, 0, signs, 0, sqsum, seed, ni++, HAETAEParameters.N + 1);
            sampleGaussN(samples, HAETAEParameters.N, signs, HAETAEParameters.N / 8,
                sqsum, seed, ni++, HAETAEParameters.N + 1);

            // Sample the remaining polynomials (with N coefficients)
            for (int i = 2; i < totalPolys; i++)
            {
                sampleGaussN(samples, HAETAEParameters.N * i,
                    signs, (HAETAEParameters.N / 8) * i,
                    sqsum, seed, ni++, HAETAEParameters.N);
            }

            // Divide sqsum by 2 (with rounding)
            sqsum[0] += 1;
            sqsum[0] >>>= 1;
            sqsum[0] += (sqsum[1] & 1L) << 47;
            sqsum[1] >>>= 1;
            sqsum[1] += sqsum[0] >>> 48;
            sqsum[0] &= MASK48;

            // invsqrt = 1 / sqrt(sqsum)
            fixpointNewtonInvSqrt(invsqrt, sqsum);

            // sqsum = invsqrt * scale   (scale = (B0 * LN + SQNM/2) << (28-13))
            long scaleRaw = (long)(params.getB0() * params.getLn() + params.getSqnm() / 2.0);
            long scale = scaleRaw << (28 - params.getLnBits());

            fixpointMulHigh(sqsum, invsqrt, scale);

            // Fill y1 (L polynomials)
            for (int i = 0; i < params.getL(); i++)
            {
                for (int j = 0; j < HAETAEParameters.N; j++)
                {
                    int idx = i * HAETAEParameters.N + j;
                    long sample = samples[idx];
                    int signBit = (signs[idx / 8] >> (idx % 8)) & 1;
                    y1[i][j] = fixpointMulRnd13(sample, sqsum, signBit);
                }
            }

            // Fill y2 (K polynomials)
            for (int i = 0; i < params.getK(); i++)
            {
                for (int j = 0; j < HAETAEParameters.N; j++)
                {
                    int idx = (params.getL() + i) * HAETAEParameters.N + j;
                    long sample = samples[idx];
                    int signBit = (signs[idx / 8] >> (idx % 8)) & 1;
                    y2[i][j] = fixpointMulRnd13(sample, sqsum, signBit);
                }
            }
        }
        while (polyfixveclkSqnorm2(y1, y2) > b0SqLn2);

        // Generate the extra byte b using SHAKE‑256
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(seed, 0, HAETAEParameters.CRH_BYTES);
        shake.update((byte)(ni & 0xFF));
        shake.update((byte)((ni >> 8) & 0xFF));
        byte[] out = new byte[1];
        shake.doFinal(out, 0, 1);
        b[0] = out[0];

        return ni;
    }

    /**
     * Generates a HAETAE signature.
     *
     * @param sig output signature byte array (length at least CRYPTO_BYTES)
     * @param m   message to sign
     * @param pre pre‑hash context (can be empty)
     * @param rnd random seed (SEED_BYTES)
     * @param sk  secret key (CRYPTO_SECRETKEYBYTES)
     * @return the signature length (CRYPTO_BYTES) on success, 0 on failure
     */
    public int cryptoSignSignatureInternal(byte[] sig, byte[] m, byte[] pre, byte[] rnd, byte[] sk)
    {
        // Buffers
        byte[] buf = new byte[params.getPolyveckHighbitsPackedBytes() + HAETAEParameters.POLYC_PACKED_BYTES];
        byte[] seedbuf = new byte[HAETAEParameters.CRH_BYTES];
        byte[] key = new byte[HAETAEParameters.SEED_BYTES];
        byte[] mu = new byte[HAETAEParameters.CRH_BYTES];
        byte[] b = new byte[1];
        short counter = 0;

        // Secret vectors
        int[][][] A1 = new int[params.getK()][params.getL()][HAETAEParameters.N];
        int[][] s1 = new int[params.getM()][HAETAEParameters.N];
        int[][] s2 = new int[params.getK()][HAETAEParameters.N];

        // Unpack secret key
        unpackSk(A1, s1, s2, key, sk);

        // Compute mu = H(pk, pre, m)
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(sk, 0, params.getPublicKeyBytes());
        if (pre != null)
        {
            shake.update(pre, 0, pre.length);
        }
        shake.update(m, 0, m.length);
        shake.doFinal(mu, 0, HAETAEParameters.CRH_BYTES);

        // seedbuf = H(key, rnd, mu)
        shake.reset();
        shake.update(key, 0, HAETAEParameters.SEED_BYTES);
        shake.update(rnd, 0, HAETAEParameters.SEED_BYTES);
        shake.update(mu, 0, HAETAEParameters.CRH_BYTES);
        shake.doFinal(seedbuf, 0, HAETAEParameters.CRH_BYTES);

        // NTT of secret vectors
        polyvecmNtt(s1);
        polyveckNtt(s2);

        // Temporary arrays for the rejection loop
        int[][] y1 = new int[params.getL()][HAETAEParameters.N];
        int[][] y2 = new int[params.getK()][HAETAEParameters.N];
        int[][] z1 = new int[params.getL()][HAETAEParameters.N];
        int[][] z2 = new int[params.getK()][HAETAEParameters.N];
        int[][] z1rnd = new int[params.getL()][HAETAEParameters.N];
        int[][] z2rnd = new int[params.getK()][HAETAEParameters.N];
        int[][] Ay = new int[params.getK()][HAETAEParameters.N];
        int[][] highbits = new int[params.getK()][HAETAEParameters.N];
        int[] lsb = new int[HAETAEParameters.N];
        int[] c = new int[HAETAEParameters.N];
        int[] chat = new int[HAETAEParameters.N];
        int[][] cs1 = new int[params.getL()][HAETAEParameters.N];
        int[][] cs2 = new int[params.getK()][HAETAEParameters.N];
        int[][] h = new int[params.getK()][HAETAEParameters.N];
        int[][] lb_z1 = new int[params.getL()][HAETAEParameters.N];
        int[][] hb_z1 = new int[params.getL()][HAETAEParameters.N];

        long reject1, reject2;
        long b0SqLn2 = ((long)(params.getB0() * params.getB0())) * params.getLn() * params.getLn();
        long b1SqLn2 = ((long)(params.getB1() * params.getB1())) * params.getLn() * params.getLn();

        while (true)
        {
            // 1. Sample y1, y2 and b from hyperball
            counter = polyfixveclkSampleHyperball(y1, y2, b, seedbuf, counter);

            // 2. Round y1 and y2
            polyfixveclRound(z1rnd, y1);
            polyfixveckRound(z2rnd, y2);

            // 3. Compute Ay = A1 * NTT(z1rnd) + 2 * z2rnd (mod Q)
            int[] z1rnd0 = (int[])z1rnd[0].clone();
            polyveclNtt(z1rnd);
            polymatklPointwiseMontgomery(Ay, A1, z1rnd);
            polyveckInvnttTomont(Ay);
            polyveckDouble(z2rnd);
            polyveckAdd(Ay, Ay, z2rnd);

            // 4. Recover mod 2Q
            polyveckPolyFromcrt(Ay, Ay, z1rnd0);
            polyveckFreeze2q(Ay);

            // 5. HighBits of Ay
            polyveckHighbitsHint(highbits, Ay);

            // 6. LSB of z1rnd0
            polyLsb(lsb, z1rnd0);

            // 7. Pack highbits and LSB
            packVecHighbits(buf, 0, highbits);
            packPolyLsb(buf, params.getPolyveckHighbitsPackedBytes(), lsb);

            // 8. Generate challenge c
            polyChallenge(c, buf, mu);

            // 9. Compute cs = c * s
            cs1[0] = (int[])c.clone();
            chat = (int[])c.clone();
            polyNtt(chat);

            for (int i = 1; i < params.getL(); i++)
            {
                polyPointwiseMontgomery(cs1[i], chat, s1[i - 1]);
                polyInvnttTomont(cs1[i]);
            }
            polyveckPolyPointwiseMontgomery(cs2, s2, chat);
            polyveckInvnttTomont(cs2);

            // 10. z = y + (-1)^b * cs
            polyveclCneg(cs1, b[0] & 1);
            polyveckCneg(cs2, b[0] & 1);
            polyfixveclAdd(z1, y1, cs1);
            polyfixveckAdd(z2, y2, cs2);

            // 11. Rejection checks
            long normZ = polyfixveclkSqnorm2(z1, z2);
            reject1 = (b1SqLn2 - normZ) >>> 63;
            reject1 &= 1;

            int[][] z1tmp = new int[params.getL()][HAETAEParameters.N];
            int[][] z2tmp = new int[params.getK()][HAETAEParameters.N];
            polyfixveclDouble(z1tmp, z1);
            polyfixveckDouble(z2tmp, z2);
            polyfixfixveclSub(z1tmp, z1tmp, y1);
            polyfixfixveckSub(z2tmp, z2tmp, y2);

            long norm2z_y = polyfixveclkSqnorm2(z1tmp, z2tmp);
            reject2 = (norm2z_y - b0SqLn2) >>> 63;
            reject2 &= 1;
            reject2 &= (b[0] & 0x02) >>> 1;

            if ((reject1 | reject2) != 0)
            {
                continue;
            }

            // 12. Make hint
            polyfixveclRound(z1rnd, z1);
            polyfixveckRound(z2rnd, z2);

            polyveckDouble(z2rnd);
            int[][] htmp = new int[params.getK()][HAETAEParameters.N];
            polyveckSub(htmp, Ay, z2rnd);
            polyveckFreeze2q(htmp);
            polyveckHighbitsHint(htmp, htmp);
            polyveckSub(h, highbits, htmp);
            polyveckCaddDQ2ALPHA(h);

            // 13. Decompose z1rnd and pack signature
            polyveclLowbits(lb_z1, z1rnd);
            polyveclHighbits(hb_z1, z1rnd);

            // Reset sig buffer before each packSig attempt (it ORs the
            // challenge bits and the previous attempt's bytes would linger).
            java.util.Arrays.fill(sig, (byte)0);

            if (packSig(sig, c, lb_z1, hb_z1, h) == 0)
            {
                return params.getCryptoBytes();
            }
            // Packing failed (signature too big); retry with new sample.
        }
    }

    /**
     * Unpacks a decomposed polynomial from a byte array.
     * Each coefficient is stored as a single signed byte.
     *
     * @param a   output polynomial (length N)
     * @param buf input byte array
     * @param off offset in buf where the polynomial begins
     */
    public void polyDecomposedUnpack(int[] a, byte[] buf, int off)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            a[i] = buf[off + i];   // sign extension automatically happens when byte is promoted to int
        }
    }

    /**
     * Initializes the rANS decoder by reading the first 4 bytes of the input.
     *
     * @param state output state (element 0 set to the read value)
     * @param ptr   pointer to input position (wrapped in 1‑element array)
     * @param buf   input byte array
     * @return 0 on success, 1 if initial state is out of range
     */
    private static int ransDecInit(int[] state, int[] ptr, byte[] buf)
    {
        int p = ptr[0];
        if (p + 4 > buf.length)
        {
            return 1; // not enough data
        }
        int x = (buf[p] & 0xFF)
            | ((buf[p + 1] & 0xFF) << 8)
            | ((buf[p + 2] & 0xFF) << 16)
            | ((buf[p + 3] & 0xFF) << 24);
        //TODO
//        if (x < RANS_BYTE_L || x >= (RANS_BYTE_L << 8))
//        {
//            return 1; // state out of allowed range
//        }
        ptr[0] = p + 4;
        state[0] = x;
        return 0;
    }

    /**
     * Returns the current symbol bucket (lower scale_bits of state).
     */
    private static int ransDecGet(int state, int scaleBits)
    {
        return state & ((1 << scaleBits) - 1);
    }

    /**
     * Advances the rANS state by one symbol.
     *
     * @param state     current state (modified in place via array)
     * @param ptr       pointer to input position (modified)
     * @param buf       input byte array
     * @param endIdx    index after the last valid byte (exclusive)
     * @param start     start of symbol range
     * @param freq      symbol frequency
     * @param scaleBits scale bits (usually 10)
     */
    private static void ransDecAdvance(int[] state, int[] ptr, byte[] buf, int endIdx,
                                       int start, int freq, int scaleBits)
    {
        int mask = (1 << scaleBits) - 1;
        int x = state[0];
        x = freq * (x >>> scaleBits) + (x & mask) - start;

        // Renormalize: read bytes while x < RANS_BYTE_L
        if (x < RANS_BYTE_L && ptr[0] < endIdx)
        {
            int p = ptr[0];
            do
            {
                x = (x << 8) | (buf[p++] & 0xFF);
            }
            while (x < RANS_BYTE_L && p < endIdx);
            ptr[0] = p;
        }
        state[0] = x;
    }

    /**
     * Advances the state using a precomputed decoder symbol.
     */
    private static void ransDecAdvanceSymbol(int[] state, int[] ptr, byte[] buf, int endIdx,
                                             RansDecSymbol sym, int scaleBits)
    {
        ransDecAdvance(state, ptr, buf, endIdx, sym.start, sym.freq, scaleBits);
    }

    /**
     * Verifies that the final state equals RANS_BYTE_L.
     *
     * @return 0 on success, 1 on failure
     */
    private static int ransDecVerify(int state)
    {
        return (state == RANS_BYTE_L) ? 0 : 1;
    }

    /**
     * Decodes the high‑bits of z1 (size L×N) from the compressed input.
     *
     * @param hbZ1   output array (flattened: L×N coefficients)
     * @param buf    input byte array containing compressed data
     * @param sizeIn number of bytes in the compressed block
     * @return 0 on success, 1 on error
     */
    public int decodeHbZ1(int[] hbZ1, byte[] buf, int sizeIn)
    {
        int sizeHbZ1 = HAETAEParameters.N * params.getL();
        int[] state = new int[1];
        int[] ptr = new int[1];
        ptr[0] = 0;
        int endIdx = sizeIn;

        if (ransDecInit(state, ptr, buf) != 0)
        {
            return 1;
        }

        for (int i = 0; i < sizeHbZ1; i++)
        {
            int bucket = ransDecGet(state[0], SCALE_BITS);
            int s = params.getSymbolH_z1()[bucket];
            if (s >= params.getM_hb_z1())
            {
                return 1;
            }
            hbZ1[i] = s - params.getOffset_hb_z1();
            ransDecAdvanceSymbol(state, ptr, buf, endIdx, params.getDsyms_hb_z1()[s], SCALE_BITS);
        }

        if (ransDecVerify(state[0]) != 0)
        {
            return 1;
        }
        if (ptr[0] != sizeIn)
        {
            return 1;
        }
        return 0;
    }

    /**
     * Decodes the hint vector h (size K×N) from the compressed input.
     *
     * @param h      output array (flattened: K×N coefficients)
     * @param buf    input byte array
     * @param sizeIn number of bytes in the compressed block
     * @return 0 on success, 1 on error
     */
    public int decodeH(int[] h, byte[] buf, int sizeIn)
    {
        int sizeH = HAETAEParameters.N * params.getK();
        int[] state = new int[1];
        int[] ptr = new int[1];
        ptr[0] = 0;
        int endIdx = sizeIn;

        if (ransDecInit(state, ptr, buf) != 0)
        {
            return 1;
        }

        short[] symbolH = params.getSymbolH(); // Need to add this getter to HAETAEParameters
        RansDecSymbol[] dsyms = params.getDsyms_h();

        for (int i = 0; i < sizeH; i++)
        {
            int bucket = ransDecGet(state[0], SCALE_BITS);
            int s = symbolH[bucket];
            if (s >= params.getM_h())
            {
                return 1;
            }
            int tmp = (H_CUT < s) ? (s + params.getOffset_h()) : s;
            h[i] = tmp;
            ransDecAdvanceSymbol(state, ptr, buf, endIdx, dsyms[s], SCALE_BITS);
        }

        if (ransDecVerify(state[0]) != 0)
        {
            return 1;
        }
        if (ptr[0] != sizeIn)
        {
            return 1;
        }
        return 0;
    }

    /**
     * Unpacks a HAETAE signature into its components.
     *
     * @param c          output challenge polynomial (length N, coefficients 0/1)
     * @param lowbitsZ1  output low bits of z1 (L × N)
     * @param highbitsZ1 output high bits of z1 (L × N)
     * @param h          output hint vector (K × N)
     * @param sig        input signature byte array (length CRYPTO_BYTES)
     * @return 0 on success, 1 if the signature is malformed
     */
    public int unpackSig(int[] c, int[][] lowbitsZ1, int[][] highbitsZ1, int[][] h, byte[] sig)
    {
        int offset = 0;

        // 1. Unpack challenge c (N bits → N/8 bytes)
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            c[i] = (sig[offset + i / 8] >> (i % 8)) & 1;
        }
        offset += HAETAEParameters.N / 8;

        // 2. Unpack low bits of z1 (L polynomials, each N signed bytes)
        for (int i = 0; i < params.getL(); i++)
        {
            polyDecomposedUnpack(lowbitsZ1[i], sig, offset + HAETAEParameters.N * i);
        }
        offset += params.getL() * HAETAEParameters.N;

        // 3. Read compressed sizes (1 byte offset each)
        int sizeEncHbZ1 = (sig[offset] & 0xFF) + params.getBaseEncHbZ1();
        int sizeEncH = (sig[offset + 1] & 0xFF) + params.getBaseEncH();
        offset += 2;

        // Check overall size
        int minTotal = 2 + params.getL() * HAETAEParameters.N + HAETAEParameters.SEED_BYTES
            + sizeEncH + sizeEncHbZ1;
        if (params.getCryptoBytes() < minTotal)
        {
            return 1;
        }

        // 4. Decode highbits of z1
        int[] flatHbZ1 = new int[HAETAEParameters.N * params.getL()];
        byte[] encHbZ1 = new byte[sizeEncHbZ1];
        System.arraycopy(sig, offset, encHbZ1, 0, sizeEncHbZ1);
        if (decodeHbZ1(flatHbZ1, encHbZ1, sizeEncHbZ1) != 0)
        {
            return 1;
        }
        // Reshape into 2D array
        for (int i = 0; i < params.getL(); i++)
        {
            System.arraycopy(flatHbZ1, i * HAETAEParameters.N, highbitsZ1[i], 0, HAETAEParameters.N);
        }
        offset += sizeEncHbZ1;

        // 5. Decode hint h
        int[] flatH = new int[HAETAEParameters.N * params.getK()];
        byte[] encH = new byte[sizeEncH];
        System.arraycopy(sig, offset, encH, 0, sizeEncH);
        if (decodeH(flatH, encH, sizeEncH) != 0)
        {
            return 1;
        }
        for (int i = 0; i < params.getK(); i++)
        {
            System.arraycopy(flatH, i * HAETAEParameters.N, h[i], 0, HAETAEParameters.N);
        }
        offset += sizeEncH;

        // 6. Verify zero padding
        for (int i = offset; i < params.getCryptoBytes(); i++)
        {
            if (sig[i] != 0)
            {
                return 1;
            }
        }
        return 0;
    }

    // ---------- Polynomial Composition ----------

    /**
     * Composes a polynomial from its high and low parts.
     * a = 256 * ha + la
     */
    public void polyCompose(int[] a, int[] ha, int[] la)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            a[i] = ha[i] * 256 + la[i];
        }
    }

    // ---------- Squared Norms ----------

    /**
     * Computes the squared ℓ₂‑norm of a vector of length L.
     */
    public long polyveclSqnorm2(int[][] a)
    {
        long ret = 0;
        for (int i = 0; i < params.getL(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                long coeff = a[i][j];
                ret += coeff * coeff;
            }
        }
        return ret;
    }

    /**
     * Computes the squared ℓ₂‑norm of a vector of length K.
     */
    public long polyveckSqnorm2(int[][] b)
    {
        long ret = 0;
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                long coeff = b[i][j];
                ret += coeff * coeff;
            }
        }
        return ret;
    }

    // ---------- Vector Operations for Verification ----------

    /**
     * Conditional subtraction: v -= maxHint if v >= maxHint.
     * maxHint = (DQ - 2) / ALPHA_HINT
     */
    public void polyveckCsubDQ2ALPHA(int[][] v)
    {
        int maxHint = (HAETAEParameters.DQ - 2) / params.getAlphaHint();
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                int coeff = v[i][j];
                // if coeff >= maxHint, subtract maxHint
                int mask = ~((coeff - maxHint) >> 31);
                v[i][j] = coeff - (mask & maxHint);
            }
        }
    }

    /**
     * Multiplies each coefficient by ALPHA_HINT.
     */
    public void polyveckMulAlpha(int[][] v, int[][] u)
    {
        int alpha = params.getAlphaHint();
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                v[i][j] = u[i][j] * alpha;
            }
        }
    }

    /**
     * Reduces each coefficient to the centered representation modulo 2Q.
     */
    public void polyveckReduce2q(int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            polyReduce2q(v[i]);
        }
    }

    private void polyReduce2q(int[] a)
    {
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            a[i] = reduce32_2q(a[i]);
        }
    }

    private int reduce32_2q(int a)
    {
        // Use DQREC (precomputed reciprocal for 2Q)
        long t = ((long)a * DQREC) >> 32;
        long r = a - t * HAETAEParameters.DQ;               // -4Q < r < 4Q
        r += (r >> 31) & (HAETAEParameters.DQ * 2);         // 0 <= r < 4Q
        r -= ~((r - HAETAEParameters.DQ) >> 31) & HAETAEParameters.DQ; // 0 <= r < 2Q
        // Centered representation: if r >= Q, subtract 2Q (i.e., r - 2Q)
        r -= ~((r - HAETAEParameters.Q) >> 31) & HAETAEParameters.DQ;
        return (int)r;
    }

    /**
     * Divides each coefficient by 2 (arithmetic right shift).
     */
    public void polyveckDiv2(int[][] v)
    {
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                v[i][j] >>= 1;
            }
        }
    }

    /**
     * Verifies a HAETAE signature.
     *
     * @param sig signature byte array (length CRYPTO_BYTES)
     * @param m   message to verify
     * @param pre pre‑hash context (can be empty)
     * @param vk  public key byte array (CRYPTO_PUBLICKEYBYTES)
     * @return 0 if signature is valid, -1 otherwise
     */
    public boolean cryptoSignVerifyInternal(byte[] sig, byte[] m, byte[] pre, byte[] vk)
    {
        // 1. Check signature length
        if (sig.length != params.getCryptoBytes())
        {
            return false;
        }

        // Buffers
        byte[] buf = new byte[params.getPolyveckHighbitsPackedBytes() + HAETAEParameters.POLYC_PACKED_BYTES];
        byte[] mu = new byte[HAETAEParameters.SEED_BYTES];

        // Matrix A1 (K × L)
        int[][][] A1 = new int[params.getK()][params.getL()][HAETAEParameters.N];

        // Vectors and polynomials
        int[][] highz = new int[params.getL()][HAETAEParameters.N];   // high bits of z1
        int[][] lowz = new int[params.getL()][HAETAEParameters.N];   // low bits of z1
        int[][] z1 = new int[params.getL()][HAETAEParameters.N];   // reconstructed z1
        int[][] h = new int[params.getK()][HAETAEParameters.N];   // hint vector
        int[][] highbits = new int[params.getK()][HAETAEParameters.N];
        int[][] w = new int[params.getK()][HAETAEParameters.N];
        int[][] z2 = new int[params.getK()][HAETAEParameters.N];

        int[] c = new int[HAETAEParameters.N];
        int[] cprime = new int[HAETAEParameters.N];
        int[] wprime = new int[HAETAEParameters.N];

        // 2. Unpack public key → build matrix A1
        unpackVk(A1, vk);

        // 3. Unpack signature
        if (unpackSig(c, lowz, highz, h, sig) != 0)
        {
            return false;
        }

        // 4. Compose z1 = 256 * highz + lowz
        for (int i = 0; i < params.getL(); i++)
        {
            polyCompose(z1[i], highz[i], lowz[i]);
        }

        // 5. Compute squared norm of z1 and w' = LSB(z1[0] - c)
        long sqnorm2 = polyveclSqnorm2(z1);
        int[] z1_0 = z1[0];
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            wprime[i] = (z1_0[i] - c[i]) & 1;   // LSB of difference
        }

        // 6. A1 * NTT(z1)   (mod Q)
        polyveclNtt(z1);
        polymatklPointwiseMontgomery(highbits, A1, z1);
        polyveckInvnttTomont(highbits);

        // 7. Recover A1 * z1 mod 2Q using CRT
        polyveckPolyFromcrt(highbits, highbits, wprime);
        polyveckFreeze2q(highbits);

        // 8. w1 = HighBits(highbits)
        polyveckHighbitsHint(w, highbits);
        polyveckAdd(w, w, h);
        polyveckCsubDQ2ALPHA(w);

        // 9. Recover \tilde{z}_2
        polyveckMulAlpha(z2, w);
        polyveckSub(z2, z2, highbits);
        // Add wprime to the first polynomial of z2
        for (int i = 0; i < HAETAEParameters.N; i++)
        {
            z2[0][i] += wprime[i];
        }
        polyveckReduce2q(z2);
        polyveckDiv2(z2);

        // 10. Check final norm
        if (sqnorm2 + polyveckSqnorm2(z2) > params.getB2Sq())
        {
            return false;
        }

        // 11. Compute challenge c' and compare
        packVecHighbits(buf, 0, w);
        packPolyLsb(buf, params.getPolyveckHighbitsPackedBytes(), wprime);

        // mu = H(pk, pre, m)
        SHAKEDigest shake = new SHAKEDigest(256);
        shake.update(vk, 0, params.getPublicKeyBytes());
        if (pre != null)
        {
            shake.update(pre, 0, pre.length);
        }
        shake.update(m, 0, m.length);
        shake.doFinal(mu, 0, HAETAEParameters.SEED_BYTES);

        polyChallenge(cprime, buf, mu);

        // Compare c and c'
        return Arrays.areEqual(c, cprime);
    }
}
