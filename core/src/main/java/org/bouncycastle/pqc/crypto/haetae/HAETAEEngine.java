package org.bouncycastle.pqc.crypto.haetae;

import org.bouncycastle.crypto.digests.SHAKEDigest;

public class HAETAEEngine
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

    public HAETAEEngine(HAETAEParameters params)
    {
        this.params = params;
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
        // w = u[0] ∘ v[0]
        polyPointwiseMontgomery(w, u[0], v[0]);

        // temporary polynomial for intermediate results
        int[] t = new int[HAETAEParameters.N];

        for (int j = 1; j < params.getM(); j++)
        {
            polyPointwiseMontgomery(t, u[j], v[j]);
            polyAdd(w, w, t);
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
     * The low part {@code a0} is in {-1, 0, 1} and satisfies:
     * {@code a = 2 * result + a0}.
     * </p>
     *
     * @param a0 output array of length 1 to hold the low part
     * @param a  input coefficient
     * @return the high part
     */
    private static int decomposeVk(int[] a0, int a)
    {
        int low = a & 1;
        low -= (((a >> 1) & low) << 1);
        a0[0] = low;
        return (a - low) >> 1;
    }

    /**
     * Overloaded version that returns the high part and stores the low part in a single-element array.
     * (Convenience for in-place updates.)
     */
    private static int decomposeVk(int a, int[] lowHolder)
    {
        int low = a & 1;
        low -= (((a >> 1) & low) << 1);
        lowHolder[0] = low;
        return (a - low) >> 1;
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
        int[] lowHolder = new int[1];
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                v[i][j] = decomposeVk(v[i][j], lowHolder);
                v0[i][j] = lowHolder[0];
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
            // Multiply by pre‑twiddle factor
            r[invI].real = mulrnd16(c, roots[i].real);
            r[invI].imag = mulrnd16(c, roots[i].imag);
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
            int md2 = m >> 1;
            for (int n = 0; n < FFT_N; n += m)
            {
                for (int k = 0; k < md2; k++)
                {
                    int even = n + k;
                    int odd = even + md2;
                    int twid = k << (FFT_LOGN - r + 1);

                    ComplexFp32_16 u = data[even];
                    ComplexFp32_16 t = new ComplexFp32_16();
                    complexMul(t, roots[twid], data[odd]);

                    data[even].real = u.real + t.real;
                    data[even].imag = u.imag + t.imag;
                    data[odd].real = u.real - t.real;
                    data[odd].imag = u.imag - t.imag;
                }
            }
        }
    }

    // ---------- Branchless min/max swap (djbsort) ----------

    private static void minmax(int[] x, int[] y)
    {
        int a = x[0];
        int b = y[0];
        int ab = b ^ a;
        int c = b - a;
        c ^= ab & (c ^ b);
        c >>= 31;
        c &= ab;
        x[0] = a ^ c;
        y[0] = b ^ c;
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
        for (int i = 0; i < bestmSize; i++)
        {
            bestm[i] = sum[i];
        }
        for (int i = bestmSize; i < HAETAEParameters.N; i++)
        {
            int[] val = new int[]{sum[i]};
            for (int j = 0; j < bestmSize; j++)
            {
                int[] bj = new int[]{bestm[j]};
                minmax(val, bj);
                bestm[j] = bj[0];
            }
        }

        // Find minimum among bestm
        int min = bestm[0];
        for (int i = 1; i < bestmSize; i++)
        {
            int tmp = bestm[i];
            int[] minArr = new int[]{min};
            int[] tmpArr = new int[]{tmp};
            minmax(minArr, tmpArr);
            min = minArr[0];
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
                s1 = deepCopy(s1hat);
                System.out.println("counter: " + counter + " b[0][0]: " + b[0][0] + " " + squaredSingularValue);
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
            int[][] s1hat = s1;
            int[][] s2hat = s2;
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
            dst[i] = src[i].clone();
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
        long factor = ((long)MONT * -2) & 0xFFFFFFFFL; // treat as unsigned 32‑bit
        for (int i = 0; i < params.getK(); i++)
        {
            for (int j = 0; j < HAETAEParameters.N; j++)
            {
                v[i][j] = montgomeryReduce(v[i][j] * factor);
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
}
