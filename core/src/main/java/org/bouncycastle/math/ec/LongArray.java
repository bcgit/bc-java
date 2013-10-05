package org.bouncycastle.math.ec;

import org.bouncycastle.util.Arrays;

import java.math.BigInteger;

class LongArray
{
//    private static long DEINTERLEAVE_MASK = 0x5555555555555555L;

    /*
     * This expands 8 bit indices into 16 bit contents (high bit 14), by inserting 0s between bits.
     * In a binary field, this operation is the same as squaring an 8 bit number.
     */
    private static final int[] INTERLEAVE2_TABLE = new int[]
    {
        0x0000, 0x0001, 0x0004, 0x0005, 0x0010, 0x0011, 0x0014, 0x0015,
        0x0040, 0x0041, 0x0044, 0x0045, 0x0050, 0x0051, 0x0054, 0x0055,
        0x0100, 0x0101, 0x0104, 0x0105, 0x0110, 0x0111, 0x0114, 0x0115,
        0x0140, 0x0141, 0x0144, 0x0145, 0x0150, 0x0151, 0x0154, 0x0155,
        0x0400, 0x0401, 0x0404, 0x0405, 0x0410, 0x0411, 0x0414, 0x0415,
        0x0440, 0x0441, 0x0444, 0x0445, 0x0450, 0x0451, 0x0454, 0x0455,
        0x0500, 0x0501, 0x0504, 0x0505, 0x0510, 0x0511, 0x0514, 0x0515,
        0x0540, 0x0541, 0x0544, 0x0545, 0x0550, 0x0551, 0x0554, 0x0555,
        0x1000, 0x1001, 0x1004, 0x1005, 0x1010, 0x1011, 0x1014, 0x1015,
        0x1040, 0x1041, 0x1044, 0x1045, 0x1050, 0x1051, 0x1054, 0x1055,
        0x1100, 0x1101, 0x1104, 0x1105, 0x1110, 0x1111, 0x1114, 0x1115,
        0x1140, 0x1141, 0x1144, 0x1145, 0x1150, 0x1151, 0x1154, 0x1155,
        0x1400, 0x1401, 0x1404, 0x1405, 0x1410, 0x1411, 0x1414, 0x1415,
        0x1440, 0x1441, 0x1444, 0x1445, 0x1450, 0x1451, 0x1454, 0x1455,
        0x1500, 0x1501, 0x1504, 0x1505, 0x1510, 0x1511, 0x1514, 0x1515,
        0x1540, 0x1541, 0x1544, 0x1545, 0x1550, 0x1551, 0x1554, 0x1555,
        0x4000, 0x4001, 0x4004, 0x4005, 0x4010, 0x4011, 0x4014, 0x4015,
        0x4040, 0x4041, 0x4044, 0x4045, 0x4050, 0x4051, 0x4054, 0x4055,
        0x4100, 0x4101, 0x4104, 0x4105, 0x4110, 0x4111, 0x4114, 0x4115,
        0x4140, 0x4141, 0x4144, 0x4145, 0x4150, 0x4151, 0x4154, 0x4155,
        0x4400, 0x4401, 0x4404, 0x4405, 0x4410, 0x4411, 0x4414, 0x4415,
        0x4440, 0x4441, 0x4444, 0x4445, 0x4450, 0x4451, 0x4454, 0x4455,
        0x4500, 0x4501, 0x4504, 0x4505, 0x4510, 0x4511, 0x4514, 0x4515,
        0x4540, 0x4541, 0x4544, 0x4545, 0x4550, 0x4551, 0x4554, 0x4555,
        0x5000, 0x5001, 0x5004, 0x5005, 0x5010, 0x5011, 0x5014, 0x5015,
        0x5040, 0x5041, 0x5044, 0x5045, 0x5050, 0x5051, 0x5054, 0x5055,
        0x5100, 0x5101, 0x5104, 0x5105, 0x5110, 0x5111, 0x5114, 0x5115,
        0x5140, 0x5141, 0x5144, 0x5145, 0x5150, 0x5151, 0x5154, 0x5155,
        0x5400, 0x5401, 0x5404, 0x5405, 0x5410, 0x5411, 0x5414, 0x5415,
        0x5440, 0x5441, 0x5444, 0x5445, 0x5450, 0x5451, 0x5454, 0x5455,
        0x5500, 0x5501, 0x5504, 0x5505, 0x5510, 0x5511, 0x5514, 0x5515,
        0x5540, 0x5541, 0x5544, 0x5545, 0x5550, 0x5551, 0x5554, 0x5555
    };

    /*
     * This expands 7 bit indices into 21 bit contents (high bit 18), by inserting 0s between bits.
     */
    private static final int[] INTERLEAVE3_TABLE = new  int[]
    {
        0x00000, 0x00001, 0x00008, 0x00009, 0x00040, 0x00041, 0x00048, 0x00049,
        0x00200, 0x00201, 0x00208, 0x00209, 0x00240, 0x00241, 0x00248, 0x00249,
        0x01000, 0x01001, 0x01008, 0x01009, 0x01040, 0x01041, 0x01048, 0x01049,
        0x01200, 0x01201, 0x01208, 0x01209, 0x01240, 0x01241, 0x01248, 0x01249,
        0x08000, 0x08001, 0x08008, 0x08009, 0x08040, 0x08041, 0x08048, 0x08049,
        0x08200, 0x08201, 0x08208, 0x08209, 0x08240, 0x08241, 0x08248, 0x08249,
        0x09000, 0x09001, 0x09008, 0x09009, 0x09040, 0x09041, 0x09048, 0x09049,
        0x09200, 0x09201, 0x09208, 0x09209, 0x09240, 0x09241, 0x09248, 0x09249,
        0x40000, 0x40001, 0x40008, 0x40009, 0x40040, 0x40041, 0x40048, 0x40049,
        0x40200, 0x40201, 0x40208, 0x40209, 0x40240, 0x40241, 0x40248, 0x40249,
        0x41000, 0x41001, 0x41008, 0x41009, 0x41040, 0x41041, 0x41048, 0x41049,
        0x41200, 0x41201, 0x41208, 0x41209, 0x41240, 0x41241, 0x41248, 0x41249,
        0x48000, 0x48001, 0x48008, 0x48009, 0x48040, 0x48041, 0x48048, 0x48049,
        0x48200, 0x48201, 0x48208, 0x48209, 0x48240, 0x48241, 0x48248, 0x48249,
        0x49000, 0x49001, 0x49008, 0x49009, 0x49040, 0x49041, 0x49048, 0x49049,
        0x49200, 0x49201, 0x49208, 0x49209, 0x49240, 0x49241, 0x49248, 0x49249
    };

    /*
     * This expands 8 bit indices into 32 bit contents (high bit 28), by inserting 0s between bits.
     */
    private static final int[] INTERLEAVE4_TABLE = new int[]
    {
        0x00000000, 0x00000001, 0x00000010, 0x00000011, 0x00000100, 0x00000101, 0x00000110, 0x00000111,
        0x00001000, 0x00001001, 0x00001010, 0x00001011, 0x00001100, 0x00001101, 0x00001110, 0x00001111,
        0x00010000, 0x00010001, 0x00010010, 0x00010011, 0x00010100, 0x00010101, 0x00010110, 0x00010111,
        0x00011000, 0x00011001, 0x00011010, 0x00011011, 0x00011100, 0x00011101, 0x00011110, 0x00011111,
        0x00100000, 0x00100001, 0x00100010, 0x00100011, 0x00100100, 0x00100101, 0x00100110, 0x00100111,
        0x00101000, 0x00101001, 0x00101010, 0x00101011, 0x00101100, 0x00101101, 0x00101110, 0x00101111,
        0x00110000, 0x00110001, 0x00110010, 0x00110011, 0x00110100, 0x00110101, 0x00110110, 0x00110111,
        0x00111000, 0x00111001, 0x00111010, 0x00111011, 0x00111100, 0x00111101, 0x00111110, 0x00111111,
        0x01000000, 0x01000001, 0x01000010, 0x01000011, 0x01000100, 0x01000101, 0x01000110, 0x01000111,
        0x01001000, 0x01001001, 0x01001010, 0x01001011, 0x01001100, 0x01001101, 0x01001110, 0x01001111,
        0x01010000, 0x01010001, 0x01010010, 0x01010011, 0x01010100, 0x01010101, 0x01010110, 0x01010111,
        0x01011000, 0x01011001, 0x01011010, 0x01011011, 0x01011100, 0x01011101, 0x01011110, 0x01011111,
        0x01100000, 0x01100001, 0x01100010, 0x01100011, 0x01100100, 0x01100101, 0x01100110, 0x01100111,
        0x01101000, 0x01101001, 0x01101010, 0x01101011, 0x01101100, 0x01101101, 0x01101110, 0x01101111,
        0x01110000, 0x01110001, 0x01110010, 0x01110011, 0x01110100, 0x01110101, 0x01110110, 0x01110111,
        0x01111000, 0x01111001, 0x01111010, 0x01111011, 0x01111100, 0x01111101, 0x01111110, 0x01111111,
        0x10000000, 0x10000001, 0x10000010, 0x10000011, 0x10000100, 0x10000101, 0x10000110, 0x10000111,
        0x10001000, 0x10001001, 0x10001010, 0x10001011, 0x10001100, 0x10001101, 0x10001110, 0x10001111,
        0x10010000, 0x10010001, 0x10010010, 0x10010011, 0x10010100, 0x10010101, 0x10010110, 0x10010111,
        0x10011000, 0x10011001, 0x10011010, 0x10011011, 0x10011100, 0x10011101, 0x10011110, 0x10011111,
        0x10100000, 0x10100001, 0x10100010, 0x10100011, 0x10100100, 0x10100101, 0x10100110, 0x10100111,
        0x10101000, 0x10101001, 0x10101010, 0x10101011, 0x10101100, 0x10101101, 0x10101110, 0x10101111,
        0x10110000, 0x10110001, 0x10110010, 0x10110011, 0x10110100, 0x10110101, 0x10110110, 0x10110111,
        0x10111000, 0x10111001, 0x10111010, 0x10111011, 0x10111100, 0x10111101, 0x10111110, 0x10111111,
        0x11000000, 0x11000001, 0x11000010, 0x11000011, 0x11000100, 0x11000101, 0x11000110, 0x11000111,
        0x11001000, 0x11001001, 0x11001010, 0x11001011, 0x11001100, 0x11001101, 0x11001110, 0x11001111,
        0x11010000, 0x11010001, 0x11010010, 0x11010011, 0x11010100, 0x11010101, 0x11010110, 0x11010111,
        0x11011000, 0x11011001, 0x11011010, 0x11011011, 0x11011100, 0x11011101, 0x11011110, 0x11011111,
        0x11100000, 0x11100001, 0x11100010, 0x11100011, 0x11100100, 0x11100101, 0x11100110, 0x11100111,
        0x11101000, 0x11101001, 0x11101010, 0x11101011, 0x11101100, 0x11101101, 0x11101110, 0x11101111,
        0x11110000, 0x11110001, 0x11110010, 0x11110011, 0x11110100, 0x11110101, 0x11110110, 0x11110111,
        0x11111000, 0x11111001, 0x11111010, 0x11111011, 0x11111100, 0x11111101, 0x11111110, 0x11111111
    };

    /*
     * This expands 7 bit indices into 35 bit contents (high bit 30), by inserting 0s between bits.
     */
    private static final int[] INTERLEAVE5_TABLE = new int[] {
        0x00000000, 0x00000001, 0x00000020, 0x00000021, 0x00000400, 0x00000401, 0x00000420, 0x00000421,
        0x00008000, 0x00008001, 0x00008020, 0x00008021, 0x00008400, 0x00008401, 0x00008420, 0x00008421,
        0x00100000, 0x00100001, 0x00100020, 0x00100021, 0x00100400, 0x00100401, 0x00100420, 0x00100421,
        0x00108000, 0x00108001, 0x00108020, 0x00108021, 0x00108400, 0x00108401, 0x00108420, 0x00108421,
        0x02000000, 0x02000001, 0x02000020, 0x02000021, 0x02000400, 0x02000401, 0x02000420, 0x02000421,
        0x02008000, 0x02008001, 0x02008020, 0x02008021, 0x02008400, 0x02008401, 0x02008420, 0x02008421,
        0x02100000, 0x02100001, 0x02100020, 0x02100021, 0x02100400, 0x02100401, 0x02100420, 0x02100421,
        0x02108000, 0x02108001, 0x02108020, 0x02108021, 0x02108400, 0x02108401, 0x02108420, 0x02108421,
        0x40000000, 0x40000001, 0x40000020, 0x40000021, 0x40000400, 0x40000401, 0x40000420, 0x40000421,
        0x40008000, 0x40008001, 0x40008020, 0x40008021, 0x40008400, 0x40008401, 0x40008420, 0x40008421,
        0x40100000, 0x40100001, 0x40100020, 0x40100021, 0x40100400, 0x40100401, 0x40100420, 0x40100421,
        0x40108000, 0x40108001, 0x40108020, 0x40108021, 0x40108400, 0x40108401, 0x40108420, 0x40108421,
        0x42000000, 0x42000001, 0x42000020, 0x42000021, 0x42000400, 0x42000401, 0x42000420, 0x42000421,
        0x42008000, 0x42008001, 0x42008020, 0x42008021, 0x42008400, 0x42008401, 0x42008420, 0x42008421,
        0x42100000, 0x42100001, 0x42100020, 0x42100021, 0x42100400, 0x42100401, 0x42100420, 0x42100421,
        0x42108000, 0x42108001, 0x42108020, 0x42108021, 0x42108400, 0x42108401, 0x42108420, 0x42108421
    };

    /*
     * This expands 9 bit indices into 63 bit (long) contents (high bit 56), by inserting 0s between bits.
     */
    private static final long[] INTERLEAVE7_TABLE = new long[]
    {
        0x0000000000000000L, 0x0000000000000001L, 0x0000000000000080L, 0x0000000000000081L,
        0x0000000000004000L, 0x0000000000004001L, 0x0000000000004080L, 0x0000000000004081L,
        0x0000000000200000L, 0x0000000000200001L, 0x0000000000200080L, 0x0000000000200081L,
        0x0000000000204000L, 0x0000000000204001L, 0x0000000000204080L, 0x0000000000204081L,
        0x0000000010000000L, 0x0000000010000001L, 0x0000000010000080L, 0x0000000010000081L,
        0x0000000010004000L, 0x0000000010004001L, 0x0000000010004080L, 0x0000000010004081L,
        0x0000000010200000L, 0x0000000010200001L, 0x0000000010200080L, 0x0000000010200081L,
        0x0000000010204000L, 0x0000000010204001L, 0x0000000010204080L, 0x0000000010204081L,
        0x0000000800000000L, 0x0000000800000001L, 0x0000000800000080L, 0x0000000800000081L,
        0x0000000800004000L, 0x0000000800004001L, 0x0000000800004080L, 0x0000000800004081L,
        0x0000000800200000L, 0x0000000800200001L, 0x0000000800200080L, 0x0000000800200081L,
        0x0000000800204000L, 0x0000000800204001L, 0x0000000800204080L, 0x0000000800204081L,
        0x0000000810000000L, 0x0000000810000001L, 0x0000000810000080L, 0x0000000810000081L,
        0x0000000810004000L, 0x0000000810004001L, 0x0000000810004080L, 0x0000000810004081L,
        0x0000000810200000L, 0x0000000810200001L, 0x0000000810200080L, 0x0000000810200081L,
        0x0000000810204000L, 0x0000000810204001L, 0x0000000810204080L, 0x0000000810204081L,
        0x0000040000000000L, 0x0000040000000001L, 0x0000040000000080L, 0x0000040000000081L,
        0x0000040000004000L, 0x0000040000004001L, 0x0000040000004080L, 0x0000040000004081L,
        0x0000040000200000L, 0x0000040000200001L, 0x0000040000200080L, 0x0000040000200081L,
        0x0000040000204000L, 0x0000040000204001L, 0x0000040000204080L, 0x0000040000204081L,
        0x0000040010000000L, 0x0000040010000001L, 0x0000040010000080L, 0x0000040010000081L,
        0x0000040010004000L, 0x0000040010004001L, 0x0000040010004080L, 0x0000040010004081L,
        0x0000040010200000L, 0x0000040010200001L, 0x0000040010200080L, 0x0000040010200081L,
        0x0000040010204000L, 0x0000040010204001L, 0x0000040010204080L, 0x0000040010204081L,
        0x0000040800000000L, 0x0000040800000001L, 0x0000040800000080L, 0x0000040800000081L,
        0x0000040800004000L, 0x0000040800004001L, 0x0000040800004080L, 0x0000040800004081L,
        0x0000040800200000L, 0x0000040800200001L, 0x0000040800200080L, 0x0000040800200081L,
        0x0000040800204000L, 0x0000040800204001L, 0x0000040800204080L, 0x0000040800204081L,
        0x0000040810000000L, 0x0000040810000001L, 0x0000040810000080L, 0x0000040810000081L,
        0x0000040810004000L, 0x0000040810004001L, 0x0000040810004080L, 0x0000040810004081L,
        0x0000040810200000L, 0x0000040810200001L, 0x0000040810200080L, 0x0000040810200081L,
        0x0000040810204000L, 0x0000040810204001L, 0x0000040810204080L, 0x0000040810204081L,
        0x0002000000000000L, 0x0002000000000001L, 0x0002000000000080L, 0x0002000000000081L,
        0x0002000000004000L, 0x0002000000004001L, 0x0002000000004080L, 0x0002000000004081L,
        0x0002000000200000L, 0x0002000000200001L, 0x0002000000200080L, 0x0002000000200081L,
        0x0002000000204000L, 0x0002000000204001L, 0x0002000000204080L, 0x0002000000204081L,
        0x0002000010000000L, 0x0002000010000001L, 0x0002000010000080L, 0x0002000010000081L,
        0x0002000010004000L, 0x0002000010004001L, 0x0002000010004080L, 0x0002000010004081L,
        0x0002000010200000L, 0x0002000010200001L, 0x0002000010200080L, 0x0002000010200081L,
        0x0002000010204000L, 0x0002000010204001L, 0x0002000010204080L, 0x0002000010204081L,
        0x0002000800000000L, 0x0002000800000001L, 0x0002000800000080L, 0x0002000800000081L,
        0x0002000800004000L, 0x0002000800004001L, 0x0002000800004080L, 0x0002000800004081L,
        0x0002000800200000L, 0x0002000800200001L, 0x0002000800200080L, 0x0002000800200081L,
        0x0002000800204000L, 0x0002000800204001L, 0x0002000800204080L, 0x0002000800204081L,
        0x0002000810000000L, 0x0002000810000001L, 0x0002000810000080L, 0x0002000810000081L,
        0x0002000810004000L, 0x0002000810004001L, 0x0002000810004080L, 0x0002000810004081L,
        0x0002000810200000L, 0x0002000810200001L, 0x0002000810200080L, 0x0002000810200081L,
        0x0002000810204000L, 0x0002000810204001L, 0x0002000810204080L, 0x0002000810204081L,
        0x0002040000000000L, 0x0002040000000001L, 0x0002040000000080L, 0x0002040000000081L,
        0x0002040000004000L, 0x0002040000004001L, 0x0002040000004080L, 0x0002040000004081L,
        0x0002040000200000L, 0x0002040000200001L, 0x0002040000200080L, 0x0002040000200081L,
        0x0002040000204000L, 0x0002040000204001L, 0x0002040000204080L, 0x0002040000204081L,
        0x0002040010000000L, 0x0002040010000001L, 0x0002040010000080L, 0x0002040010000081L,
        0x0002040010004000L, 0x0002040010004001L, 0x0002040010004080L, 0x0002040010004081L,
        0x0002040010200000L, 0x0002040010200001L, 0x0002040010200080L, 0x0002040010200081L,
        0x0002040010204000L, 0x0002040010204001L, 0x0002040010204080L, 0x0002040010204081L,
        0x0002040800000000L, 0x0002040800000001L, 0x0002040800000080L, 0x0002040800000081L,
        0x0002040800004000L, 0x0002040800004001L, 0x0002040800004080L, 0x0002040800004081L,
        0x0002040800200000L, 0x0002040800200001L, 0x0002040800200080L, 0x0002040800200081L,
        0x0002040800204000L, 0x0002040800204001L, 0x0002040800204080L, 0x0002040800204081L,
        0x0002040810000000L, 0x0002040810000001L, 0x0002040810000080L, 0x0002040810000081L,
        0x0002040810004000L, 0x0002040810004001L, 0x0002040810004080L, 0x0002040810004081L,
        0x0002040810200000L, 0x0002040810200001L, 0x0002040810200080L, 0x0002040810200081L,
        0x0002040810204000L, 0x0002040810204001L, 0x0002040810204080L, 0x0002040810204081L,
        0x0100000000000000L, 0x0100000000000001L, 0x0100000000000080L, 0x0100000000000081L,
        0x0100000000004000L, 0x0100000000004001L, 0x0100000000004080L, 0x0100000000004081L,
        0x0100000000200000L, 0x0100000000200001L, 0x0100000000200080L, 0x0100000000200081L,
        0x0100000000204000L, 0x0100000000204001L, 0x0100000000204080L, 0x0100000000204081L,
        0x0100000010000000L, 0x0100000010000001L, 0x0100000010000080L, 0x0100000010000081L,
        0x0100000010004000L, 0x0100000010004001L, 0x0100000010004080L, 0x0100000010004081L,
        0x0100000010200000L, 0x0100000010200001L, 0x0100000010200080L, 0x0100000010200081L,
        0x0100000010204000L, 0x0100000010204001L, 0x0100000010204080L, 0x0100000010204081L,
        0x0100000800000000L, 0x0100000800000001L, 0x0100000800000080L, 0x0100000800000081L,
        0x0100000800004000L, 0x0100000800004001L, 0x0100000800004080L, 0x0100000800004081L,
        0x0100000800200000L, 0x0100000800200001L, 0x0100000800200080L, 0x0100000800200081L,
        0x0100000800204000L, 0x0100000800204001L, 0x0100000800204080L, 0x0100000800204081L,
        0x0100000810000000L, 0x0100000810000001L, 0x0100000810000080L, 0x0100000810000081L,
        0x0100000810004000L, 0x0100000810004001L, 0x0100000810004080L, 0x0100000810004081L,
        0x0100000810200000L, 0x0100000810200001L, 0x0100000810200080L, 0x0100000810200081L,
        0x0100000810204000L, 0x0100000810204001L, 0x0100000810204080L, 0x0100000810204081L,
        0x0100040000000000L, 0x0100040000000001L, 0x0100040000000080L, 0x0100040000000081L,
        0x0100040000004000L, 0x0100040000004001L, 0x0100040000004080L, 0x0100040000004081L,
        0x0100040000200000L, 0x0100040000200001L, 0x0100040000200080L, 0x0100040000200081L,
        0x0100040000204000L, 0x0100040000204001L, 0x0100040000204080L, 0x0100040000204081L,
        0x0100040010000000L, 0x0100040010000001L, 0x0100040010000080L, 0x0100040010000081L,
        0x0100040010004000L, 0x0100040010004001L, 0x0100040010004080L, 0x0100040010004081L,
        0x0100040010200000L, 0x0100040010200001L, 0x0100040010200080L, 0x0100040010200081L,
        0x0100040010204000L, 0x0100040010204001L, 0x0100040010204080L, 0x0100040010204081L,
        0x0100040800000000L, 0x0100040800000001L, 0x0100040800000080L, 0x0100040800000081L,
        0x0100040800004000L, 0x0100040800004001L, 0x0100040800004080L, 0x0100040800004081L,
        0x0100040800200000L, 0x0100040800200001L, 0x0100040800200080L, 0x0100040800200081L,
        0x0100040800204000L, 0x0100040800204001L, 0x0100040800204080L, 0x0100040800204081L,
        0x0100040810000000L, 0x0100040810000001L, 0x0100040810000080L, 0x0100040810000081L,
        0x0100040810004000L, 0x0100040810004001L, 0x0100040810004080L, 0x0100040810004081L,
        0x0100040810200000L, 0x0100040810200001L, 0x0100040810200080L, 0x0100040810200081L,
        0x0100040810204000L, 0x0100040810204001L, 0x0100040810204080L, 0x0100040810204081L,
        0x0102000000000000L, 0x0102000000000001L, 0x0102000000000080L, 0x0102000000000081L,
        0x0102000000004000L, 0x0102000000004001L, 0x0102000000004080L, 0x0102000000004081L,
        0x0102000000200000L, 0x0102000000200001L, 0x0102000000200080L, 0x0102000000200081L,
        0x0102000000204000L, 0x0102000000204001L, 0x0102000000204080L, 0x0102000000204081L,
        0x0102000010000000L, 0x0102000010000001L, 0x0102000010000080L, 0x0102000010000081L,
        0x0102000010004000L, 0x0102000010004001L, 0x0102000010004080L, 0x0102000010004081L,
        0x0102000010200000L, 0x0102000010200001L, 0x0102000010200080L, 0x0102000010200081L,
        0x0102000010204000L, 0x0102000010204001L, 0x0102000010204080L, 0x0102000010204081L,
        0x0102000800000000L, 0x0102000800000001L, 0x0102000800000080L, 0x0102000800000081L,
        0x0102000800004000L, 0x0102000800004001L, 0x0102000800004080L, 0x0102000800004081L,
        0x0102000800200000L, 0x0102000800200001L, 0x0102000800200080L, 0x0102000800200081L,
        0x0102000800204000L, 0x0102000800204001L, 0x0102000800204080L, 0x0102000800204081L,
        0x0102000810000000L, 0x0102000810000001L, 0x0102000810000080L, 0x0102000810000081L,
        0x0102000810004000L, 0x0102000810004001L, 0x0102000810004080L, 0x0102000810004081L,
        0x0102000810200000L, 0x0102000810200001L, 0x0102000810200080L, 0x0102000810200081L,
        0x0102000810204000L, 0x0102000810204001L, 0x0102000810204080L, 0x0102000810204081L,
        0x0102040000000000L, 0x0102040000000001L, 0x0102040000000080L, 0x0102040000000081L,
        0x0102040000004000L, 0x0102040000004001L, 0x0102040000004080L, 0x0102040000004081L,
        0x0102040000200000L, 0x0102040000200001L, 0x0102040000200080L, 0x0102040000200081L,
        0x0102040000204000L, 0x0102040000204001L, 0x0102040000204080L, 0x0102040000204081L,
        0x0102040010000000L, 0x0102040010000001L, 0x0102040010000080L, 0x0102040010000081L,
        0x0102040010004000L, 0x0102040010004001L, 0x0102040010004080L, 0x0102040010004081L,
        0x0102040010200000L, 0x0102040010200001L, 0x0102040010200080L, 0x0102040010200081L,
        0x0102040010204000L, 0x0102040010204001L, 0x0102040010204080L, 0x0102040010204081L,
        0x0102040800000000L, 0x0102040800000001L, 0x0102040800000080L, 0x0102040800000081L,
        0x0102040800004000L, 0x0102040800004001L, 0x0102040800004080L, 0x0102040800004081L,
        0x0102040800200000L, 0x0102040800200001L, 0x0102040800200080L, 0x0102040800200081L,
        0x0102040800204000L, 0x0102040800204001L, 0x0102040800204080L, 0x0102040800204081L,
        0x0102040810000000L, 0x0102040810000001L, 0x0102040810000080L, 0x0102040810000081L,
        0x0102040810004000L, 0x0102040810004001L, 0x0102040810004080L, 0x0102040810004081L,
        0x0102040810200000L, 0x0102040810200001L, 0x0102040810200080L, 0x0102040810200081L,
        0x0102040810204000L, 0x0102040810204001L, 0x0102040810204080L, 0x0102040810204081L
    };

    // For toString(); must have length 64
    private static final String ZEROES = "0000000000000000000000000000000000000000000000000000000000000000";

    final static byte[] bitLengths =
    {
        0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
        5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
    };

    // TODO make m fixed for the LongArray, and hence compute T once and for all

    private long[] m_ints;

    public LongArray(int intLen)
    {
        m_ints = new long[intLen];
    }

    public LongArray(long[] ints)
    {
        m_ints = ints;
    }

    public LongArray(BigInteger bigInt)
    {
        if (bigInt == null || bigInt.signum() < 0)
        {
            throw new IllegalArgumentException("invalid F2m field value");
        }

        if (bigInt.signum() == 0)
        {
            m_ints = new long[] { 0L };
            return;
        }

        byte[] barr = bigInt.toByteArray();
        int barrLen = barr.length;
        int barrStart = 0;
        if (barr[0] == 0)
        {
            // First byte is 0 to enforce highest (=sign) bit is zero.
            // In this case ignore barr[0].
            barrLen--;
            barrStart = 1;
        }
        int intLen = (barrLen + 7) / 8;
        m_ints = new long[intLen];

        int iarrJ = intLen - 1;
        int rem = barrLen % 8 + barrStart;
        long temp = 0;
        int barrI = barrStart;
        if (barrStart < rem)
        {
            for (; barrI < rem; barrI++)
            {
                temp <<= 8;
                int barrBarrI = barr[barrI] & 0xFF;
                temp |= barrBarrI;
            }
            m_ints[iarrJ--] = temp;
        }

        for (; iarrJ >= 0; iarrJ--)
        {
            temp = 0;
            for (int i = 0; i < 8; i++)
            {
                temp <<= 8;
                int barrBarrI = barr[barrI++] & 0xFF;
                temp |= barrBarrI;
            }
            m_ints[iarrJ] = temp;
        }
    }

    public boolean isZero()
    {
        long[] a = m_ints;
        for (int i = 0; i < a.length; ++i)
        {
            if (a[i] != 0L)
            {
                return false;
            }
        }
        return true;
    }

    public int getUsedLength()
    {
        return getUsedLengthFrom(m_ints.length);
    }

    public int getUsedLengthFrom(int from)
    {
        long[] a = m_ints;
        from = Math.min(from, a.length);

        if (from < 1)
        {
            return 0;
        }

        // Check if first element will act as sentinel
        if (a[0] != 0)
        {
            while (a[--from] == 0)
            {
            }
            return from + 1;
        }

        do
        {
            if (a[--from] != 0)
            {
                return from + 1;
            }
        }
        while (from > 0);

        return 0;
    }

    public int degree()
    {
        int i = m_ints.length;
        long w;
        do
        {
            if (i == 0)
            {
                return 0;
            }
            w = m_ints[--i];
        }
        while (w == 0);

        return (i << 6) + bitLength(w);
    }

    private static int bitLength(long w)
    {
        int u = (int)(w >>> 32), b;
        if (u == 0)
        {
            u = (int)w;
            b = 0;
        }
        else
        {
            b = 32;
        }

        int t = u >>> 16, k;
        if (t == 0)
        {
            t = u >>> 8;
            k = (t == 0) ? bitLengths[u] : 8 + bitLengths[t];
        }
        else
        {
            int v = t >>> 8;
            k = (v == 0) ? 16 + bitLengths[t] : 24 + bitLengths[v];
        }

        return b + k;
    }

    private long[] resizedInts(int newLen)
    {
        long[] newInts = new long[newLen];
        System.arraycopy(m_ints, 0, newInts, 0, Math.min(m_ints.length, newLen));
        return newInts;
    }

    public BigInteger toBigInteger()
    {
        int usedLen = getUsedLength();
        if (usedLen == 0)
        {
            return ECConstants.ZERO;
        }

        long highestInt = m_ints[usedLen - 1];
        byte[] temp = new byte[8];
        int barrI = 0;
        boolean trailingZeroBytesDone = false;
        for (int j = 7; j >= 0; j--)
        {
            byte thisByte = (byte)(highestInt >>> (8 * j));
            if (trailingZeroBytesDone || (thisByte != 0))
            {
                trailingZeroBytesDone = true;
                temp[barrI++] = thisByte;
            }
        }

        int barrLen = 8 * (usedLen - 1) + barrI;
        byte[] barr = new byte[barrLen];
        for (int j = 0; j < barrI; j++)
        {
            barr[j] = temp[j];
        }
        // Highest value int is done now

        for (int iarrJ = usedLen - 2; iarrJ >= 0; iarrJ--)
        {
            long mi = m_ints[iarrJ];
            for (int j = 7; j >= 0; j--)
            {
                barr[barrI++] = (byte)(mi >>> (8 * j));
            }
        }
        return new BigInteger(1, barr);
    }

    private static long shiftLeft(long[] x, int count)
    {
        long prev = 0;
        for (int i = 0; i < count; ++i)
        {
            long next = x[i];
            x[i] = (next << 1) | prev;
            prev = next >>> 63;
        }
        return prev;
    }

    public void addOneShifted(int shift)
    {
        if (shift >= m_ints.length)
        {
            m_ints = resizedInts(shift + 1);
        }

        m_ints[shift] ^= 1;
    }

    private void addShiftedByBits(LongArray other, int bits)
    {
        int words = bits >>> 6;
        int shift = bits & 0x3F;

        if (shift == 0)
        {
            addShiftedByWords(other, words);
            return;
        }

        int otherUsedLen = other.getUsedLength();
        if (otherUsedLen == 0)
        {
            return;
        }

        int minLen = otherUsedLen + words + 1;
        if (minLen > m_ints.length)
        {
            m_ints = resizedInts(minLen);
        }

        int shiftInv = 64 - shift;
        long prev = 0;
        for (int i = 0; i < otherUsedLen; ++i)
        {
            long next = other.m_ints[i];
            m_ints[i + words] ^= (next << shift) | prev;
            prev = next >>> shiftInv;
        }
        m_ints[otherUsedLen + words] ^= prev;
    }

    private static long addShiftedByBits(long[] x, long[] y, int count, int shift)
    {
        int shiftInv = 64 - shift;
        long prev = 0;
        for (int i = 0; i < count; ++i)
        {
            long next = y[i];
            x[i] ^= (next << shift) | prev;
            prev = next >>> shiftInv;
        }
        return prev;
    }

    private static long addShiftedByBits(long[] x, int xOff, long[] y, int yOff, int count, int shift)
    {
        int shiftInv = 64 - shift;
        long prev = 0;
        for (int i = 0; i < count; ++i)
        {
            long next = y[yOff + i];
            x[xOff + i] ^= (next << shift) | prev;
            prev = next >>> shiftInv;
        }
        return prev;
    }

    public void addShiftedByWords(LongArray other, int words)
    {
        int otherUsedLen = other.getUsedLength();
        if (otherUsedLen == 0)
        {
            return;
        }

        int minLen = otherUsedLen + words;
        if (minLen > m_ints.length)
        {
            m_ints = resizedInts(minLen);
        }

        for (int i = 0; i < otherUsedLen; i++)
        {
            m_ints[words + i] ^= other.m_ints[i];
        }
    }

    private static void addShiftedByWords(long[] x, int xOff, long[] y, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            x[xOff + i] ^= y[i];
        }
    }

    private static void add(long[] x, long[] y, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            x[i] ^= y[i];
        }
    }

    private static void distribute(long[] x, int dst1, int dst2, int src, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            long v = x[src + i];
            x[dst1 + i] ^= v;
            x[dst2 + i] ^= v;
        }
    }

    public int getLength()
    {
        return m_ints.length;
    }

    public void flipWord(int bit, long word)
    {
        int len = m_ints.length;
        int n = bit >>> 6;
        if (n < len)
        {
            int shift = bit & 0x3F;
            if (shift == 0)
            {
                m_ints[n] ^= word;
            }
            else
            {
                m_ints[n] ^= word << shift;
                if (++n < len)
                {
                    m_ints[n] ^= word >>> (64 - shift);
                }
            }
        }
    }

    public long getWord(int bit)
    {
        int len = m_ints.length;
        int n = bit >>> 6;
        if (n >= len)
        {
            return 0;
        }
        int shift = bit & 0x3F;
        if (shift == 0)
        {
            return m_ints[n];
        }
        long result = m_ints[n] >>> shift;
        if (++n < len)
        {
            result |= m_ints[n] << (64 - shift);
        }
        return result;
    }

    public boolean testBitZero()
    {
        return m_ints.length > 0 && (m_ints[0] & 1L) != 0;
    }

    public boolean testBit(int n)
    {
        // theInt = n / 64
        int theInt = n >>> 6;
        // theBit = n % 64
        int theBit = n & 0x3F;
        long tester = 1L << theBit;
        return (m_ints[theInt] & tester) != 0;
    }

    public void flipBit(int n)
    {
        // theInt = n / 64
        int theInt = n >>> 6;
        // theBit = n % 64
        int theBit = n & 0x3F;
        long flipper = 1L << theBit;
        m_ints[theInt] ^= flipper;
    }

    public void setBit(int n)
    {
        // theInt = n / 64
        int theInt = n >>> 6;
        // theBit = n % 64
        int theBit = n & 0x3F;
        long setter = 1L << theBit;
        m_ints[theInt] |= setter;
    }

    public void clearBit(int n)
    {
        // theInt = n / 64
        int theInt = n >>> 6;
        // theBit = n % 64
        int theBit = n & 0x3F;
        long setter = 1L << theBit;
        m_ints[theInt] &= ~setter;
    }

    public LongArray modMultiply(LongArray other, int m, int[] ks)
    {
        int aLen = getUsedLength();
        if (aLen == 0)
        {
            return new LongArray(1);
        }

        int bLen = other.getUsedLength();
        if (bLen == 0)
        {
            return new LongArray(1);
        }

        LongArray A = this, B = other;
        if (aLen > bLen)
        {
            A = other; B = this;
            int tmp = aLen; aLen = bLen; bLen = tmp;
        }

        if (aLen == 1)
        {
            long a = A.m_ints[0];
            long[] b = B.m_ints;
            long[] c = new long[aLen + bLen];
            if ((a & 1L) != 0L)
            {
                add(c, b, bLen);
            }
            int k = 1;
            while ((a >>>= 1) != 0)
            {
                if ((a & 1L) != 0L)
                {
                    addShiftedByBits(c, b, bLen, k);
                }
                ++k;
            }
            LongArray p = new LongArray(c);
            p.reduce(m, ks);
            return p;
        }

        int width, shifts, top;

        // NOTE: These work, but require too many shifts to be competitive
//        width = 1; shifts = 64; top = 64;
//        width = 2; shifts = 32; top = 64;
//        width = 3; shifts = 21; top = 63;

        if (aLen <= 16)
        {
            width = 4; shifts = 16; top = 64;
        }
        else if (aLen <= 32)
        {
            width = 5; shifts = 13; top = 65;
        }
        else if (aLen <= 128)
        {
            width = 7; shifts = 9; top = 63;
        }
        else
        {
            width = 8; shifts = 8; top = 64;
        }

        int actualShifts = shifts;
        if (top >= 64)
        {
            --actualShifts;
        }

        int bExt = bLen;
        if ((B.m_ints[bLen - 1] >>> (64 - actualShifts)) != 0L)
        {
            ++bExt;
        }

        int cLen = bExt + aLen;

        long[] c = new long[cLen << width];
        System.arraycopy(B.m_ints, 0, c, 0, bLen);
        switch (width)
        {
        case 3:
            interleave3(A.m_ints, 0, c, bExt, aLen);
            break;
        case 5:
            interleave5(A.m_ints, 0, c, bExt, aLen);
            break;
        case 7:
            interleave7(A.m_ints, 0, c, bExt, aLen);
            break;
        default:
            interleave2_n(A.m_ints, 0, c, bExt, aLen, bitLengths[width] - 1);
            break;
        }

        int[] ci = new int[1 << width];
        for (int i = 1; i < ci.length; ++i)
        {
            ci[i] = ci[i - 1] + cLen;
        }

        int MASK = (1 << width) - 1;

        int k = 0;
        for (;;)
        {
            for (int aPos = 0; aPos < aLen; ++aPos)
            {
                int index = (int)(c[bExt + aPos] >>> k) & MASK;
                if (index != 0)
                {
                    addShiftedByWords(c, aPos + ci[index], c, bExt);
                }
            }

            if ((k += width) >= top)
            {
                if (k >= 64)
                {
                    break;
                }

                // NOTE: This adjustment allows to process the top bit for widths 3, 7
                k = 64 - width;
                MASK &= MASK << (top - k);
            }

            shiftLeft(c, bExt);
        }

        int ciPos = ci.length, pow2 = ciPos >>> 1;
        int offset = top;
        while (--ciPos > 1)
        {
            if (ciPos == pow2)
            {
                offset -= shifts;
                addShiftedByBits(c, ci[1], c, ci[pow2], cLen, offset);
                pow2 >>>= 1;
            }
            else
            {
                distribute(c, ci[pow2], ci[ciPos - pow2], ci[ciPos], cLen);
            }
        }

        // TODO reduce in place to avoid extra copying
        LongArray p = new LongArray(cLen);
        System.arraycopy(c, ci[1], p.m_ints, 0, cLen);
        p.reduce(m, ks);
        return p;
    }

//    private static void deInterleave(long[] x, int xOff, long[] z, int zOff, int count, int rounds)
//    {
//        for (int i = 0; i < count; ++i)
//        {
//            z[zOff + i] = deInterleave(x[zOff + i], rounds);
//        }
//    }
//
//    private static long deInterleave(long x, int rounds)
//    {
//        while (--rounds >= 0)
//        {
//            x = deInterleave32(x & DEINTERLEAVE_MASK) | (deInterleave32((x >>> 1) & DEINTERLEAVE_MASK) << 32);
//        }
//        return x;
//    }
//
//    private static long deInterleave32(long x)
//    {
//        x = (x | (x >>> 1)) & 0x3333333333333333L;
//        x = (x | (x >>> 2)) & 0x0F0F0F0F0F0F0F0FL;
//        x = (x | (x >>> 4)) & 0x00FF00FF00FF00FFL;
//        x = (x | (x >>> 8)) & 0x0000FFFF0000FFFFL;
//        x = (x | (x >>> 16)) & 0x00000000FFFFFFFFL;
//        return x;
//    }

    private void reduce(int m, int[] ks)
    {
        int len = getUsedLength();

        int mLen = (m + 63) >>> 6;
        if (len < mLen)
        {
            return;
        }

        int kMax = ks[ks.length - 1];
        int wordWiseLimit = Math.max(m, kMax + 64);

        int numBits = len << 6;

        if (numBits > wordWiseLimit)
        {
            reduceWordWise(len, wordWiseLimit, m, ks);
            numBits = wordWiseLimit;
        }

        if (numBits > m)
        {
            reduceBitWise(numBits, m, ks);
        }

        if (len > mLen)
        {
            m_ints = resizedInts(mLen);
        }
    }

    private void reduceBitWise(int bitlength, int m, int[] ks)
    {
        while (--bitlength >= m)
        {
            if (testBit(bitlength))
            {
                clearBit(bitlength);
                int bit = bitlength - m;
                flipBit(bit);
                int j = ks.length;
                while (--j >= 0)
                {
                    flipBit(ks[j] + bit);
                }
            }
        }
    }

    private void reduceWordWise(int len, int toBit, int m, int[] ks)
    {
        int toPos = toBit >>> 6;

        while (--len > toPos)
        {
            long word = m_ints[len];
            if (word != 0)
            {
                m_ints[len] = 0;
                reduceWord(word, (len << 6), m, ks);
            }
        }

        int partial = toBit & 0x3F;
        long word = m_ints[toPos] >>> partial;
        if (word != 0)
        {
            m_ints[toPos] ^= word << partial;
            reduceWord(word, toBit, m, ks);
        }
    }

    private void reduceWord(long word, int bit, int m, int[] ks)
    {
        int offset = bit - m;
        flipWord(offset, word);
        int j = ks.length;
        while (--j >= 0)
        {
            flipWord(offset + ks[j], word);
        }
    }

    public LongArray modSquare(int m, int[] ks)
    {
        int len = getUsedLength();
        if (len == 0)
        {
            return this;
        }

        int _2len = len << 1;
        long[] r = new long[_2len];

        int pos = 0;
        while (pos < _2len)
        {
            long mi = m_ints[pos >>> 1];
            r[pos++] = interleave2_32to64((int)mi);
            r[pos++] = interleave2_32to64((int)(mi >>> 32));
        }

        LongArray p = new LongArray(r);
        p.reduce(m, ks);
        return p;
    }

    private static void interleave3(long[] x, int xOff, long[] z, int zOff, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            z[zOff + i] = interleave3(x[xOff + i]);
        }
    }

    private static long interleave3(long x)
    {
        long z = x & (1L << 63);
        return z
            | interleave3_21to63((int)x & 0x1FFFFF)
            | interleave3_21to63((int)(x >>> 21) & 0x1FFFFF) << 1
            | interleave3_21to63((int)(x >>> 42) & 0x1FFFFF) << 2;

//        int zPos = 0, wPos = 0, xPos = 0;
//        for (;;)
//        {
//            z |= ((x >>> xPos) & 1L) << zPos;
//            if (++zPos == 63)
//            {
//                String sz2 = Long.toBinaryString(z);
//                return z;
//            }
//            if ((xPos += 21) >= 63)
//            {
//                xPos = ++wPos;
//            }
//        }
    }

    private static long interleave3_21to63(int x)
    {
        int r00 = INTERLEAVE3_TABLE[x & 0x7F];
        int r21 = INTERLEAVE3_TABLE[(x >>> 7) & 0x7F];
        int r42 = INTERLEAVE3_TABLE[x >>> 14];
        return (r42 & 0xFFFFFFFFL) << 42 | (r21 & 0xFFFFFFFFL) << 21 | (r00 & 0xFFFFFFFFL);
    }

    private static void interleave5(long[] x, int xOff, long[] z, int zOff, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            z[zOff + i] = interleave5(x[xOff + i]);
        }
    }

    private static long interleave5(long x)
    {
        return interleave3_13to65((int)x & 0x1FFF)
            | interleave3_13to65((int)(x >>> 13) & 0x1FFF) << 1
            | interleave3_13to65((int)(x >>> 26) & 0x1FFF) << 2
            | interleave3_13to65((int)(x >>> 39) & 0x1FFF) << 3
            | interleave3_13to65((int)(x >>> 52) & 0x1FFF) << 4;

//        long z = 0;
//        int zPos = 0, wPos = 0, xPos = 0;
//        for (;;)
//        {
//            z |= ((x >>> xPos) & 1L) << zPos;
//            if (++zPos == 64)
//            {
//                return z;
//            }
//            if ((xPos += 13) >= 64)
//            {
//                xPos = ++wPos;
//            }
//        }
    }

    private static long interleave3_13to65(int x)
    {
        int r00 = INTERLEAVE5_TABLE[x & 0x7F];
        int r35 = INTERLEAVE5_TABLE[x >>> 7];
        return (r35 & 0xFFFFFFFFL) << 35 | (r00 & 0xFFFFFFFFL);
    }

    private static void interleave7(long[] x, int xOff, long[] z, int zOff, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            z[zOff + i] = interleave7(x[xOff + i]);
        }
    }

    private static long interleave7(long x)
    {
        long z = x & (1L << 63);
        return z
            | INTERLEAVE7_TABLE[(int)x & 0x1FF]
            | INTERLEAVE7_TABLE[(int)(x >>> 9) & 0x1FF] << 1
            | INTERLEAVE7_TABLE[(int)(x >>> 18) & 0x1FF] << 2
            | INTERLEAVE7_TABLE[(int)(x >>> 27) & 0x1FF] << 3
            | INTERLEAVE7_TABLE[(int)(x >>> 36) & 0x1FF] << 4
            | INTERLEAVE7_TABLE[(int)(x >>> 45) & 0x1FF] << 5
            | INTERLEAVE7_TABLE[(int)(x >>> 54) & 0x1FF] << 6;

//        int zPos = 0, wPos = 0, xPos = 0;
//        for (;;)
//        {
//            z |= ((x >>> xPos) & 1L) << zPos;
//            if (++zPos == 63)
//            {
//                return z;
//            }
//            if ((xPos += 9) >= 63)
//            {
//                xPos = ++wPos;
//            }
//        }
    }

    private static void interleave2_n(long[] x, int xOff, long[] z, int zOff, int count, int rounds)
    {
        for (int i = 0; i < count; ++i)
        {
            z[zOff + i] = interleave2_n(x[xOff + i], rounds);
        }
    }

    private static long interleave2_n(long x, int rounds)
    {
        while (rounds > 1)
        {
            rounds -= 2;
            x = interleave4_16to64((int)x & 0xFFFF)
                | interleave4_16to64((int)(x >>> 16) & 0xFFFF) << 1
                | interleave4_16to64((int)(x >>> 32) & 0xFFFF) << 2
                | interleave4_16to64((int)(x >>> 48) & 0xFFFF) << 3;
        }
        if (rounds > 0)
        {
            x = interleave2_32to64((int)x) | interleave2_32to64((int)(x >>> 32)) << 1;
        }
        return x;
    }

    private static long interleave4_16to64(int x)
    {
        int r00 = INTERLEAVE4_TABLE[x & 0xFF];
        int r32 = INTERLEAVE4_TABLE[x >>> 8];
        return (r32 & 0xFFFFFFFFL) << 32 | (r00 & 0xFFFFFFFFL);
    }

    private static long interleave2_32to64(int x)
    {
        int r00 = INTERLEAVE2_TABLE[x & 0xFF] | INTERLEAVE2_TABLE[(x >>> 8) & 0xFF] << 16;
        int r32 = INTERLEAVE2_TABLE[(x >>> 16) & 0xFF] | INTERLEAVE2_TABLE[x >>> 24] << 16;
        return (r32 & 0xFFFFFFFFL) << 32 | (r00 & 0xFFFFFFFFL);
    }

    public LongArray modInverse(int m, int[] ks)
    {
        // Inversion in F2m using the extended Euclidean algorithm
        // Input: A nonzero polynomial a(z) of degree at most m-1
        // Output: a(z)^(-1) mod f(z)

        int uzDegree = degree();
        if (uzDegree == 1)
        {
            return this;
        }

        // u(z) := a(z)
        LongArray uz = (LongArray)clone();

        int t = (m + 63) >>> 6;

        // v(z) := f(z)
        LongArray vz = new LongArray(t);
        vz.setBit(m);
        vz.setBit(0);
        vz.setBit(ks[0]);
        if (ks.length > 1) 
        {
            vz.setBit(ks[1]);
            vz.setBit(ks[2]);
        }

        // g1(z) := 1, g2(z) := 0
        LongArray g1z = new LongArray(t);
        g1z.setBit(0);
        LongArray g2z = new LongArray(t);

        while (uzDegree != 0)
        {
            // j := deg(u(z)) - deg(v(z))
            int j = uzDegree - vz.degree();

            // If j < 0 then: u(z) <-> v(z), g1(z) <-> g2(z), j := -j
            if (j < 0) 
            {
                final LongArray uzCopy = uz;
                uz = vz;
                vz = uzCopy;

                final LongArray g1zCopy = g1z;
                g1z = g2z;
                g2z = g1zCopy;

                j = -j;
            }

            // u(z) := u(z) + z^j * v(z)
            // Note, that no reduction modulo f(z) is required, because
            // deg(u(z) + z^j * v(z)) <= max(deg(u(z)), j + deg(v(z)))
            // = max(deg(u(z)), deg(u(z)) - deg(v(z)) + deg(v(z))
            // = deg(u(z))
            // uz = uz.xor(vz.shiftLeft(j));
            uz.addShiftedByBits(vz, j);
            uzDegree = uz.degree();

            // g1(z) := g1(z) + z^j * g2(z)
//            g1z = g1z.xor(g2z.shiftLeft(j));
            if (uzDegree != 0)
            {
                g1z.addShiftedByBits(g2z, j);
            }
        }
        return g2z;
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof LongArray))
        {
            return false;
        }
        LongArray other = (LongArray) o;
        int usedLen = getUsedLength();
        if (other.getUsedLength() != usedLen)
        {
            return false;
        }
        for (int i = 0; i < usedLen; i++)
        {
            if (m_ints[i] != other.m_ints[i])
            {
                return false;
            }
        }
        return true;
    }

    public int hashCode()
    {
        int usedLen = getUsedLength();
        int hash = 1;
        for (int i = 0; i < usedLen; i++)
        {
            long mi = m_ints[i];
            hash *= 31;
            hash ^= (int)mi;
            hash *= 31;
            hash ^= (int)(mi >>> 32);
        }
        return hash;
    }

    public Object clone()
    {
        return new LongArray(Arrays.clone(m_ints));
    }

    public String toString()
    {
        int i = getUsedLength();
        if (i == 0)
        {
            return "0";
        }

        StringBuffer sb = new StringBuffer(Long.toBinaryString(m_ints[--i]));
        while (--i >= 0)
        {
            String s = Long.toBinaryString(m_ints[i]);

            // Add leading zeroes, except for highest significant word
            int len = s.length();
            if (len < 64)
            {
                sb.append(ZEROES.substring(len));
            }

            sb.append(s);
        }
        return sb.toString();
    }
}