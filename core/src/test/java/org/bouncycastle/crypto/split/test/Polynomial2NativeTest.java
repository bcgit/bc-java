package org.bouncycastle.crypto.split.test;

import java.util.Arrays;

import junit.framework.TestCase;

import org.bouncycastle.crypto.split.GaloisField;
import org.bouncycastle.crypto.split.Polynomial2Native;
import org.junit.Test;

public class Polynomial2NativeTest
    extends TestCase
{
    // Test test vectors for Polynomial 1 (x^^8 + x^^4 + x^^3 + x + 1)

    /*
     * Test vector TV011D_1
     * secret = 74 65 73 74 00
     * random = A8 7B 34 91 B5
     *
     * l = 5
     * m = 2
     * n = 2
     *
     * split1 = DC 1E 47 E5 B5
     * split2 = 3F 93 1B 4D 71
     */


    // Constants for testing
    public static final int[][] TV011D_TV1_P = {
        {Polynomial2Native.gfPow(0x01, 0x00), Polynomial2Native.gfPow(0x01, 0x01)},
        {Polynomial2Native.gfPow(0x02, 0x00), Polynomial2Native.gfPow(0x02, 0x01)}
    };

    public static final int[][] TV011D_TV1_SR = {
        {0x74, 0x65, 0x73, 0x74, 0x00},
        {0xF3, 0xC2, 0x33, 0x81, 0xF5}
    };

    public static final int[][] TV011D_TV1_SPLITS = {
        {0x87, 0xA7, 0x40, 0xF5, 0xF5},
        {0x8F, 0xFC, 0x15, 0x6B, 0xF7}
    };

    public static final int[][] TV011D_TV1_1_2_R = {
        {Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x02, 0x01)), Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x02))}
    };

    public static final int[][] TV011D_TV1_1_2_SPLITS = {
        {0x87, 0xA7, 0x40, 0xF5, 0xF5},
        {0x8F, 0xFC, 0x15, 0x6B, 0xF7}
    };

    public static final int[][] TV011D_TV1_SECRET = {
        {0x74, 0x65, 0x73, 0x74, 0x00}
    };

    /*
     * Test vector TV011D_2
     * secret = 53 41 4D 54 43
     * random = 39 5D 39 6C 87
     *
     * l = 5
     * m = 2
     * n = 4
     *
     * split1 = 6A 1C 74 38 C4
     * split2 = 21 FB 3F 8C 56
     * split3 = 18 A6 06 E0 D1
     * split4 = B7 2E A9 FF 69
     */
    public static final int[][] TV011D_TV2_P = {
        {Polynomial2Native.gfPow(0x01, 0x00), Polynomial2Native.gfPow(0x01, 0x01)},
        {Polynomial2Native.gfPow(0x02, 0x00), Polynomial2Native.gfPow(0x02, 0x01)},
        {Polynomial2Native.gfPow(0x03, 0x00), Polynomial2Native.gfPow(0x03, 0x01)},
        {Polynomial2Native.gfPow(0x04, 0x00), Polynomial2Native.gfPow(0x04, 0x01)}
    };

    public static final int[][] TV011D_TV2_SR = {
        {0x53, 0x41, 0x4D, 0x54, 0x43},
        {0x20, 0x76, 0x08, 0x93, 0x0C}
    };

    public static final int[][] TV011D_TV2_SPLITS = {
        {0x73, 0x37, 0x45, 0xC7, 0x4F},
        {0x13, 0xAD, 0x5D, 0x6F, 0x5B},
        {0x33, 0xDB, 0x55, 0xFC, 0x57},
        {0xD3, 0x84, 0x6D, 0x22, 0x73}
    };

    // Matrices for recombination
    public static final int[][] TV011D_TV2_1_2_R = {
        {Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x01, 0x02)), Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x02))}
    };

    public static final int[][] TV011D_TV2_1_4_R = {
        {Polynomial2Native.gfDiv(0x04, Polynomial2Native.gfAdd(0x01, 0x04)), Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x04))}
    };

    public static final int[][] TV011D_TV2_3_4_R = {
        {Polynomial2Native.gfDiv(0x04, Polynomial2Native.gfAdd(0x03, 0x04)), Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x03, 0x04))}
    };

    // Split shares
    public static final int[][] TV011D_TV2_1_2_SPLITS = {
        {0x73, 0x37, 0x45, 0xC7, 0x4F},
        {0x13, 0xAD, 0x5D, 0x6F, 0x5B}
    };

    public static final int[][] TV011D_TV2_1_4_SPLITS = {
        {0x73, 0x37, 0x45, 0xC7, 0x4F},
        {0xD3, 0x84, 0x6D, 0x22, 0x73}
    };

    public static final int[][] TV011D_TV2_3_4_SPLITS = {
        {0x33, 0xDB, 0x55, 0xFC, 0x57},
        {0xD3, 0x84, 0x6D, 0x22, 0x73}
    };

    public static final int[][] TV011D_TV2_SECRET = {
        {0x53, 0x41, 0x4D, 0x54, 0x43}
    };
    /*
     * Test vector TV011D_3
     * secret = 53 41 4D 54 43
     * random = 8C 15 92 62 5C 4A AF 53 41 45
     *
     * l = 5
     * m = 3
     * n = 4
     *
     * split1 = CA B1 5B A8 47
     * split2 = 02 ED C0 46 C8
     * split3 = 9B 1D D6 BA CC
     * split4 = 14 5D F4 8B 7E
     */

    // Constants for TV3
    public static final int[][] TV011D_TV3_P = {
        {Polynomial2Native.gfPow(0x01, 0x00), Polynomial2Native.gfPow(0x01, 0x01), Polynomial2Native.gfPow(0x01, 0x02)},
        {Polynomial2Native.gfPow(0x02, 0x00), Polynomial2Native.gfPow(0x02, 0x01), Polynomial2Native.gfPow(0x02, 0x02)},
        {Polynomial2Native.gfPow(0x03, 0x00), Polynomial2Native.gfPow(0x03, 0x01), Polynomial2Native.gfPow(0x03, 0x02)},
        {Polynomial2Native.gfPow(0x04, 0x00), Polynomial2Native.gfPow(0x04, 0x01), Polynomial2Native.gfPow(0x04, 0x02)}
    };

    public static final int[][] TV011D_TV3_SR = {
        {0x53, 0x41, 0x4D, 0x54, 0x43},
        {0x8C, 0x92, 0x5C, 0xAF, 0x41},
        {0x15, 0x62, 0x4A, 0x53, 0x45}
    };

    public static final int[][] TV011D_TV3_SPLITS = {
        {0xCA, 0xB1, 0x5B, 0xA8, 0x47},
        {0x02, 0xED, 0xC0, 0x46, 0xC8},
        {0x9B, 0x1D, 0xD6, 0xBA, 0xCC},
        {0x14, 0x5D, 0xF4, 0x8B, 0x7E}
    };

    // Matrices for recombination
    public static final int[][] TV011D_TV3_1_2_3_R = {
        {
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x01, 0x02)), Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x01, 0x03))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x02)), Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x02, 0x03))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x03)), Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x02, 0x03))})
        }
    };

    public static final int[][] TV011D_TV3_1_2_4_R = {
        {
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x01, 0x02)), Polynomial2Native.gfDiv(0x04, Polynomial2Native.gfAdd(0x01, 0x04))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x02)), Polynomial2Native.gfDiv(0x04, Polynomial2Native.gfAdd(0x02, 0x04))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x04)), Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x02, 0x04))})
        }
    };

    public static final int[][] TV011D_TV3_1_3_4_R = {
        {
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x01, 0x03)), Polynomial2Native.gfDiv(0x04, Polynomial2Native.gfAdd(0x01, 0x04))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x03)), Polynomial2Native.gfDiv(0x04, Polynomial2Native.gfAdd(0x03, 0x04))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x04)), Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x03, 0x04))})
        }
    };

    // Split shares
    public static final int[][] TV011D_TV3_1_2_3_SPLITS = {
        {0xCA, 0xB1, 0x5B, 0xA8, 0x47},
        {0x02, 0xED, 0xC0, 0x46, 0xC8},
        {0x9B, 0x1D, 0xD6, 0xBA, 0xCC}
    };

    public static final int[][] TV011D_TV3_1_2_4_SPLITS = {
        {0xCA, 0xB1, 0x5B, 0xA8, 0x47},
        {0x02, 0xED, 0xC0, 0x46, 0xC8},
        {0x14, 0x5D, 0xF4, 0x8B, 0x7E}
    };

    public static final int[][] TV011D_TV3_1_3_4_SPLITS = {
        {0xCA, 0xB1, 0x5B, 0xA8, 0x47},
        {0x9B, 0x1D, 0xD6, 0xBA, 0xCC},
        {0x14, 0x5D, 0xF4, 0x8B, 0x7E}
    };

    // Secret to recover
    public static final int[][] TV011D_TV3_SECRET = {
        {0x53, 0x41, 0x4D, 0x54, 0x43}
    };

    /*
     * Test vector TV011D_4
     * secret = 53 41 4D 54 43
     * random = 72 B0 88 3C 96 B9 CB B9 CB B2 82 66 F3 79 FA
     *
     * l = 5
     * m = 4
     * n = 4
     *
     * split1 = 19 52 F4 02 33
     * split2 = 79 FA 0E 08 C2
     * split3 = 24 58 37 17 94
     * split4 = F4 45 A9 D6 07
     */
    // Constants for TV4
    public static final int[][] TV011D_TV4_P = {
        {Polynomial2Native.gfPow(0x01, 0x00), Polynomial2Native.gfPow(0x01, 0x01), Polynomial2Native.gfPow(0x01, 0x02), Polynomial2Native.gfPow(0x01, 0x03)},
        {Polynomial2Native.gfPow(0x02, 0x00), Polynomial2Native.gfPow(0x02, 0x01), Polynomial2Native.gfPow(0x02, 0x02), Polynomial2Native.gfPow(0x02, 0x03)},
        {Polynomial2Native.gfPow(0x03, 0x00), Polynomial2Native.gfPow(0x03, 0x01), Polynomial2Native.gfPow(0x03, 0x02), Polynomial2Native.gfPow(0x03, 0x03)},
        {Polynomial2Native.gfPow(0x04, 0x00), Polynomial2Native.gfPow(0x04, 0x01), Polynomial2Native.gfPow(0x04, 0x02), Polynomial2Native.gfPow(0x04, 0x03)}
    };

    public static final int[][] TV011D_TV4_SR = {
        {0x53, 0x41, 0x4D, 0x54, 0x43},
        {0x72, 0x3C, 0xCB, 0xB2, 0xF3},
        {0xB0, 0x96, 0xB9, 0x82, 0x79},
        {0x88, 0xB9, 0xCB, 0x66, 0xFA}
    };

    public static final int[][] TV011D_TV4_SPLITS = {
        {0x19, 0x52, 0xF4, 0x02, 0x33},
        {0x79, 0xFA, 0x0E, 0x08, 0xC2},
        {0x24, 0x58, 0x37, 0x17, 0x94},
        {0xF4, 0x45, 0xA9, 0xD6, 0x07}
    };

    // Matrices for recombination
    public static final int[][] TV011D_TV4_1_2_3_4_R = {
        {
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x01, 0x02)), Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x01, 0x03)), Polynomial2Native.gfDiv(0x04, Polynomial2Native.gfAdd(0x01, 0x04))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x02)), Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x02, 0x03)), Polynomial2Native.gfDiv(0x04, Polynomial2Native.gfAdd(0x02, 0x04))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x03)), Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x02, 0x03)), Polynomial2Native.gfDiv(0x04, Polynomial2Native.gfAdd(0x03, 0x04))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x04)), Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x02, 0x04)), Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x03, 0x04))})
        }
    };

    public static final int[][] TV011D_TV4_1_2_3_4_SPLITS = {
        {0x19, 0x52, 0xF4, 0x02, 0x33},
        {0x79, 0xFA, 0x0E, 0x08, 0xC2},
        {0x24, 0x58, 0x37, 0x17, 0x94},
        {0xF4, 0x45, 0xA9, 0xD6, 0x07}
    };

    // Secret to recover
    public static final int[][] TV011D_TV4_SECRET = {
        {0x53, 0x41, 0x4D, 0x54, 0x43}
    };


    /*
     * Test vector TV011D_5
     * secret = 54 65 73 74 20 44 61 74 61
     * random = AF FD 2B 0B FA 34 33 63 9C
     *
     * l = 9
     * m = 2
     * n = 9
     *
     * split1 = FB 98 58 7F DA 70 52 17 FD
     * split2 = 17 82 25 62 C9 2C 07 B2 44
     * split3 = B8 7F 0E 69 33 18 34 D1 D8
     * split4 = D2 B6 DF 58 EF 94 AD E5 2B
     * split5 = 7D 4B F4 53 15 A0 9E 86 B7
     * split6 = 91 51 89 4E 06 FC CB 23 0E
     * split7 = 3E AC A2 45 FC C8 F8 40 92
     * split8 = 45 DE 36 2C A3 F9 E4 4B F5
     * split9 = EA 23 1D 27 59 CD D7 28 69
     */
    // Constants for TV5
    public static final int[][] TV011D_TV5_P = {
        {Polynomial2Native.gfPow(0x01, 0x00), Polynomial2Native.gfPow(0x01, 0x01)},
        {Polynomial2Native.gfPow(0x02, 0x00), Polynomial2Native.gfPow(0x02, 0x01)},
        {Polynomial2Native.gfPow(0x03, 0x00), Polynomial2Native.gfPow(0x03, 0x01)},
        {Polynomial2Native.gfPow(0x04, 0x00), Polynomial2Native.gfPow(0x04, 0x01)},
        {Polynomial2Native.gfPow(0x05, 0x00), Polynomial2Native.gfPow(0x05, 0x01)},
        {Polynomial2Native.gfPow(0x06, 0x00), Polynomial2Native.gfPow(0x06, 0x01)},
        {Polynomial2Native.gfPow(0x07, 0x00), Polynomial2Native.gfPow(0x07, 0x01)},
        {Polynomial2Native.gfPow(0x08, 0x00), Polynomial2Native.gfPow(0x08, 0x01)},
        {Polynomial2Native.gfPow(0x09, 0x00), Polynomial2Native.gfPow(0x09, 0x01)}
    };

    public static final int[][] TV011D_TV5_SR = {
        {0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61},
        {0xAF, 0xFD, 0x2B, 0x0B, 0xFA, 0x34, 0x33, 0x63, 0x9C}
    };

    public static final int[][] TV011D_TV5_SPLITS = {
        {0xFB, 0x98, 0x58, 0x7F, 0xDA, 0x70, 0x52, 0x17, 0xFD},
        {0x17, 0x82, 0x25, 0x62, 0xC9, 0x2C, 0x07, 0xB2, 0x44},
        {0xB8, 0x7F, 0x0E, 0x69, 0x33, 0x18, 0x34, 0xD1, 0xD8},
        {0xD2, 0xB6, 0xDF, 0x58, 0xEF, 0x94, 0xAD, 0xE5, 0x2B},
        {0x7D, 0x4B, 0xF4, 0x53, 0x15, 0xA0, 0x9E, 0x86, 0xB7},
        {0x91, 0x51, 0x89, 0x4E, 0x06, 0xFC, 0xCB, 0x23, 0x0E},
        {0x3E, 0xAC, 0xA2, 0x45, 0xFC, 0xC8, 0xF8, 0x40, 0x92},
        {0x45, 0xDE, 0x36, 0x2C, 0xA3, 0xF9, 0xE4, 0x4B, 0xF5},
        {0xEA, 0x23, 0x1D, 0x27, 0x59, 0xCD, 0xD7, 0x28, 0x69}
    };

    // Matrices for recombination
    public static final int[][] TV011D_TV5_1_2_R = {
        {Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x01, 0x02)), Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x02))}
    };

    public static final int[][] TV011D_TV5_8_9_R = {
        {Polynomial2Native.gfDiv(0x09, Polynomial2Native.gfAdd(0x08, 0x09)), Polynomial2Native.gfDiv(0x08, Polynomial2Native.gfAdd(0x08, 0x09))}
    };

    public static final int[][] TV011D_TV5_1_2_SPLITS = {
        {0xFB, 0x98, 0x58, 0x7F, 0xDA, 0x70, 0x52, 0x17, 0xFD},
        {0x17, 0x82, 0x25, 0x62, 0xC9, 0x2C, 0x07, 0xB2, 0x44}
    };

    public static final int[][] TV011D_TV5_8_9_SPLITS = {
        {0x45, 0xDE, 0x36, 0x2C, 0xA3, 0xF9, 0xE4, 0x4B, 0xF5},
        {0xEA, 0x23, 0x1D, 0x27, 0x59, 0xCD, 0xD7, 0x28, 0x69}
    };

    // Secret to recover
    public static final int[][] TV011D_TV5_SECRET = {
        {0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61}
    };


    /*
     * Test vector TV011D_6
     * secret = 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
     * random = 02 4A 89 AC 96 8C 98 65 77 FE B0 24 11 6B 94 F6 54 DD DE 20 9C 3C C3 E4 48 88 4D 31 F8 C8
     *
     * l = 15
     * m = 3
     * n = 5
     *
     * split1 = 49 27 19 F9 8C 92 7D 6A 80 F4 AB 2B CD 72 3F
     * split2 = 30 87 38 A0 34 EB 94 C2 F2 2B DE 20 87 50 E5
     * split3 = 78 A2 22 5D BD 7F EE A0 7B D5 7E 07 47 2C D5
     * split4 = DD 0E 49 40 9F 86 BD B9 15 6F A6 C1 58 10 D4
     * split5 = 95 2B 53 BD 16 12 C7 DB 9C 91 06 E6 98 6C E4
     */
    private static final int[][] TV011D_TV6_P = {
        {Polynomial2Native.gfPow(0x01, 0x00), Polynomial2Native.gfPow(0x01, 0x01), Polynomial2Native.gfPow(0x01, 0x02)},
        {Polynomial2Native.gfPow(0x02, 0x00), Polynomial2Native.gfPow(0x02, 0x01), Polynomial2Native.gfPow(0x02, 0x02)},
        {Polynomial2Native.gfPow(0x03, 0x00), Polynomial2Native.gfPow(0x03, 0x01), Polynomial2Native.gfPow(0x03, 0x02)},
        {Polynomial2Native.gfPow(0x04, 0x00), Polynomial2Native.gfPow(0x04, 0x01), Polynomial2Native.gfPow(0x04, 0x02)},
        {Polynomial2Native.gfPow(0x05, 0x00), Polynomial2Native.gfPow(0x05, 0x01), Polynomial2Native.gfPow(0x05, 0x02)}
    };

    private static final int[][] TV011D_TV6_SR = {
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
        {0x02, 0x89, 0x96, 0x98, 0x77, 0xB0, 0x11, 0x94, 0x54, 0xDE, 0x9C, 0xC3, 0x48, 0x4D, 0xF8},
        {0x4A, 0xAC, 0x8C, 0x65, 0xFE, 0x24, 0x6B, 0xF6, 0xDD, 0x20, 0x3C, 0xE4, 0x88, 0x31, 0xC8}
    };

    private static final int[][] TV011D_TV6_SPLITS = {
        {0x49, 0x27, 0x19, 0xF9, 0x8C, 0x92, 0x7D, 0x6A, 0x80, 0xF4, 0xAB, 0x2B, 0xCD, 0x72, 0x3F},
        {0x30, 0x87, 0x38, 0xA0, 0x34, 0xEB, 0x94, 0xC2, 0xF2, 0x2B, 0xDE, 0x20, 0x87, 0x50, 0xE5},
        {0x78, 0xA2, 0x22, 0x5D, 0xBD, 0x7F, 0xEE, 0xA0, 0x7B, 0xD5, 0x7E, 0x07, 0x47, 0x2C, 0xD5},
        {0xDD, 0x0E, 0x49, 0x40, 0x9F, 0x86, 0xBD, 0xB9, 0x15, 0x6F, 0xA6, 0xC1, 0x58, 0x10, 0xD4},
        {0x95, 0x2B, 0x53, 0xBD, 0x16, 0x12, 0xC7, 0xDB, 0x9C, 0x91, 0x06, 0xE6, 0x98, 0x6C, 0xE4}
    };

    private static final int[][] TV011D_TV6_1_2_3_R = {
        {
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x01, 0x02)), Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x01, 0x03))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x02)), Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x02, 0x03))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x01, Polynomial2Native.gfAdd(0x01, 0x03)), Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x02, 0x03))})
        }
    };

    private static final int[][] TV011D_TV6_2_3_4_R = {
        {
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x02, 0x03)), Polynomial2Native.gfDiv(0x04, Polynomial2Native.gfAdd(0x02, 0x04))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x02, 0x03)), Polynomial2Native.gfDiv(0x04, Polynomial2Native.gfAdd(0x03, 0x04))}),
            Polynomial2Native.gfProd(new int[]{Polynomial2Native.gfDiv(0x02, Polynomial2Native.gfAdd(0x02, 0x04)), Polynomial2Native.gfDiv(0x03, Polynomial2Native.gfAdd(0x03, 0x04))})
        }
    };

    private static final int[][] TV011D_TV6_1_2_3_SPLITS = {
        {0x49, 0x27, 0x19, 0xF9, 0x8C, 0x92, 0x7D, 0x6A, 0x80, 0xF4, 0xAB, 0x2B, 0xCD, 0x72, 0x3F},
        {0x30, 0x87, 0x38, 0xA0, 0x34, 0xEB, 0x94, 0xC2, 0xF2, 0x2B, 0xDE, 0x20, 0x87, 0x50, 0xE5},
        {0x78, 0xA2, 0x22, 0x5D, 0xBD, 0x7F, 0xEE, 0xA0, 0x7B, 0xD5, 0x7E, 0x07, 0x47, 0x2C, 0xD5}
    };

    private static final int[][] TV011D_TV6_2_3_4_SPLITS = {
        {0x30, 0x87, 0x38, 0xA0, 0x34, 0xEB, 0x94, 0xC2, 0xF2, 0x2B, 0xDE, 0x20, 0x87, 0x50, 0xE5},
        {0x78, 0xA2, 0x22, 0x5D, 0xBD, 0x7F, 0xEE, 0xA0, 0x7B, 0xD5, 0x7E, 0x07, 0x47, 0x2C, 0xD5},
        {0xDD, 0x0E, 0x49, 0x40, 0x9F, 0x86, 0xBD, 0xB9, 0x15, 0x6F, 0xA6, 0xC1, 0x58, 0x10, 0xD4}
    };

    private static final int[][] TV011D_TV6_SECRET = {
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
    };

    public static void main(String[] args)
    {
        Polynomial2NativeTest test = new Polynomial2NativeTest();
        test.performTest();
    }

    public void performTest()
    {
        testMatrixMultiplication(TV011D_TV1_P, TV011D_TV1_SR, TV011D_TV1_SPLITS);
        testRecombine(TV011D_TV1_1_2_R, TV011D_TV1_1_2_SPLITS, TV011D_TV1_SECRET);
        testMatrixMultiplication(TV011D_TV2_P, TV011D_TV2_SR, TV011D_TV2_SPLITS);
        testRecombine(TV011D_TV2_1_2_R, TV011D_TV2_1_2_SPLITS, TV011D_TV2_SECRET);
        testRecombine(TV011D_TV2_1_4_R, TV011D_TV2_1_4_SPLITS, TV011D_TV2_SECRET);
        testRecombine(TV011D_TV2_3_4_R, TV011D_TV2_3_4_SPLITS, TV011D_TV2_SECRET);
        testMatrixMultiplication(TV011D_TV3_P, TV011D_TV3_SR, TV011D_TV3_SPLITS);
        testRecombine(TV011D_TV3_1_2_3_R, TV011D_TV3_1_2_3_SPLITS, TV011D_TV3_SECRET);
        testRecombine(TV011D_TV3_1_2_4_R, TV011D_TV3_1_2_4_SPLITS, TV011D_TV3_SECRET);
        testRecombine(TV011D_TV3_1_3_4_R, TV011D_TV3_1_3_4_SPLITS, TV011D_TV3_SECRET);
        testMatrixMultiplication(TV011D_TV4_P, TV011D_TV4_SR, TV011D_TV4_SPLITS);
        testRecombine(TV011D_TV4_1_2_3_4_R, TV011D_TV4_1_2_3_4_SPLITS, TV011D_TV4_SECRET);
        testMatrixMultiplication(TV011D_TV5_P, TV011D_TV5_SR, TV011D_TV5_SPLITS);
        testRecombine(TV011D_TV5_1_2_R, TV011D_TV5_1_2_SPLITS, TV011D_TV5_SECRET);
        testRecombine(TV011D_TV5_8_9_R, TV011D_TV5_8_9_SPLITS, TV011D_TV5_SECRET);
        testMatrixMultiplication(TV011D_TV6_P, TV011D_TV6_SR, TV011D_TV6_SPLITS);
        testRecombine(TV011D_TV6_1_2_3_R, TV011D_TV6_1_2_3_SPLITS, TV011D_TV6_SECRET);
        testRecombine(TV011D_TV6_2_3_4_R, TV011D_TV6_2_3_4_SPLITS, TV011D_TV6_SECRET);
    }


    static void testMatrixMultiplication(int[][] p, int[][] sr, int[][] splits)
    {
        int[][] result = Polynomial2Native.gfMatMul(p, sr);
        assertArrayEquals(splits, result);
    }

    @Test
    public void testRecombine(int[][] r, int[][] splits, int[][] secret)
    {
        int[][] result = Polynomial2Native.gfMatMul(r, splits);
        assertArrayEquals(secret, result);
    }

    private static void assertArrayEquals(int[][] expected, int[][] actual)
    {
        assertEquals(Arrays.deepToString(expected), Arrays.deepToString(actual));
    }
}

