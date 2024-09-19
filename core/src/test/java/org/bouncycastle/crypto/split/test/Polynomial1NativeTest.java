package org.bouncycastle.crypto.split.test;

import java.util.Arrays;

import junit.framework.TestCase;

import org.bouncycastle.crypto.split.Polynomial1Native;
import org.junit.Test;

public class Polynomial1NativeTest
    extends TestCase
{
    public static void main(String[] args)
    {
        Polynomial1NativeTest test = new Polynomial1NativeTest();
        test.performTest();
    }

    public void performTest()
    {
        testMatrixMultiplication();
        testRecombine();
        testMatrixMultiplicationTV2();
        testRecombines();
        testMatrixMultiplicationTV3();
        testRecombines3();
        testMatrixMultiplicationTV4();
        testRecombines4();
        testMatrixMultiplicationTV5();
        testRecombines5();
        testMatrixMultiplicationTV6();
        testRecombines6();
    }

    // Test test vectors for Polynomial 1 (x^^8 + x^^4 + x^^3 + x + 1)



    /*

     * Test vector TV011B_1

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
    @Test
    public void testMatrixMultiplication() {
        int[][] TV011B_TV1_P = {
            { Polynomial1Native.gfPow(0x01, 0x00), Polynomial1Native.gfPow(0x01, 0x01) },
            { Polynomial1Native.gfPow(0x02, 0x00), Polynomial1Native.gfPow(0x02, 0x01) }
        };

        int[][] TV011B_TV1_SR = {
            { 0x74, 0x65, 0x73, 0x74, 0x00 },
            { 0xA8, 0x7B, 0x34, 0x91, 0xB5 }
        };

        int[][] TV011B_TV1_SPLITS = {
            { 0xDC, 0x1E, 0x47, 0xE5, 0xB5 },
            { 0x3F, 0x93, 0x1B, 0x4D, 0x71 }
        };

        int[][] result = Polynomial1Native.gfMatMul(TV011B_TV1_P, TV011B_TV1_SR);
        assertArrayEquals(TV011B_TV1_SPLITS, result);
    }

    @Test
    public void testRecombine() {
        int[][] TV011B_TV1_1_2_R = {
            { Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x02, 0x01)), Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x02)) }
        };

        int[][] TV011B_TV1_1_2_SPLITS = {
            { 0xDC, 0x1E, 0x47, 0xE5, 0xB5 },
            { 0x3F, 0x93, 0x1B, 0x4D, 0x71 }
        };

        int[][] TV011B_TV1_SECRET = {
            { 0x74, 0x65, 0x73, 0x74, 0x00 }
        };

        int[][] result = Polynomial1Native.gfMatMul(TV011B_TV1_1_2_R, TV011B_TV1_1_2_SPLITS);
        assertArrayEquals(TV011B_TV1_SECRET, result);
    }

    /*

     * Test vector TV011B_2

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
    @Test
    public void testMatrixMultiplicationTV2() {
        int[][] TV011B_TV2_P = {
            { Polynomial1Native.gfPow(0x01, 0x00), Polynomial1Native.gfPow(0x01, 0x01) },
            { Polynomial1Native.gfPow(0x02, 0x00), Polynomial1Native.gfPow(0x02, 0x01) },
            { Polynomial1Native.gfPow(0x03, 0x00), Polynomial1Native.gfPow(0x03, 0x01) },
            { Polynomial1Native.gfPow(0x04, 0x00), Polynomial1Native.gfPow(0x04, 0x01) }
        };

        int[][] TV011B_TV2_SR = {
            { 0x53, 0x41, 0x4D, 0x54, 0x43 },
            { 0x39, 0x5D, 0x39, 0x6C, 0x87 }
        };

        int[][] TV011B_TV2_SPLITS = {
            { 0x6A, 0x1C, 0x74, 0x38, 0xC4 },
            { 0x21, 0xFB, 0x3F, 0x8C, 0x56 },
            { 0x18, 0xA6, 0x06, 0xE0, 0xD1 },
            { 0xB7, 0x2E, 0xA9, 0xFF, 0x69 }
        };

        int[][] result = Polynomial1Native.gfMatMul(TV011B_TV2_P, TV011B_TV2_SR);
        assertArrayEquals(TV011B_TV2_SPLITS, result);
    }

    @Test
    public void testRecombines() {
        int[][] TV011B_TV2_1_2_R = {
            { Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x01, 0x02)), Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x02)) }
        };

        int[][] TV011B_TV2_1_4_R = {
            { Polynomial1Native.gfDiv(0x04, Polynomial1Native.gfAdd(0x01, 0x04)), Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x04)) }
        };

        int[][] TV011B_TV2_3_4_R = {
            { Polynomial1Native.gfDiv(0x04, Polynomial1Native.gfAdd(0x03, 0x04)), Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x03, 0x04)) }
        };

        int[][] TV011B_TV2_1_2_SPLITS = {
            { 0x6A, 0x1C, 0x74, 0x38, 0xC4 },
            { 0x21, 0xFB, 0x3F, 0x8C, 0x56 }
        };

        int[][] TV011B_TV2_1_4_SPLITS = {
            { 0x6A, 0x1C, 0x74, 0x38, 0xC4 },
            { 0xB7, 0x2E, 0xA9, 0xFF, 0x69 }
        };

        int[][] TV011B_TV2_3_4_SPLITS = {
            { 0x18, 0xA6, 0x06, 0xE0, 0xD1 },
            { 0xB7, 0x2E, 0xA9, 0xFF, 0x69 }
        };

        int[][] TV011B_TV2_SECRET = {
            { 0x53, 0x41, 0x4D, 0x54, 0x43 }
        };

        int[][] result1_2 = Polynomial1Native.gfMatMul(TV011B_TV2_1_2_R, TV011B_TV2_1_2_SPLITS);
        assertArrayEquals(TV011B_TV2_SECRET, result1_2);

        int[][] result1_4 = Polynomial1Native.gfMatMul(TV011B_TV2_1_4_R, TV011B_TV2_1_4_SPLITS);
        assertArrayEquals(TV011B_TV2_SECRET, result1_4);

        int[][] result3_4 = Polynomial1Native.gfMatMul(TV011B_TV2_3_4_R, TV011B_TV2_3_4_SPLITS);
        assertArrayEquals(TV011B_TV2_SECRET, result3_4);
    }

    @Test
    public void testMatrixMultiplicationTV3() {
        int[][] TV011B_TV3_P = {
            { Polynomial1Native.gfPow(0x01, 0x00), Polynomial1Native.gfPow(0x01, 0x01), Polynomial1Native.gfPow(0x01, 0x02) },
            { Polynomial1Native.gfPow(0x02, 0x00), Polynomial1Native.gfPow(0x02, 0x01), Polynomial1Native.gfPow(0x02, 0x02) },
            { Polynomial1Native.gfPow(0x03, 0x00), Polynomial1Native.gfPow(0x03, 0x01), Polynomial1Native.gfPow(0x03, 0x02) },
            { Polynomial1Native.gfPow(0x04, 0x00), Polynomial1Native.gfPow(0x04, 0x01), Polynomial1Native.gfPow(0x04, 0x02) }
        };

        int[][] TV011B_TV3_SR = {
            { 0x53, 0x41, 0x4D, 0x54, 0x43 },
            { 0x27, 0x1A, 0xAB, 0x79, 0x06 },
            { 0x3A, 0x28, 0x99, 0xBC, 0x37 }
        };

        int[][] TV011B_TV3_SPLITS = {
            { 0x4E, 0x73, 0x7F, 0x91, 0x72 },
            { 0xF5, 0xD5, 0x52, 0x60, 0x93 },
            { 0xE8, 0xE7, 0x60, 0xA5, 0xA2 },
            { 0x42, 0x9F, 0x84, 0x9E, 0x06 }
        };

        int[][] result = Polynomial1Native.gfMatMul(TV011B_TV3_P, TV011B_TV3_SR);
        assertArrayEquals(TV011B_TV3_SPLITS, result);
    }

    @Test
    public void testRecombines3() {
        int[][] TV011B_TV3_1_2_3_R = {
            {
                Polynomial1Native.gfMul(Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x01, 0x02)), Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x01, 0x03))),
                Polynomial1Native.gfMul(Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x02)), Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x02, 0x03))),
                Polynomial1Native.gfMul(Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x03)), Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x02, 0x03)))
            }
        };

        int[][] TV011B_TV3_1_2_4_R = {
            {
                Polynomial1Native.gfMul(Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x01, 0x02)), Polynomial1Native.gfDiv(0x04, Polynomial1Native.gfAdd(0x01, 0x04))),
                Polynomial1Native.gfMul(Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x02)), Polynomial1Native.gfDiv(0x04, Polynomial1Native.gfAdd(0x02, 0x04))),
                Polynomial1Native.gfMul(Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x04)), Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x02, 0x04)))
            }
        };

        int[][] TV011B_TV3_1_3_4_R = {
            {
                Polynomial1Native.gfMul(Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x01, 0x03)), Polynomial1Native.gfDiv(0x04, Polynomial1Native.gfAdd(0x01, 0x04))),
                Polynomial1Native.gfMul(Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x03)), Polynomial1Native.gfDiv(0x04, Polynomial1Native.gfAdd(0x03, 0x04))),
                Polynomial1Native.gfMul(Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x04)), Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x03, 0x04)))
            }
        };

        int[][] TV011B_TV3_1_2_3_SPLITS = {
            { 0x4E, 0x73, 0x7F, 0x91, 0x72 },
            { 0xF5, 0xD5, 0x52, 0x60, 0x93 },
            { 0xE8, 0xE7, 0x60, 0xA5, 0xA2 }
        };

        int[][] TV011B_TV3_1_2_4_SPLITS = {
            { 0x4E, 0x73, 0x7F, 0x91, 0x72 },
            { 0xF5, 0xD5, 0x52, 0x60, 0x93 },
            { 0x42, 0x9F, 0x84, 0x9E, 0x06 }
        };

        int[][] TV011B_TV3_1_3_4_SPLITS = {
            { 0x4E, 0x73, 0x7F, 0x91, 0x72 },
            { 0xE8, 0xE7, 0x60, 0xA5, 0xA2 },
            { 0x42, 0x9F, 0x84, 0x9E, 0x06 }
        };

        int[][] TV011B_TV3_SECRET = {
            { 0x53, 0x41, 0x4D, 0x54, 0x43 }
        };

        int[][] result1_2_3 = Polynomial1Native.gfMatMul(TV011B_TV3_1_2_3_R, TV011B_TV3_1_2_3_SPLITS);
        assertArrayEquals(TV011B_TV3_SECRET, result1_2_3);
        int[][] result1_2_4 = Polynomial1Native.gfMatMul(TV011B_TV3_1_2_4_R, TV011B_TV3_1_2_4_SPLITS);
        assertArrayEquals(TV011B_TV3_SECRET, result1_2_4);

        int[][] result1_3_4 = Polynomial1Native.gfMatMul(TV011B_TV3_1_3_4_R, TV011B_TV3_1_3_4_SPLITS);
        assertArrayEquals(TV011B_TV3_SECRET, result1_3_4);
    }

    @Test
    public void testMatrixMultiplicationTV4() {
        int[][] TV011B_TV4_P = {
            { Polynomial1Native.gfPow(0x01, 0x00), Polynomial1Native.gfPow(0x01, 0x01), Polynomial1Native.gfPow(0x01, 0x02), Polynomial1Native.gfPow(0x01, 0x03) },
            { Polynomial1Native.gfPow(0x02, 0x00), Polynomial1Native.gfPow(0x02, 0x01), Polynomial1Native.gfPow(0x02, 0x02), Polynomial1Native.gfPow(0x02, 0x03) },
            { Polynomial1Native.gfPow(0x03, 0x00), Polynomial1Native.gfPow(0x03, 0x01), Polynomial1Native.gfPow(0x03, 0x02), Polynomial1Native.gfPow(0x03, 0x03) },
            { Polynomial1Native.gfPow(0x04, 0x00), Polynomial1Native.gfPow(0x04, 0x01), Polynomial1Native.gfPow(0x04, 0x02), Polynomial1Native.gfPow(0x04, 0x03) }
        };

        int[][] TV011B_TV4_SR = {
            { 0x53, 0x41, 0x4D, 0x54, 0x43 },
            { 0x1A, 0x1E, 0x0A, 0x9D, 0x44 },
            { 0x22, 0xE9, 0x73, 0x05, 0x34 },
            { 0x4C, 0x76, 0xA0, 0x77, 0x67 }
        };

        int[][] TV011B_TV4_SPLITS = {
            { 0x27, 0xC0, 0x94, 0xBB, 0x54 },
            { 0xB9, 0x69, 0xF9, 0xF4, 0x0E },
            { 0x7E, 0xC7, 0xCD, 0x32, 0x50 },
            { 0xAB, 0xAF, 0x81, 0x82, 0x8D }
        };

        int[][] result = Polynomial1Native.gfMatMul(TV011B_TV4_P, TV011B_TV4_SR);
        assertArrayEquals(TV011B_TV4_SPLITS, result);
    }

    @Test
    public void testRecombines4() {

        int[][] TV011B_TV4_1_2_3_4_R = {
            { Polynomial1Native.gfProd(new int[]{Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x01, 0x02)), Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x01, 0x03)), Polynomial1Native.gfDiv(0x04, Polynomial1Native.gfAdd(0x01, 0x04))}),
                Polynomial1Native.gfProd(new int[]{Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x02)), Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x02, 0x03)), Polynomial1Native.gfDiv(0x04, Polynomial1Native.gfAdd(0x02, 0x04))}),
                Polynomial1Native.gfProd(new int[]{Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x03)), Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x02, 0x03)), Polynomial1Native.gfDiv(0x04, Polynomial1Native.gfAdd(0x03, 0x04))}),
                Polynomial1Native.gfProd(new int[]{Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x04)), Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x02, 0x04)), Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x03, 0x04))})
            }
        };

        int[][] TV011B_TV4_1_2_3_4_SPLITS = {
            { 0x27, 0xC0, 0x94, 0xBB, 0x54 },
            { 0xB9, 0x69, 0xF9, 0xF4, 0x0E },
            { 0x7E, 0xC7, 0xCD, 0x32, 0x50 },
            { 0xAB, 0xAF, 0x81, 0x82, 0x8D }
        };

        int[][] TV011B_TV4_SECRET = {
            { 0x53, 0x41, 0x4D, 0x54, 0x43 }
        };

        int[][] result1_2_3_4 = Polynomial1Native.gfMatMul(TV011B_TV4_1_2_3_4_R, TV011B_TV4_1_2_3_4_SPLITS);
        assertArrayEquals(TV011B_TV4_SECRET, result1_2_3_4);
    }

    private static final int[][] TV011B_TV5_P = {
        { Polynomial1Native.gfPow(0x01, 0x00), Polynomial1Native.gfPow(0x01, 0x01) },
        { Polynomial1Native.gfPow(0x02, 0x00), Polynomial1Native.gfPow(0x02, 0x01) },
        { Polynomial1Native.gfPow(0x03, 0x00), Polynomial1Native.gfPow(0x03, 0x01) },
        { Polynomial1Native.gfPow(0x04, 0x00), Polynomial1Native.gfPow(0x04, 0x01) },
        { Polynomial1Native.gfPow(0x05, 0x00), Polynomial1Native.gfPow(0x05, 0x01) },
        { Polynomial1Native.gfPow(0x06, 0x00), Polynomial1Native.gfPow(0x06, 0x01) },
        { Polynomial1Native.gfPow(0x07, 0x00), Polynomial1Native.gfPow(0x07, 0x01) },
        { Polynomial1Native.gfPow(0x08, 0x00), Polynomial1Native.gfPow(0x08, 0x01) },
        { Polynomial1Native.gfPow(0x09, 0x00), Polynomial1Native.gfPow(0x09, 0x01) }
    };

    private static final int[][] TV011B_TV5_SR = {
        { 0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61 },
        { 0x7F, 0xB4, 0xE8, 0x58, 0x1E, 0xB7, 0x5D, 0xC9, 0x45 }
    };

    private static final int[][] TV011B_TV5_SPLITS = {
        { 0x2B, 0xD1, 0x9B, 0x2C, 0x3E, 0xF3, 0x3C, 0xBD, 0x24 },
        { 0xAA, 0x16, 0xB8, 0xC4, 0x1C, 0x31, 0xDB, 0xFD, 0xEB },
        { 0xD5, 0xA2, 0x50, 0x9C, 0x02, 0x86, 0x86, 0x34, 0xAE },
        { 0xB3, 0x83, 0xFE, 0x0F, 0x58, 0xAE, 0x0E, 0x7D, 0x6E },
        { 0xCC, 0x37, 0x16, 0x57, 0x46, 0x19, 0x53, 0xB4, 0x2B },
        { 0x4D, 0xF0, 0x35, 0xBF, 0x64, 0xDB, 0xB4, 0xF4, 0xE4 },
        { 0x32, 0x44, 0xDD, 0xE7, 0x7A, 0x6C, 0xE9, 0x3D, 0xA1 },
        { 0x81, 0xB2, 0x72, 0x82, 0xD0, 0x8B, 0xBF, 0x66, 0x7F },
        { 0xFE, 0x06, 0x9A, 0xDA, 0xCE, 0x3C, 0xE2, 0xAF, 0x3A }
    };

    private static final int[][] TV011B_TV5_1_2_R = {
        { Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x01, 0x02)), Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x02)) }
    };

    private static final int[][] TV011B_TV5_8_9_R = {
        { Polynomial1Native.gfDiv(0x09, Polynomial1Native.gfAdd(0x08, 0x09)), Polynomial1Native.gfDiv(0x08, Polynomial1Native.gfAdd(0x08, 0x09)) }
    };

    private static final int[][] TV011B_TV5_1_2_SPLITS = {
        { 0x2B, 0xD1, 0x9B, 0x2C, 0x3E, 0xF3, 0x3C, 0xBD, 0x24 },
        { 0xAA, 0x16, 0xB8, 0xC4, 0x1C, 0x31, 0xDB, 0xFD, 0xEB }
    };

    private static final int[][] TV011B_TV5_8_9_SPLITS = {
        { 0x81, 0xB2, 0x72, 0x82, 0xD0, 0x8B, 0xBF, 0x66, 0x7F },
        { 0xFE, 0x06, 0x9A, 0xDA, 0xCE, 0x3C, 0xE2, 0xAF, 0x3A }
    };

    private static final int[][] TV011B_TV5_SECRET = {
        { 0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61 }
    };

    public void testMatrixMultiplicationTV5() {
        int[][] result = Polynomial1Native.gfMatMul(TV011B_TV5_P, TV011B_TV5_SR);
        assertArrayEquals(TV011B_TV5_SPLITS, result);
    }

    public void testRecombines5() {
        int[][] result = Polynomial1Native.gfMatMul(TV011B_TV5_1_2_R, TV011B_TV5_1_2_SPLITS);
        assertArrayEquals(TV011B_TV5_SECRET, result);
        result = Polynomial1Native.gfMatMul(TV011B_TV5_8_9_R, TV011B_TV5_8_9_SPLITS);
        assertArrayEquals(TV011B_TV5_SECRET, result);
    }

    private static final int[][] TV011B_TV6_P = {
        { Polynomial1Native.gfPow(0x01, 0x00), Polynomial1Native.gfPow(0x01, 0x01), Polynomial1Native.gfPow(0x01, 0x02) },
        { Polynomial1Native.gfPow(0x02, 0x00), Polynomial1Native.gfPow(0x02, 0x01), Polynomial1Native.gfPow(0x02, 0x02) },
        { Polynomial1Native.gfPow(0x03, 0x00), Polynomial1Native.gfPow(0x03, 0x01), Polynomial1Native.gfPow(0x03, 0x02) },
        { Polynomial1Native.gfPow(0x04, 0x00), Polynomial1Native.gfPow(0x04, 0x01), Polynomial1Native.gfPow(0x04, 0x02) },
        { Polynomial1Native.gfPow(0x05, 0x00), Polynomial1Native.gfPow(0x05, 0x01), Polynomial1Native.gfPow(0x05, 0x02) }
    };

    private static final int[][] TV011B_TV6_SR = {
        { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
        { 0xEC, 0x74, 0x40, 0xE1, 0x9A, 0x4F, 0x5F, 0xCA, 0xDB, 0x32, 0xC9, 0x81, 0x4F, 0xA2, 0x71 },
        { 0x96, 0x05, 0xB3, 0xFC, 0x91, 0x6E, 0x7C, 0x51, 0x72, 0x02, 0xB8, 0x00, 0x66, 0x80, 0x97 }
    };

    private static final int[][] TV011B_TV6_SPLITS = {
        { 0x7B, 0x73, 0xF0, 0x19, 0x0E, 0x27, 0x24, 0x93, 0xA0, 0x3A, 0x7A, 0x8D, 0x24, 0x2C, 0xE9 },
        { 0xAC, 0xFE, 0x79, 0x00, 0x58, 0x3B, 0x52, 0xD8, 0x77, 0x66, 0x54, 0x15, 0x10, 0x67, 0x87 },
        { 0xD6, 0x8F, 0x8A, 0x1D, 0x53, 0x1A, 0x71, 0x43, 0xDE, 0x56, 0x25, 0x94, 0x39, 0x45, 0x61 },
        { 0x3F, 0x99, 0xDD, 0xF4, 0x88, 0x9B, 0xE1, 0x6A, 0x29, 0xE2, 0x77, 0x3E, 0x10, 0x68, 0x63 },
        { 0x45, 0xE8, 0x2E, 0xE9, 0x83, 0xBA, 0xC2, 0xF1, 0x80, 0xD2, 0x06, 0xBF, 0x39, 0x4A, 0x85 }
    };

    private static final int[][] TV011B_TV6_1_2_3_R = {
        { Polynomial1Native.gfProd(new int[]{Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x01, 0x02)), Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x01, 0x03))}),
            Polynomial1Native.gfProd(new int[]{Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x02)), Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x02, 0x03))}),
            Polynomial1Native.gfProd(new int[]{Polynomial1Native.gfDiv(0x01, Polynomial1Native.gfAdd(0x01, 0x03)), Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x02, 0x03))}) }
    };

    private static final int[][] TV011B_TV6_2_3_4_R = {
        { Polynomial1Native.gfProd(new int[]{Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x02, 0x03)), Polynomial1Native.gfDiv(0x04, Polynomial1Native.gfAdd(0x02, 0x04))}),
            Polynomial1Native.gfProd(new int[]{Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x02, 0x03)), Polynomial1Native.gfDiv(0x04, Polynomial1Native.gfAdd(0x03, 0x04))}),
            Polynomial1Native.gfProd(new int[]{Polynomial1Native.gfDiv(0x02, Polynomial1Native.gfAdd(0x02, 0x04)), Polynomial1Native.gfDiv(0x03, Polynomial1Native.gfAdd(0x03, 0x04))}) }
    };

    private static final int[][] TV011B_TV6_1_2_3_SPLITS = {
        { 0x7B, 0x73, 0xF0, 0x19, 0x0E, 0x27, 0x24, 0x93, 0xA0, 0x3A, 0x7A, 0x8D, 0x24, 0x2C, 0xE9 },
        { 0xAC, 0xFE, 0x79, 0x00, 0x58, 0x3B, 0x52, 0xD8, 0x77, 0x66, 0x54, 0x15, 0x10, 0x67, 0x87 },
        { 0xD6, 0x8F, 0x8A, 0x1D, 0x53, 0x1A, 0x71, 0x43, 0xDE, 0x56, 0x25, 0x94, 0x39, 0x45, 0x61 }
    };

    private static final int[][] TV011B_TV6_2_3_4_SPLITS = {
        { 0xAC, 0xFE, 0x79, 0x00, 0x58, 0x3B, 0x52, 0xD8, 0x77, 0x66, 0x54, 0x15, 0x10, 0x67, 0x87 },
        { 0xD6, 0x8F, 0x8A, 0x1D, 0x53, 0x1A, 0x71, 0x43, 0xDE, 0x56, 0x25, 0x94, 0x39, 0x45, 0x61 },
        { 0x3F, 0x99, 0xDD, 0xF4, 0x88, 0x9B, 0xE1, 0x6A, 0x29, 0xE2, 0x77, 0x3E, 0x10, 0x68, 0x63 }
    };

    private static final int[][] TV011B_TV6_SECRET = {
        { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }
    };

    public void testMatrixMultiplicationTV6() {
        int[][] result = Polynomial1Native.gfMatMul(TV011B_TV6_P, TV011B_TV6_SR);
        assertArrayEquals(TV011B_TV6_SPLITS, result);
    }

    public void testRecombines6() {
        int[][] result = Polynomial1Native.gfMatMul(TV011B_TV6_1_2_3_R, TV011B_TV6_1_2_3_SPLITS);
        assertArrayEquals(TV011B_TV6_SECRET, result);
        result = Polynomial1Native.gfMatMul(TV011B_TV6_2_3_4_R, TV011B_TV6_2_3_4_SPLITS);
        assertArrayEquals(TV011B_TV6_SECRET, result);
    }

    private void assertArrayEquals(int[][] expected, int[][] actual)
    {
        assertEquals(Arrays.deepToString(expected), Arrays.deepToString(actual));
    }
}

