package org.bouncycastle.crypto.split.test;

import java.util.Arrays;

import junit.framework.TestCase;

import org.bouncycastle.crypto.split.GaloisField;
import org.junit.Test;

public class GaloisFieldTest
    extends TestCase
{
    public static void main(String[] args)
    {
        GaloisFieldTest test = new GaloisFieldTest();
        test.performTest();
    }

    public void performTest()
    {
//        testAddition();
//        testSubtraction();
//        testMultiplication();
//        testDivision();
//        testPower();
//        testVectorSum();
//        testVectorProduct();
//        testDotProduct();
//        testVectorMatrixMultiplication();
        testMatrixMultiplication();
        testRecombine();
        testMatrixMultiplicationTV2();
        testRecombines();
        testMatrixMultiplicationTV3();
        testRecombines3();
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
            { GaloisField.gfPow(0x01, 0x00), GaloisField.gfPow(0x01, 0x01) },
            { GaloisField.gfPow(0x02, 0x00), GaloisField.gfPow(0x02, 0x01) }
        };

        int[][] TV011B_TV1_SR = {
            { 0x74, 0x65, 0x73, 0x74, 0x00 },
            { 0xA8, 0x7B, 0x34, 0x91, 0xB5 }
        };

        int[][] TV011B_TV1_SPLITS = {
            { 0xDC, 0x1E, 0x47, 0xE5, 0xB5 },
            { 0x3F, 0x93, 0x1B, 0x4D, 0x71 }
        };

        int[][] result = GaloisField.gfMatMul(TV011B_TV1_P, TV011B_TV1_SR);
        assertArrayEquals(TV011B_TV1_SPLITS, result);
    }

    @Test
    public void testRecombine() {
        int[][] TV011B_TV1_1_2_R = {
            { GaloisField.gfDiv(0x02, GaloisField.gfAdd(0x02, 0x01)), GaloisField.gfDiv(0x01, GaloisField.gfAdd(0x01, 0x02)) }
        };

        int[][] TV011B_TV1_1_2_SPLITS = {
            { 0xDC, 0x1E, 0x47, 0xE5, 0xB5 },
            { 0x3F, 0x93, 0x1B, 0x4D, 0x71 }
        };

        int[][] TV011B_TV1_SECRET = {
            { 0x74, 0x65, 0x73, 0x74, 0x00 }
        };

        int[][] result = GaloisField.gfMatMul(TV011B_TV1_1_2_R, TV011B_TV1_1_2_SPLITS);
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
            { GaloisField.gfPow(0x01, 0x00), GaloisField.gfPow(0x01, 0x01) },
            { GaloisField.gfPow(0x02, 0x00), GaloisField.gfPow(0x02, 0x01) },
            { GaloisField.gfPow(0x03, 0x00), GaloisField.gfPow(0x03, 0x01) },
            { GaloisField.gfPow(0x04, 0x00), GaloisField.gfPow(0x04, 0x01) }
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

        int[][] result = GaloisField.gfMatMul(TV011B_TV2_P, TV011B_TV2_SR);
        assertArrayEquals(TV011B_TV2_SPLITS, result);
    }

    @Test
    public void testRecombines() {
        int[][] TV011B_TV2_1_2_R = {
            { GaloisField.gfDiv(0x02, GaloisField.gfAdd(0x01, 0x02)), GaloisField.gfDiv(0x01, GaloisField.gfAdd(0x01, 0x02)) }
        };

        int[][] TV011B_TV2_1_4_R = {
            { GaloisField.gfDiv(0x04, GaloisField.gfAdd(0x01, 0x04)), GaloisField.gfDiv(0x01, GaloisField.gfAdd(0x01, 0x04)) }
        };

        int[][] TV011B_TV2_3_4_R = {
            { GaloisField.gfDiv(0x04, GaloisField.gfAdd(0x03, 0x04)), GaloisField.gfDiv(0x03, GaloisField.gfAdd(0x03, 0x04)) }
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

        int[][] result1_2 = GaloisField.gfMatMul(TV011B_TV2_1_2_R, TV011B_TV2_1_2_SPLITS);
        assertArrayEquals(TV011B_TV2_SECRET, result1_2);

        int[][] result1_4 = GaloisField.gfMatMul(TV011B_TV2_1_4_R, TV011B_TV2_1_4_SPLITS);
        assertArrayEquals(TV011B_TV2_SECRET, result1_4);

        int[][] result3_4 = GaloisField.gfMatMul(TV011B_TV2_3_4_R, TV011B_TV2_3_4_SPLITS);
        assertArrayEquals(TV011B_TV2_SECRET, result3_4);
    }

    @Test
    public void testMatrixMultiplicationTV3() {
        int[][] TV011B_TV3_P = {
            { GaloisField.gfPow(0x01, 0x00), GaloisField.gfPow(0x01, 0x01), GaloisField.gfPow(0x01, 0x02) },
            { GaloisField.gfPow(0x02, 0x00), GaloisField.gfPow(0x02, 0x01), GaloisField.gfPow(0x02, 0x02) },
            { GaloisField.gfPow(0x03, 0x00), GaloisField.gfPow(0x03, 0x01), GaloisField.gfPow(0x03, 0x02) },
            { GaloisField.gfPow(0x04, 0x00), GaloisField.gfPow(0x04, 0x01), GaloisField.gfPow(0x04, 0x02) }
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

        int[][] result = GaloisField.gfMatMul(TV011B_TV3_P, TV011B_TV3_SR);
        assertArrayEquals(TV011B_TV3_SPLITS, result);
    }

    @Test
    public void testRecombines3() {
        int[][] TV011B_TV3_1_2_3_R = {
            {
                GaloisField.gfMul(GaloisField.gfDiv(0x02, GaloisField.gfAdd(0x01, 0x02)), GaloisField.gfDiv(0x03, GaloisField.gfAdd(0x01, 0x03))),
                GaloisField.gfMul(GaloisField.gfDiv(0x01, GaloisField.gfAdd(0x01, 0x02)), GaloisField.gfDiv(0x03, GaloisField.gfAdd(0x02, 0x03))),
                GaloisField.gfMul(GaloisField.gfDiv(0x01, GaloisField.gfAdd(0x01, 0x03)), GaloisField.gfDiv(0x02, GaloisField.gfAdd(0x02, 0x03)))
            }
        };

        int[][] TV011B_TV3_1_2_4_R = {
            {
                GaloisField.gfMul(GaloisField.gfDiv(0x02, GaloisField.gfAdd(0x01, 0x02)), GaloisField.gfDiv(0x04, GaloisField.gfAdd(0x01, 0x04))),
                GaloisField.gfMul(GaloisField.gfDiv(0x01, GaloisField.gfAdd(0x01, 0x02)), GaloisField.gfDiv(0x04, GaloisField.gfAdd(0x02, 0x04))),
                GaloisField.gfMul(GaloisField.gfDiv(0x01, GaloisField.gfAdd(0x01, 0x04)), GaloisField.gfDiv(0x02, GaloisField.gfAdd(0x02, 0x04)))
            }
        };

        int[][] TV011B_TV3_1_3_4_R = {
            {
                GaloisField.gfMul(GaloisField.gfDiv(0x03, GaloisField.gfAdd(0x01, 0x03)), GaloisField.gfDiv(0x04, GaloisField.gfAdd(0x01, 0x04))),
                GaloisField.gfMul(GaloisField.gfDiv(0x01, GaloisField.gfAdd(0x01, 0x03)), GaloisField.gfDiv(0x04, GaloisField.gfAdd(0x03, 0x04))),
                GaloisField.gfMul(GaloisField.gfDiv(0x01, GaloisField.gfAdd(0x01, 0x04)), GaloisField.gfDiv(0x03, GaloisField.gfAdd(0x03, 0x04)))
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

        int[][] result1_2_3 = GaloisField.gfMatMul(TV011B_TV3_1_2_3_R, TV011B_TV3_1_2_3_SPLITS);
        assertArrayEquals(TV011B_TV3_SECRET, result1_2_3);
        int[][] result1_2_4 = GaloisField.gfMatMul(TV011B_TV3_1_2_4_R, TV011B_TV3_1_2_4_SPLITS);
        assertArrayEquals(TV011B_TV3_SECRET, result1_2_4);

        int[][] result1_3_4 = GaloisField.gfMatMul(TV011B_TV3_1_3_4_R, TV011B_TV3_1_3_4_SPLITS);
        assertArrayEquals(TV011B_TV3_SECRET, result1_3_4);
    }

    private void assertArrayEquals(int[][] expected, int[][] actual)
    {
        assertEquals(Arrays.deepToString(expected), Arrays.deepToString(actual));
    }
}

