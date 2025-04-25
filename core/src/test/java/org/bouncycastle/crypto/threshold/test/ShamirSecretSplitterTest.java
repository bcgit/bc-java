package org.bouncycastle.crypto.threshold.test;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.threshold.SecretShare;
import org.bouncycastle.crypto.threshold.ShamirSecretSplitter;
import org.bouncycastle.crypto.threshold.ShamirSplitSecret;
import org.bouncycastle.crypto.threshold.ShamirSplitSecretShare;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

public class ShamirSecretSplitterTest
    extends TestCase
{
    public static void main(String[] args)
        throws IOException
    {
        ShamirSecretSplitterTest test = new ShamirSecretSplitterTest();
        for (int i = 0; i < 1000; ++i)
        {
            test.testShamirSecretMultipleDivide();
        }
        test.performTest();
        System.out.println("OK");
    }

    public void performTest()
        throws IOException
    {
        testShamirSecretResplit();
        testShamirSecretMultipleDivide();
        testShamirSecretSplitterSplitAround();
        testPolynomial();
        testShamirSecretSplitter();
    }

    public void testShamirSecretResplit()
        throws IOException
    {
        int l = 9, m = 3, n = 9;
        SecureRandom random = new SecureRandom();
        ShamirSecretSplitter.Algorithm algorithm = ShamirSecretSplitter.Algorithm.AES;
        ShamirSecretSplitter.Mode mode = ShamirSecretSplitter.Mode.Table;
        ShamirSecretSplitter splitter = new ShamirSecretSplitter(algorithm, mode, l, random);

        ShamirSplitSecret splitSecret = (ShamirSplitSecret)splitter.split(m, n);
        ShamirSplitSecretShare[] secretShares = (ShamirSplitSecretShare[])splitSecret.getSecretShares();

        ShamirSplitSecretShare[] secretShares1 = new ShamirSplitSecretShare[]{secretShares[0], secretShares[1], secretShares[2]};
        ShamirSplitSecret splitSecret1 = new ShamirSplitSecret(algorithm, mode, secretShares1);
        byte[] secret1 = splitSecret1.getSecret();


        ShamirSplitSecret splitSecret2 = (ShamirSplitSecret)splitter.resplit(secret1, m, n);
        ShamirSplitSecretShare[] secretShares2 = (ShamirSplitSecretShare[])splitSecret2.getSecretShares();
        ShamirSplitSecretShare[] secretShares3 = new ShamirSplitSecretShare[]{secretShares2[0], secretShares2[1], secretShares2[2]};
        ShamirSplitSecret splitSecret3 = new ShamirSplitSecret(algorithm, mode, secretShares3);
        byte[] secret3 = splitSecret3.getSecret();


        assertTrue(Arrays.areEqual(secret1, secret3));
        assertFalse(Arrays.areEqual(Arrays.concatenate(secretShares[0].getEncoded(), secretShares[1].getEncoded(), secretShares[2].getEncoded()),
            Arrays.concatenate(secretShares2[0].getEncoded(), secretShares2[1].getEncoded(), secretShares2[2].getEncoded())));
    }

    public void testShamirSecretMultipleDivide()
        throws IOException
    {
        int l = 9, m = 3, n = 9;
        SecureRandom random = new SecureRandom();
        ShamirSecretSplitter.Algorithm algorithm = ShamirSecretSplitter.Algorithm.AES;
        ShamirSecretSplitter.Mode mode = ShamirSecretSplitter.Mode.Table;
        ShamirSecretSplitter splitter = new ShamirSecretSplitter(algorithm, mode, l, random);

        ShamirSplitSecret splitSecret = (ShamirSplitSecret)splitter.split(m, n);
        ShamirSplitSecretShare[] secretShares = (ShamirSplitSecretShare[])splitSecret.getSecretShares();

        ShamirSplitSecretShare[] secretShares1 = new ShamirSplitSecretShare[]{secretShares[0], secretShares[1], secretShares[2]};
        ShamirSplitSecret splitSecret1 = new ShamirSplitSecret(algorithm, mode, secretShares1);
        byte[] secret1 = splitSecret1.getSecret();

        int mul = random.nextInt(254) + 1;
        splitSecret.multiple(mul);
        secretShares = (ShamirSplitSecretShare[])splitSecret.getSecretShares();
        ShamirSplitSecretShare[] secretShares4 = new ShamirSplitSecretShare[]{secretShares[1], secretShares[2], secretShares[5]};
        ShamirSplitSecret splitSecret4 = new ShamirSplitSecret(algorithm, mode, secretShares4);
        byte[] secret4 = splitSecret4.getSecret();

        splitSecret.divide(mul);
        secretShares = (ShamirSplitSecretShare[])splitSecret.getSecretShares();
        ShamirSplitSecretShare[] secretShares2 = new ShamirSplitSecretShare[]{secretShares[4], secretShares[7], secretShares[8]};
        ShamirSplitSecret splitSecret2 = new ShamirSplitSecret(algorithm, mode, secretShares2);
        byte[] secret2 = splitSecret2.getSecret();
        assertTrue(Arrays.areEqual(secret1, secret2));


        // not enough secret shares cannot correctly recover the secret
        ShamirSplitSecretShare[] secretShares3 = new ShamirSplitSecretShare[]{secretShares[3], secretShares[6]};
        ShamirSplitSecret splitSecret3 = new ShamirSplitSecret(algorithm, mode, secretShares3);
        byte[] secret3 = splitSecret3.getSecret();
        assertFalse(Arrays.areEqual(secret1, secret3));
    }

    public void testShamirSecretSplitterSplitAround()
        throws IOException
    {
        int l = 9, m = 3, n = 9;
        ShamirSecretSplitter.Algorithm algorithm = ShamirSecretSplitter.Algorithm.AES;
        ShamirSecretSplitter.Mode mode = ShamirSecretSplitter.Mode.Table;
        ShamirSecretSplitter splitter = new ShamirSecretSplitter(algorithm, mode, l, new SecureRandom());
        byte[] seed = Hex.decode("010203040506070809");
        //SecureRandom random = new SecureRandom();

        //random.nextBytes(seed);
        //System.out.println(Hex.decode(seed));
        ShamirSplitSecretShare ss = new ShamirSplitSecretShare(seed);
        ShamirSplitSecret splitSecret = (ShamirSplitSecret)splitter.splitAround(ss, m, n);
        ShamirSplitSecretShare[] secretShares = (ShamirSplitSecretShare[])splitSecret.getSecretShares();
        assertTrue(Arrays.areEqual(secretShares[0].getEncoded(), seed));

        ShamirSplitSecretShare[] secretShares1 = new ShamirSplitSecretShare[]{secretShares[0], secretShares[1], secretShares[2]};
        ShamirSplitSecret splitSecret1 = new ShamirSplitSecret(algorithm, mode, secretShares1);
        byte[] secret1 = splitSecret1.getSecret();

        ShamirSplitSecretShare[] secretShares4 = new ShamirSplitSecretShare[]{secretShares[1], secretShares[2], secretShares[5]};
        ShamirSplitSecret splitSecret4 = new ShamirSplitSecret(algorithm, mode, secretShares4);
        byte[] secret4 = splitSecret4.getSecret();

        ShamirSplitSecretShare[] secretShares2 = new ShamirSplitSecretShare[]{secretShares[4], secretShares[7], secretShares[8]};
        ShamirSplitSecret splitSecret2 = new ShamirSplitSecret(algorithm, mode, secretShares2);
        byte[] secret2 = splitSecret2.getSecret();

        assertTrue(Arrays.areEqual(secret1, secret2));
        assertTrue(Arrays.areEqual(secret1, secret4));

        // not enough secret shares cannot correctly recover the secret
        ShamirSplitSecretShare[] secretShares3 = new ShamirSplitSecretShare[]{secretShares[3], secretShares[6]};
        ShamirSplitSecret splitSecret3 = new ShamirSplitSecret(algorithm, mode, secretShares3);
        byte[] secret3 = splitSecret3.getSecret();
        assertFalse(Arrays.areEqual(secret1, secret3));

        secretShares3 = new ShamirSplitSecretShare[]{secretShares[0], secretShares[1]};
        splitSecret3 = new ShamirSplitSecret(algorithm, mode, secretShares3);
        secret3 = splitSecret3.getSecret();
        assertFalse(Arrays.areEqual(secret1, secret3));
    }

    public void testShamirSecretSplitter()
        throws IOException
    {
        int l = 9, m = 3, n = 9;
        ShamirSecretSplitter.Algorithm algorithm = ShamirSecretSplitter.Algorithm.AES;
        ShamirSecretSplitter.Mode mode = ShamirSecretSplitter.Mode.Table;
        ShamirSecretSplitter splitter = new ShamirSecretSplitter(algorithm, mode, l, new SecureRandom());//, secretshare);
        ShamirSplitSecret splitSecret = (ShamirSplitSecret)splitter.split(m, n); //integers  multiply/ divide
        ShamirSplitSecretShare[] secretShares = (ShamirSplitSecretShare[])splitSecret.getSecretShares();

        ShamirSplitSecretShare[] secretShares1 = new ShamirSplitSecretShare[]{secretShares[0], secretShares[1], secretShares[2]};
        ShamirSplitSecret splitSecret1 = new ShamirSplitSecret(algorithm, mode, secretShares1);
        byte[] secret1 = splitSecret1.getSecret();

        ShamirSplitSecretShare[] secretShares2 = new ShamirSplitSecretShare[]{secretShares[4], secretShares[7], secretShares[8]};
        ShamirSplitSecret splitSecret2 = new ShamirSplitSecret(algorithm, mode, secretShares2);
        byte[] secret2 = splitSecret2.getSecret();

        assertTrue(Arrays.areEqual(secret1, secret2));

        // not enough secret shares cannot correctly recover the secret
        ShamirSplitSecretShare[] secretShares3 = new ShamirSplitSecretShare[]{secretShares[3], secretShares[6]};
        ShamirSplitSecret splitSecret3 = new ShamirSplitSecret(algorithm, mode, secretShares3);
        byte[] secret3 = splitSecret3.getSecret();
        assertFalse(Arrays.areEqual(secret1, secret3));
    }
//    private static Polynomial polynomial1 = new PolynomialTable(Polynomial.AES);
//    private static Polynomial polynomial2 = new PolynomialTable(Polynomial.RSA);
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
//    byte[][] TV011B_TV1_P = {
//        {polynomial1.gfPow(0x01, (byte)0x00), polynomial1.gfPow(0x01, (byte)0x01)},
//        {polynomial1.gfPow(0x02, (byte)0x00), polynomial1.gfPow(0x02, (byte)0x01)}
//    };

    byte[][] TV011B_TV1_SR = {
        {(byte)0x74, (byte)0x65, (byte)0x73, (byte)0x74, (byte)0x00},
        {(byte)0xA8, (byte)0x7B, (byte)0x34, (byte)0x91, (byte)0xB5}
    };

    byte[][] TV011B_TV1_SPLITS = {
        {(byte)0xDC, (byte)0x1E, (byte)0x47, (byte)0xE5, (byte)0xB5},
        {(byte)0x3F, (byte)0x93, (byte)0x1B, (byte)0x4D, (byte)0x71}
    };

//    byte[][] TV011B_TV1_1_2_R = {
//        {polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x02, (byte)0x01)), polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x02))}
//    };

    byte[][] TV011B_TV1_1_2_SPLITS = {
        {(byte)0xDC, (byte)0x1E, (byte)0x47, (byte)0xE5, (byte)0xB5},
        {(byte)0x3F, (byte)0x93, (byte)0x1B, (byte)0x4D, (byte)0x71}
    };

    byte[] TV011B_TV1_SECRET = {(byte)0x74, (byte)0x65, (byte)0x73, (byte)0x74, (byte)0x00};

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
//    byte[][] TV011B_TV2_P = {
//        {polynomial1.gfPow(0x01, (byte)0x00), polynomial1.gfPow(0x01, (byte)0x01)},
//        {polynomial1.gfPow(0x02, (byte)0x00), polynomial1.gfPow(0x02, (byte)0x01)},
//        {polynomial1.gfPow(0x03, (byte)0x00), polynomial1.gfPow(0x03, (byte)0x01)},
//        {polynomial1.gfPow(0x04, (byte)0x00), polynomial1.gfPow(0x04, (byte)0x01)}
//    };

    byte[][] TV011B_TV2_SR = {
        {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43},
        {(byte)0x39, (byte)0x5D, (byte)0x39, (byte)0x6C, (byte)0x87}
    };

    byte[][] TV011B_TV2_SPLITS = {
        {(byte)0x6A, (byte)0x1C, (byte)0x74, (byte)0x38, (byte)0xC4},
        {(byte)0x21, (byte)0xFB, (byte)0x3F, (byte)0x8C, (byte)0x56},
        {(byte)0x18, (byte)0xA6, (byte)0x06, (byte)0xE0, (byte)0xD1},
        {(byte)0xB7, (byte)0x2E, (byte)0xA9, (byte)0xFF, (byte)0x69}
    };

//    byte[][] TV011B_TV2_1_2_R = {
//        {polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x01, (byte)0x02)), polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x02))}
//    };
//
//    byte[][] TV011B_TV2_1_4_R = {
//        {polynomial1.gfDiv(0x04, polynomial1.gfAdd(0x01, (byte)0x04)), polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x04))}
//    };
//
//    byte[][] TV011B_TV2_3_4_R = {
//        {polynomial1.gfDiv(0x04, polynomial1.gfAdd(0x03, (byte)0x04)), polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x03, (byte)0x04))}
//    };

    byte[][] TV011B_TV2_1_2_SPLITS = {
        {(byte)0x6A, (byte)0x1C, (byte)0x74, (byte)0x38, (byte)0xC4},
        {(byte)0x21, (byte)0xFB, (byte)0x3F, (byte)0x8C, (byte)0x56}
    };

    byte[][] TV011B_TV2_1_4_SPLITS = {
        {(byte)0x6A, (byte)0x1C, (byte)0x74, (byte)0x38, (byte)0xC4},
        {(byte)0xB7, (byte)0x2E, (byte)0xA9, (byte)0xFF, (byte)0x69}
    };

    byte[][] TV011B_TV2_3_4_SPLITS = {
        {(byte)0x18, (byte)0xA6, (byte)0x06, (byte)0xE0, (byte)0xD1},
        {(byte)0xB7, (byte)0x2E, (byte)0xA9, (byte)0xFF, (byte)0x69}
    };

    byte[] TV011B_TV2_SECRET = {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43};

//    byte[][] TV011B_TV3_P = {
//        {polynomial1.gfPow(0x01, (byte)0x00), polynomial1.gfPow(0x01, (byte)0x01), polynomial1.gfPow(0x01, (byte)0x02)},
//        {polynomial1.gfPow(0x02, (byte)0x00), polynomial1.gfPow(0x02, (byte)0x01), polynomial1.gfPow(0x02, (byte)0x02)},
//        {polynomial1.gfPow(0x03, (byte)0x00), polynomial1.gfPow(0x03, (byte)0x01), polynomial1.gfPow(0x03, (byte)0x02)},
//        {polynomial1.gfPow(0x04, (byte)0x00), polynomial1.gfPow(0x04, (byte)0x01), polynomial1.gfPow(0x04, (byte)0x02)}
//    };

    byte[][] TV011B_TV3_SR = {
        {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43},
        {(byte)0x27, (byte)0x1A, (byte)0xAB, (byte)0x79, (byte)0x06},
        {(byte)0x3A, (byte)0x28, (byte)0x99, (byte)0xBC, (byte)0x37}
    };

    byte[][] TV011B_TV3_SPLITS = {
        {(byte)0x4E, (byte)0x73, (byte)0x7F, (byte)0x91, (byte)0x72},
        {(byte)0xF5, (byte)0xD5, (byte)0x52, (byte)0x60, (byte)0x93},
        {(byte)0xE8, (byte)0xE7, (byte)0x60, (byte)0xA5, (byte)0xA2},
        {(byte)0x42, (byte)0x9F, (byte)0x84, (byte)0x9E, (byte)0x06}
    };

    /*
     * Test vector TV011B_3
     * secret = 53 41 4D 54 43
     * random = 27 3A 1A 28 AB 99 79 BC 06 37
     *
     * l = 5
     * m = 3
     * n = 4
     *
     * split1 = 4E 73 7F 91 72
     * split2 = F5 D5 52 60 93
     * split3 = E8 E7 60 A5 A2
     * split4 = 42 9F 84 9E 06
     */

//    byte[][] TV011B_TV3_1_2_3_R = {
//        {
//            polynomial1.gfMul(polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x01, (byte)0x02)), polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x01, (byte)0x03))),
//            polynomial1.gfMul(polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x02)), polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x02, (byte)0x03))),
//            polynomial1.gfMul(polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x03)), polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x02, (byte)0x03)))
//        }
//    };
//
//    byte[][] TV011B_TV3_1_2_4_R = {
//        {
//            polynomial1.gfMul(polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x01, (byte)0x02)), polynomial1.gfDiv(0x04, polynomial1.gfAdd(0x01, (byte)0x04))),
//            polynomial1.gfMul(polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x02)), polynomial1.gfDiv(0x04, polynomial1.gfAdd(0x02, (byte)0x04))),
//            polynomial1.gfMul(polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x04)), polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x02, (byte)0x04)))
//        }
//    };
//
//    byte[][] TV011B_TV3_1_3_4_R = {
//        {
//            polynomial1.gfMul(polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x01, (byte)0x03)), polynomial1.gfDiv(0x04, polynomial1.gfAdd(0x01, (byte)0x04))),
//            polynomial1.gfMul(polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x03)), polynomial1.gfDiv(0x04, polynomial1.gfAdd(0x03, (byte)0x04))),
//            polynomial1.gfMul(polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x04)), polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x03, (byte)0x04)))
//        }
//    };

    byte[][] TV011B_TV3_1_2_3_SPLITS = {
        {(byte)0x4E, (byte)0x73, (byte)0x7F, (byte)0x91, (byte)0x72},
        {(byte)0xF5, (byte)0xD5, (byte)0x52, (byte)0x60, (byte)0x93},
        {(byte)0xE8, (byte)0xE7, (byte)0x60, (byte)0xA5, (byte)0xA2}
    };

    byte[][] TV011B_TV3_1_2_4_SPLITS = {
        {(byte)0x4E, (byte)0x73, (byte)0x7F, (byte)0x91, (byte)0x72},
        {(byte)0xF5, (byte)0xD5, (byte)0x52, (byte)0x60, (byte)0x93},
        {(byte)0x42, (byte)0x9F, (byte)0x84, (byte)0x9E, (byte)0x06}
    };

    byte[][] TV011B_TV3_1_3_4_SPLITS = {
        {(byte)0x4E, (byte)0x73, (byte)0x7F, (byte)0x91, (byte)0x72},
        {(byte)0xE8, (byte)0xE7, (byte)0x60, (byte)0xA5, (byte)0xA2},
        {(byte)0x42, (byte)0x9F, (byte)0x84, (byte)0x9E, (byte)0x06}
    };

    byte[] TV011B_TV3_SECRET = {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43};

    /*
     * Test vector TV011B_4
     * secret = 53 41 4D 54 43
     * random = 1A 22 4C 1E E9 76 0A 73 A0 9D 05 77 44 34 67
     *
     * l = 5
     * m = 4
     * n = 4
     *
     * split1 = 27 C0 94 BB 54
     * split2 = B9 69 F9 F4 0E
     * split3 = 7E C7 CD 32 50
     * split4 = AB AF 81 82 8D
     */

//    byte[][] TV011B_TV4_P = {
//        {polynomial1.gfPow(0x01, (byte)0x00), polynomial1.gfPow(0x01, (byte)0x01), polynomial1.gfPow(0x01, (byte)0x02), polynomial1.gfPow(0x01, (byte)0x03)},
//        {polynomial1.gfPow(0x02, (byte)0x00), polynomial1.gfPow(0x02, (byte)0x01), polynomial1.gfPow(0x02, (byte)0x02), polynomial1.gfPow(0x02, (byte)0x03)},
//        {polynomial1.gfPow(0x03, (byte)0x00), polynomial1.gfPow(0x03, (byte)0x01), polynomial1.gfPow(0x03, (byte)0x02), polynomial1.gfPow(0x03, (byte)0x03)},
//        {polynomial1.gfPow(0x04, (byte)0x00), polynomial1.gfPow(0x04, (byte)0x01), polynomial1.gfPow(0x04, (byte)0x02), polynomial1.gfPow(0x04, (byte)0x03)}
//    };

    byte[][] TV011B_TV4_SR = {
        {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43},
        {(byte)0x1A, (byte)0x1E, (byte)0x0A, (byte)0x9D, (byte)0x44},
        {(byte)0x22, (byte)0xE9, (byte)0x73, (byte)0x05, (byte)0x34},
        {(byte)0x4C, (byte)0x76, (byte)0xA0, (byte)0x77, (byte)0x67}
    };

    byte[][] TV011B_TV4_SPLITS = {
        {(byte)0x27, (byte)0xC0, (byte)0x94, (byte)0xBB, (byte)0x54},
        {(byte)0xB9, (byte)0x69, (byte)0xF9, (byte)0xF4, (byte)0x0E},
        {(byte)0x7E, (byte)0xC7, (byte)0xCD, (byte)0x32, (byte)0x50},
        {(byte)0xAB, (byte)0xAF, (byte)0x81, (byte)0x82, (byte)0x8D}
    };

//    byte[][] TV011B_TV4_1_2_3_4_R = {
//        {polynomial1.gfProd(new byte[]{polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x01, (byte)0x02)), polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x01, (byte)0x03)), polynomial1.gfDiv(0x04, polynomial1.gfAdd(0x01, (byte)0x04))}),
//            polynomial1.gfProd(new byte[]{polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x02)), polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x02, (byte)0x03)), polynomial1.gfDiv(0x04, polynomial1.gfAdd(0x02, (byte)0x04))}),
//            polynomial1.gfProd(new byte[]{polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x03)), polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x02, (byte)0x03)), polynomial1.gfDiv(0x04, polynomial1.gfAdd(0x03, (byte)0x04))}),
//            polynomial1.gfProd(new byte[]{polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x04)), polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x02, (byte)0x04)), polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x03, (byte)0x04))})
//        }
//    };

    byte[][] TV011B_TV4_1_2_3_4_SPLITS = {
        {(byte)0x27, (byte)0xC0, (byte)0x94, (byte)0xBB, (byte)0x54},
        {(byte)0xB9, (byte)0x69, (byte)0xF9, (byte)0xF4, (byte)0x0E},
        {(byte)0x7E, (byte)0xC7, (byte)0xCD, (byte)0x32, (byte)0x50},
        {(byte)0xAB, (byte)0xAF, (byte)0x81, (byte)0x82, (byte)0x8D}
    };

    byte[] TV011B_TV4_SECRET = {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43};

    /*
     * Test vector TV011B_5
     * secret = 54 65 73 74 20 44 61 74 61
     * random = 7F B4 E8 58 1E B7 5D C9 45
     *
     * l = 9
     * m = 2
     * n = 9
     *
     * split1 = 2B D1 9B 2C 3E F3 3C BD 24
     * split2 = AA 16 B8 C4 1C 31 DB FD EB
     * split3 = D5 A2 50 9C 02 86 86 34 AE
     * split4 = B3 83 FE 0F 58 AE 0E 7D 6E
     * split5 = CC 37 16 57 46 19 53 B4 2B
     * split6 = 4D F0 35 BF 64 DB B4 F4 E4
     * split7 = 32 44 DD E7 7A 6C E9 3D A1
     * split8 = 81 B2 72 82 D0 8B BF 66 7F
     * split9 = FE 06 9A DA CE 3C E2 AF 3A
     */
//    private static final byte[][] TV011B_TV5_P = {
//        {polynomial1.gfPow(0x01, (byte)0x00), polynomial1.gfPow(0x01, (byte)0x01)},
//        {polynomial1.gfPow(0x02, (byte)0x00), polynomial1.gfPow(0x02, (byte)0x01)},
//        {polynomial1.gfPow(0x03, (byte)0x00), polynomial1.gfPow(0x03, (byte)0x01)},
//        {polynomial1.gfPow(0x04, (byte)0x00), polynomial1.gfPow(0x04, (byte)0x01)},
//        {polynomial1.gfPow(0x05, (byte)0x00), polynomial1.gfPow(0x05, (byte)0x01)},
//        {polynomial1.gfPow(0x06, (byte)0x00), polynomial1.gfPow(0x06, (byte)0x01)},
//        {polynomial1.gfPow(0x07, (byte)0x00), polynomial1.gfPow(0x07, (byte)0x01)},
//        {polynomial1.gfPow(0x08, (byte)0x00), polynomial1.gfPow(0x08, (byte)0x01)},
//        {polynomial1.gfPow(0x09, (byte)0x00), polynomial1.gfPow(0x09, (byte)0x01)}
//    };

    private static final byte[][] TV011B_TV5_SR = {
        {(byte)0x54, (byte)0x65, (byte)0x73, (byte)0x74, (byte)0x20, (byte)0x44, (byte)0x61, (byte)0x74, (byte)0x61},
        {(byte)0x7F, (byte)0xB4, (byte)0xE8, (byte)0x58, (byte)0x1E, (byte)0xB7, (byte)0x5D, (byte)0xC9, (byte)0x45}
    };

    private static final byte[][] TV011B_TV5_SPLITS = {
        {(byte)0x2B, (byte)0xD1, (byte)0x9B, (byte)0x2C, (byte)0x3E, (byte)0xF3, (byte)0x3C, (byte)0xBD, (byte)0x24},
        {(byte)0xAA, (byte)0x16, (byte)0xB8, (byte)0xC4, (byte)0x1C, (byte)0x31, (byte)0xDB, (byte)0xFD, (byte)0xEB},
        {(byte)0xD5, (byte)0xA2, (byte)0x50, (byte)0x9C, (byte)0x02, (byte)0x86, (byte)0x86, (byte)0x34, (byte)0xAE},
        {(byte)0xB3, (byte)0x83, (byte)0xFE, (byte)0x0F, (byte)0x58, (byte)0xAE, (byte)0x0E, (byte)0x7D, (byte)0x6E},
        {(byte)0xCC, (byte)0x37, (byte)0x16, (byte)0x57, (byte)0x46, (byte)0x19, (byte)0x53, (byte)0xB4, (byte)0x2B},
        {(byte)0x4D, (byte)0xF0, (byte)0x35, (byte)0xBF, (byte)0x64, (byte)0xDB, (byte)0xB4, (byte)0xF4, (byte)0xE4},
        {(byte)0x32, (byte)0x44, (byte)0xDD, (byte)0xE7, (byte)0x7A, (byte)0x6C, (byte)0xE9, (byte)0x3D, (byte)0xA1},
        {(byte)0x81, (byte)0xB2, (byte)0x72, (byte)0x82, (byte)0xD0, (byte)0x8B, (byte)0xBF, (byte)0x66, (byte)0x7F},
        {(byte)0xFE, (byte)0x06, (byte)0x9A, (byte)0xDA, (byte)0xCE, (byte)0x3C, (byte)0xE2, (byte)0xAF, (byte)0x3A}
    };
//
//    private static final byte[][] TV011B_TV5_1_2_R = {
//        {polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x01, (byte)0x02)), polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x02))}
//    };
//
//    private static final byte[][] TV011B_TV5_8_9_R = {
//        {polynomial1.gfDiv(0x09, polynomial1.gfAdd(0x08, (byte)0x09)), polynomial1.gfDiv(0x08, polynomial1.gfAdd(0x08, (byte)0x09))}
//    };

    private static final byte[][] TV011B_TV5_1_2_SPLITS = {
        {(byte)0x2B, (byte)0xD1, (byte)0x9B, (byte)0x2C, (byte)0x3E, (byte)0xF3, (byte)0x3C, (byte)0xBD, (byte)0x24},
        {(byte)0xAA, (byte)0x16, (byte)0xB8, (byte)0xC4, (byte)0x1C, (byte)0x31, (byte)0xDB, (byte)0xFD, (byte)0xEB}
    };

    private static final byte[][] TV011B_TV5_8_9_SPLITS = {
        {(byte)0x81, (byte)0xB2, (byte)0x72, (byte)0x82, (byte)0xD0, (byte)0x8B, (byte)0xBF, (byte)0x66, (byte)0x7F},
        {(byte)0xFE, (byte)0x06, (byte)0x9A, (byte)0xDA, (byte)0xCE, (byte)0x3C, (byte)0xE2, (byte)0xAF, (byte)0x3A}
    };

    private static final byte[] TV011B_TV5_SECRET =
        {(byte)0x54, (byte)0x65, (byte)0x73, (byte)0x74, (byte)0x20, (byte)0x44, (byte)0x61, (byte)0x74, (byte)0x61};

    /*
     * Test vector TV011B_6
     * secret = 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
     * random = EC 96 74 05 40 B3 E1 FC 9A 91 4F 6E 5F 7C CA 51 DB 72 32 02 C9 B8 81 00 4F 66 A2 80 71 97
     *
     * l = 15
     * m = 3
     * n = 5
     *
     * split1 = 7B 73 F0 19 0E 27 24 93 A0 3A 7A 8D 24 2C E9
     * split2 = AC FE 79 00 58 3B 52 D8 77 66 54 15 10 67 87
     * split3 = D6 8F 8A 1D 53 1A 71 43 DE 56 25 94 39 45 61
     * split4 = 3F 99 DD F4 88 9B E1 6A 29 E2 77 3E 10 68 63
     * split5 = 45 E8 2E E9 83 BA C2 F1 80 D2 06 BF 39 4A 85
     */
//    private static final byte[][] TV011B_TV6_P = {
//        {polynomial1.gfPow(0x01, (byte)0x00), polynomial1.gfPow(0x01, (byte)0x01), polynomial1.gfPow(0x01, (byte)0x02)},
//        {polynomial1.gfPow(0x02, (byte)0x00), polynomial1.gfPow(0x02, (byte)0x01), polynomial1.gfPow(0x02, (byte)0x02)},
//        {polynomial1.gfPow(0x03, (byte)0x00), polynomial1.gfPow(0x03, (byte)0x01), polynomial1.gfPow(0x03, (byte)0x02)},
//        {polynomial1.gfPow(0x04, (byte)0x00), polynomial1.gfPow(0x04, (byte)0x01), polynomial1.gfPow(0x04, (byte)0x02)},
//        {polynomial1.gfPow(0x05, (byte)0x00), polynomial1.gfPow(0x05, (byte)0x01), polynomial1.gfPow(0x05, (byte)0x02)}
//    };

    private static final byte[][] TV011B_TV6_SR = {
        {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F},
        {(byte)0xEC, (byte)0x74, (byte)0x40, (byte)0xE1, (byte)0x9A, (byte)0x4F, (byte)0x5F, (byte)0xCA, (byte)0xDB, (byte)0x32, (byte)0xC9, (byte)0x81, (byte)0x4F, (byte)0xA2, (byte)0x71},
        {(byte)0x96, (byte)0x05, (byte)0xB3, (byte)0xFC, (byte)0x91, (byte)0x6E, (byte)0x7C, (byte)0x51, (byte)0x72, (byte)0x02, (byte)0xB8, (byte)0x00, (byte)0x66, (byte)0x80, (byte)0x97}
    };

    private static final byte[][] TV011B_TV6_SPLITS = {
        {(byte)0x7B, (byte)0x73, (byte)0xF0, (byte)0x19, (byte)0x0E, (byte)0x27, (byte)0x24, (byte)0x93, (byte)0xA0, (byte)0x3A, (byte)0x7A, (byte)0x8D, (byte)0x24, (byte)0x2C, (byte)0xE9},
        {(byte)0xAC, (byte)0xFE, (byte)0x79, (byte)0x00, (byte)0x58, (byte)0x3B, (byte)0x52, (byte)0xD8, (byte)0x77, (byte)0x66, (byte)0x54, (byte)0x15, (byte)0x10, (byte)0x67, (byte)0x87},
        {(byte)0xD6, (byte)0x8F, (byte)0x8A, (byte)0x1D, (byte)0x53, (byte)0x1A, (byte)0x71, (byte)0x43, (byte)0xDE, (byte)0x56, (byte)0x25, (byte)0x94, (byte)0x39, (byte)0x45, (byte)0x61},
        {(byte)0x3F, (byte)0x99, (byte)0xDD, (byte)0xF4, (byte)0x88, (byte)0x9B, (byte)0xE1, (byte)0x6A, (byte)0x29, (byte)0xE2, (byte)0x77, (byte)0x3E, (byte)0x10, (byte)0x68, (byte)0x63},
        {(byte)0x45, (byte)0xE8, (byte)0x2E, (byte)0xE9, (byte)0x83, (byte)0xBA, (byte)0xC2, (byte)0xF1, (byte)0x80, (byte)0xD2, (byte)0x06, (byte)0xBF, (byte)0x39, (byte)0x4A, (byte)0x85}
    };

//    private static final byte[][] TV011B_TV6_1_2_3_R = {
//        {polynomial1.gfProd(new byte[]{polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x01, (byte)0x02)), polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x01, (byte)0x03))}),
//            polynomial1.gfProd(new byte[]{polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x02)), polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x02, (byte)0x03))}),
//            polynomial1.gfProd(new byte[]{polynomial1.gfDiv(0x01, polynomial1.gfAdd(0x01, (byte)0x03)), polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x02, (byte)0x03))})}
//    };
//
//    private static final byte[][] TV011B_TV6_2_3_4_R = {
//        {polynomial1.gfProd(new byte[]{polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x02, (byte)0x03)), polynomial1.gfDiv(0x04, polynomial1.gfAdd(0x02, (byte)0x04))}),
//            polynomial1.gfProd(new byte[]{polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x02, (byte)0x03)), polynomial1.gfDiv(0x04, polynomial1.gfAdd(0x03, (byte)0x04))}),
//            polynomial1.gfProd(new byte[]{polynomial1.gfDiv(0x02, polynomial1.gfAdd(0x02, (byte)0x04)), polynomial1.gfDiv(0x03, polynomial1.gfAdd(0x03, (byte)0x04))})}
//    };

    private static final byte[][] TV011B_TV6_1_2_3_SPLITS = {
        {(byte)0x7B, (byte)0x73, (byte)0xF0, (byte)0x19, (byte)0x0E, (byte)0x27, (byte)0x24, (byte)0x93, (byte)0xA0, (byte)0x3A, (byte)0x7A, (byte)0x8D, (byte)0x24, (byte)0x2C, (byte)0xE9},
        {(byte)0xAC, (byte)0xFE, (byte)0x79, (byte)0x00, (byte)0x58, (byte)0x3B, (byte)0x52, (byte)0xD8, (byte)0x77, (byte)0x66, (byte)0x54, (byte)0x15, (byte)0x10, (byte)0x67, (byte)0x87},
        {(byte)0xD6, (byte)0x8F, (byte)0x8A, (byte)0x1D, (byte)0x53, (byte)0x1A, (byte)0x71, (byte)0x43, (byte)0xDE, (byte)0x56, (byte)0x25, (byte)0x94, (byte)0x39, (byte)0x45, (byte)0x61}
    };

    private static final byte[][] TV011B_TV6_2_3_4_SPLITS = {
        {(byte)0xAC, (byte)0xFE, (byte)0x79, (byte)0x00, (byte)0x58, (byte)0x3B, (byte)0x52, (byte)0xD8, (byte)0x77, (byte)0x66, (byte)0x54, (byte)0x15, (byte)0x10, (byte)0x67, (byte)0x87},
        {(byte)0xD6, (byte)0x8F, (byte)0x8A, (byte)0x1D, (byte)0x53, (byte)0x1A, (byte)0x71, (byte)0x43, (byte)0xDE, (byte)0x56, (byte)0x25, (byte)0x94, (byte)0x39, (byte)0x45, (byte)0x61},
        {(byte)0x3F, (byte)0x99, (byte)0xDD, (byte)0xF4, (byte)0x88, (byte)0x9B, (byte)0xE1, (byte)0x6A, (byte)0x29, (byte)0xE2, (byte)0x77, (byte)0x3E, (byte)0x10, (byte)0x68, (byte)0x63}
    };

    private static final byte[] TV011B_TV6_SECRET =
        {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F};

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
//    public static final byte[][] TV011D_TV1_P = {
//        {polynomial2.gfPow(0x01, (byte)0x00), polynomial2.gfPow(0x01, (byte)0x01)},
//        {polynomial2.gfPow(0x02, (byte)0x00), polynomial2.gfPow(0x02, (byte)0x01)}
//    };

    public static final byte[][] TV011D_TV1_SR = {
        {(byte)0x74, (byte)0x65, (byte)0x73, (byte)0x74, (byte)0x00},
        {(byte)0xF3, (byte)0xC2, (byte)0x33, (byte)0x81, (byte)0xF5}
    };

    public static final byte[][] TV011D_TV1_SPLITS = {
        {(byte)0x87, (byte)0xA7, (byte)0x40, (byte)0xF5, (byte)0xF5},
        {(byte)0x8F, (byte)0xFC, (byte)0x15, (byte)0x6B, (byte)0xF7}
    };

//    public static final byte[][] TV011D_TV1_1_2_R = {
//        {polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x02, (byte)0x01)), polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x02))}
//    };

    public static final byte[][] TV011D_TV1_1_2_SPLITS = {
        {(byte)0x87, (byte)0xA7, (byte)0x40, (byte)0xF5, (byte)0xF5},
        {(byte)0x8F, (byte)0xFC, (byte)0x15, (byte)0x6B, (byte)0xF7}
    };

    public static final byte[] TV011D_TV1_SECRET =
        {(byte)0x74, (byte)0x65, (byte)0x73, (byte)0x74, (byte)0x00};

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
//    public static final byte[][] TV011D_TV2_P = {
//        {polynomial2.gfPow(0x01, (byte)0x00), polynomial2.gfPow(0x01, (byte)0x01)},
//        {polynomial2.gfPow(0x02, (byte)0x00), polynomial2.gfPow(0x02, (byte)0x01)},
//        {polynomial2.gfPow(0x03, (byte)0x00), polynomial2.gfPow(0x03, (byte)0x01)},
//        {polynomial2.gfPow(0x04, (byte)0x00), polynomial2.gfPow(0x04, (byte)0x01)}
//    };

    public static final byte[][] TV011D_TV2_SR = {
        {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43},
        {(byte)0x20, (byte)0x76, (byte)0x08, (byte)0x93, (byte)0x0C}
    };

    public static final byte[][] TV011D_TV2_SPLITS = {
        {(byte)0x73, (byte)0x37, (byte)0x45, (byte)0xC7, (byte)0x4F},
        {(byte)0x13, (byte)0xAD, (byte)0x5D, (byte)0x6F, (byte)0x5B},
        {(byte)0x33, (byte)0xDB, (byte)0x55, (byte)0xFC, (byte)0x57},
        {(byte)0xD3, (byte)0x84, (byte)0x6D, (byte)0x22, (byte)0x73}
    };

    // Matrices for recombination
//    public static final byte[][] TV011D_TV2_1_2_R = {
//        {polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x01, (byte)0x02)), polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x02))}
//    };
//
//    public static final byte[][] TV011D_TV2_1_4_R = {
//        {polynomial2.gfDiv(0x04, polynomial2.gfAdd(0x01, (byte)0x04)), polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x04))}
//    };
//
//    public static final byte[][] TV011D_TV2_3_4_R = {
//        {polynomial2.gfDiv(0x04, polynomial2.gfAdd(0x03, (byte)0x04)), polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x03, (byte)0x04))}
//    };

    // Split shares
    public static final byte[][] TV011D_TV2_1_2_SPLITS = {
        {(byte)0x73, (byte)0x37, (byte)0x45, (byte)0xC7, (byte)0x4F},
        {(byte)0x13, (byte)0xAD, (byte)0x5D, (byte)0x6F, (byte)0x5B}
    };

    public static final byte[][] TV011D_TV2_1_4_SPLITS = {
        {(byte)0x73, (byte)0x37, (byte)0x45, (byte)0xC7, (byte)0x4F},
        {(byte)0xD3, (byte)0x84, (byte)0x6D, (byte)0x22, (byte)0x73}
    };

    public static final byte[][] TV011D_TV2_3_4_SPLITS = {
        {(byte)0x33, (byte)0xDB, (byte)0x55, (byte)0xFC, (byte)0x57},
        {(byte)0xD3, (byte)0x84, (byte)0x6D, (byte)0x22, (byte)0x73}
    };

    public static final byte[] TV011D_TV2_SECRET =
        {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43};
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
//    public static final byte[][] TV011D_TV3_P = {
//        {polynomial2.gfPow(0x01, (byte)0x00), polynomial2.gfPow(0x01, (byte)0x01), polynomial2.gfPow(0x01, (byte)0x02)},
//        {polynomial2.gfPow(0x02, (byte)0x00), polynomial2.gfPow(0x02, (byte)0x01), polynomial2.gfPow(0x02, (byte)0x02)},
//        {polynomial2.gfPow(0x03, (byte)0x00), polynomial2.gfPow(0x03, (byte)0x01), polynomial2.gfPow(0x03, (byte)0x02)},
//        {polynomial2.gfPow(0x04, (byte)0x00), polynomial2.gfPow(0x04, (byte)0x01), polynomial2.gfPow(0x04, (byte)0x02)}
//    };

    public static final byte[][] TV011D_TV3_SR = {
        {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43},
        {(byte)0x8C, (byte)0x92, (byte)0x5C, (byte)0xAF, (byte)0x41},
        {(byte)0x15, (byte)0x62, (byte)0x4A, (byte)0x53, (byte)0x45}
    };

    public static final byte[][] TV011D_TV3_SPLITS = {
        {(byte)0xCA, (byte)0xB1, (byte)0x5B, (byte)0xA8, (byte)0x47},
        {(byte)0x02, (byte)0xED, (byte)0xC0, (byte)0x46, (byte)0xC8},
        {(byte)0x9B, (byte)0x1D, (byte)0xD6, (byte)0xBA, (byte)0xCC},
        {(byte)0x14, (byte)0x5D, (byte)0xF4, (byte)0x8B, (byte)0x7E}
    };

    // Matrices for recombination
//    public static final byte[][] TV011D_TV3_1_2_3_R = {
//        {
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x01, (byte)0x02)), polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x01, (byte)0x03))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x02)), polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x02, (byte)0x03))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x03)), polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x02, (byte)0x03))})
//        }
//    };
//
//    public static final byte[][] TV011D_TV3_1_2_4_R = {
//        {
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x01, (byte)0x02)), polynomial2.gfDiv(0x04, polynomial2.gfAdd(0x01, (byte)0x04))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x02)), polynomial2.gfDiv(0x04, polynomial2.gfAdd(0x02, (byte)0x04))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x04)), polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x02, (byte)0x04))})
//        }
//    };
//
//    public static final byte[][] TV011D_TV3_1_3_4_R = {
//        {
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x01, (byte)0x03)), polynomial2.gfDiv(0x04, polynomial2.gfAdd(0x01, (byte)0x04))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x03)), polynomial2.gfDiv(0x04, polynomial2.gfAdd(0x03, (byte)0x04))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x04)), polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x03, (byte)0x04))})
//        }
//    };

    // Split shares
    public static final byte[][] TV011D_TV3_1_2_3_SPLITS = {
        {(byte)0xCA, (byte)0xB1, (byte)0x5B, (byte)0xA8, (byte)0x47},
        {(byte)0x02, (byte)0xED, (byte)0xC0, (byte)0x46, (byte)0xC8},
        {(byte)0x9B, (byte)0x1D, (byte)0xD6, (byte)0xBA, (byte)0xCC}
    };

    public static final byte[][] TV011D_TV3_1_2_4_SPLITS = {
        {(byte)0xCA, (byte)0xB1, (byte)0x5B, (byte)0xA8, (byte)0x47},
        {(byte)0x02, (byte)0xED, (byte)0xC0, (byte)0x46, (byte)0xC8},
        {(byte)0x14, (byte)0x5D, (byte)0xF4, (byte)0x8B, (byte)0x7E}
    };

    public static final byte[][] TV011D_TV3_1_3_4_SPLITS = {
        {(byte)0xCA, (byte)0xB1, (byte)0x5B, (byte)0xA8, (byte)0x47},
        {(byte)0x9B, (byte)0x1D, (byte)0xD6, (byte)0xBA, (byte)0xCC},
        {(byte)0x14, (byte)0x5D, (byte)0xF4, (byte)0x8B, (byte)0x7E}
    };

    // Secret to recover
    public static final byte[] TV011D_TV3_SECRET =
        {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43};

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
//    public static final byte[][] TV011D_TV4_P = {
//        {polynomial2.gfPow(0x01, (byte)0x00), polynomial2.gfPow(0x01, (byte)0x01), polynomial2.gfPow(0x01, (byte)0x02), polynomial2.gfPow(0x01, (byte)0x03)},
//        {polynomial2.gfPow(0x02, (byte)0x00), polynomial2.gfPow(0x02, (byte)0x01), polynomial2.gfPow(0x02, (byte)0x02), polynomial2.gfPow(0x02, (byte)0x03)},
//        {polynomial2.gfPow(0x03, (byte)0x00), polynomial2.gfPow(0x03, (byte)0x01), polynomial2.gfPow(0x03, (byte)0x02), polynomial2.gfPow(0x03, (byte)0x03)},
//        {polynomial2.gfPow(0x04, (byte)0x00), polynomial2.gfPow(0x04, (byte)0x01), polynomial2.gfPow(0x04, (byte)0x02), polynomial2.gfPow(0x04, (byte)0x03)}
//    };

    public static final byte[][] TV011D_TV4_SR = {
        {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43},
        {(byte)0x72, (byte)0x3C, (byte)0xCB, (byte)0xB2, (byte)0xF3},
        {(byte)0xB0, (byte)0x96, (byte)0xB9, (byte)0x82, (byte)0x79},
        {(byte)0x88, (byte)0xB9, (byte)0xCB, (byte)0x66, (byte)0xFA}
    };

    public static final byte[][] TV011D_TV4_SPLITS = {
        {(byte)0x19, (byte)0x52, (byte)0xF4, (byte)0x02, (byte)0x33},
        {(byte)0x79, (byte)0xFA, (byte)0x0E, (byte)0x08, (byte)0xC2},
        {(byte)0x24, (byte)0x58, (byte)0x37, (byte)0x17, (byte)0x94},
        {(byte)0xF4, (byte)0x45, (byte)0xA9, (byte)0xD6, (byte)0x07}
    };

    // Matrices for recombination
//    public static final byte[][] TV011D_TV4_1_2_3_4_R = {
//        {
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x01, (byte)0x02)), polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x01, (byte)0x03)), polynomial2.gfDiv(0x04, polynomial2.gfAdd(0x01, (byte)0x04))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x02)), polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x02, (byte)0x03)), polynomial2.gfDiv(0x04, polynomial2.gfAdd(0x02, (byte)0x04))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x03)), polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x02, (byte)0x03)), polynomial2.gfDiv(0x04, polynomial2.gfAdd(0x03, (byte)0x04))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x04)), polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x02, (byte)0x04)), polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x03, (byte)0x04))})
//        }
//    };

    public static final byte[][] TV011D_TV4_1_2_3_4_SPLITS = {
        {(byte)0x19, (byte)0x52, (byte)0xF4, (byte)0x02, (byte)0x33},
        {(byte)0x79, (byte)0xFA, (byte)0x0E, (byte)0x08, (byte)0xC2},
        {(byte)0x24, (byte)0x58, (byte)0x37, (byte)0x17, (byte)0x94},
        {(byte)0xF4, (byte)0x45, (byte)0xA9, (byte)0xD6, (byte)0x07}
    };

    // Secret to recover
    public static final byte[] TV011D_TV4_SECRET =
        {(byte)0x53, (byte)0x41, (byte)0x4D, (byte)0x54, (byte)0x43};


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
//    public static final byte[][] TV011D_TV5_P = {
//        {polynomial2.gfPow(0x01, (byte)0x00), polynomial2.gfPow(0x01, (byte)0x01)},
//        {polynomial2.gfPow(0x02, (byte)0x00), polynomial2.gfPow(0x02, (byte)0x01)},
//        {polynomial2.gfPow(0x03, (byte)0x00), polynomial2.gfPow(0x03, (byte)0x01)},
//        {polynomial2.gfPow(0x04, (byte)0x00), polynomial2.gfPow(0x04, (byte)0x01)},
//        {polynomial2.gfPow(0x05, (byte)0x00), polynomial2.gfPow(0x05, (byte)0x01)},
//        {polynomial2.gfPow(0x06, (byte)0x00), polynomial2.gfPow(0x06, (byte)0x01)},
//        {polynomial2.gfPow(0x07, (byte)0x00), polynomial2.gfPow(0x07, (byte)0x01)},
//        {polynomial2.gfPow(0x08, (byte)0x00), polynomial2.gfPow(0x08, (byte)0x01)},
//        {polynomial2.gfPow(0x09, (byte)0x00), polynomial2.gfPow(0x09, (byte)0x01)}
//    };

    public static final byte[][] TV011D_TV5_SR = {
        {(byte)0x54, (byte)0x65, (byte)0x73, (byte)0x74, (byte)0x20, (byte)0x44, (byte)0x61, (byte)0x74, (byte)0x61},
        {(byte)0xAF, (byte)0xFD, (byte)0x2B, (byte)0x0B, (byte)0xFA, (byte)0x34, (byte)0x33, (byte)0x63, (byte)0x9C}
    };

    public static final byte[][] TV011D_TV5_SPLITS = {
        {(byte)0xFB, (byte)0x98, (byte)0x58, (byte)0x7F, (byte)0xDA, (byte)0x70, (byte)0x52, (byte)0x17, (byte)0xFD},
        {(byte)0x17, (byte)0x82, (byte)0x25, (byte)0x62, (byte)0xC9, (byte)0x2C, (byte)0x07, (byte)0xB2, (byte)0x44},
        {(byte)0xB8, (byte)0x7F, (byte)0x0E, (byte)0x69, (byte)0x33, (byte)0x18, (byte)0x34, (byte)0xD1, (byte)0xD8},
        {(byte)0xD2, (byte)0xB6, (byte)0xDF, (byte)0x58, (byte)0xEF, (byte)0x94, (byte)0xAD, (byte)0xE5, (byte)0x2B},
        {(byte)0x7D, (byte)0x4B, (byte)0xF4, (byte)0x53, (byte)0x15, (byte)0xA0, (byte)0x9E, (byte)0x86, (byte)0xB7},
        {(byte)0x91, (byte)0x51, (byte)0x89, (byte)0x4E, (byte)0x06, (byte)0xFC, (byte)0xCB, (byte)0x23, (byte)0x0E},
        {(byte)0x3E, (byte)0xAC, (byte)0xA2, (byte)0x45, (byte)0xFC, (byte)0xC8, (byte)0xF8, (byte)0x40, (byte)0x92},
        {(byte)0x45, (byte)0xDE, (byte)0x36, (byte)0x2C, (byte)0xA3, (byte)0xF9, (byte)0xE4, (byte)0x4B, (byte)0xF5},
        {(byte)0xEA, (byte)0x23, (byte)0x1D, (byte)0x27, (byte)0x59, (byte)0xCD, (byte)0xD7, (byte)0x28, (byte)0x69}
    };

    // Matrices for recombination
//    public static final byte[][] TV011D_TV5_1_2_R = {
//        {polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x01, (byte)0x02)), polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x02))}
//    };
//
//    public static final byte[][] TV011D_TV5_8_9_R = {
//        {polynomial2.gfDiv(0x09, polynomial2.gfAdd(0x08, (byte)0x09)), polynomial2.gfDiv(0x08, polynomial2.gfAdd(0x08, (byte)0x09))}
//    };

    public static final byte[][] TV011D_TV5_1_2_SPLITS = {
        {(byte)0xFB, (byte)0x98, (byte)0x58, (byte)0x7F, (byte)0xDA, (byte)0x70, (byte)0x52, (byte)0x17, (byte)0xFD},
        {(byte)0x17, (byte)0x82, (byte)0x25, (byte)0x62, (byte)0xC9, (byte)0x2C, (byte)0x07, (byte)0xB2, (byte)0x44}
    };

    public static final byte[][] TV011D_TV5_8_9_SPLITS = {
        {(byte)0x45, (byte)0xDE, (byte)0x36, (byte)0x2C, (byte)0xA3, (byte)0xF9, (byte)0xE4, (byte)0x4B, (byte)0xF5},
        {(byte)0xEA, (byte)0x23, (byte)0x1D, (byte)0x27, (byte)0x59, (byte)0xCD, (byte)0xD7, (byte)0x28, (byte)0x69}
    };

    // Secret to recover
    public static final byte[] TV011D_TV5_SECRET =
        {(byte)0x54, (byte)0x65, (byte)0x73, (byte)0x74, (byte)0x20, (byte)0x44, (byte)0x61, (byte)0x74, (byte)0x61};


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
//    private static final byte[][] TV011D_TV6_P = {
//        {polynomial2.gfPow(0x01, (byte)0x00), polynomial2.gfPow(0x01, (byte)0x01), polynomial2.gfPow(0x01, (byte)0x02)},
//        {polynomial2.gfPow(0x02, (byte)0x00), polynomial2.gfPow(0x02, (byte)0x01), polynomial2.gfPow(0x02, (byte)0x02)},
//        {polynomial2.gfPow(0x03, (byte)0x00), polynomial2.gfPow(0x03, (byte)0x01), polynomial2.gfPow(0x03, (byte)0x02)},
//        {polynomial2.gfPow(0x04, (byte)0x00), polynomial2.gfPow(0x04, (byte)0x01), polynomial2.gfPow(0x04, (byte)0x02)},
//        {polynomial2.gfPow(0x05, (byte)0x00), polynomial2.gfPow(0x05, (byte)0x01), polynomial2.gfPow(0x05, (byte)0x02)}
//    };

    private static final byte[][] TV011D_TV6_SR = {
        {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F},
        {(byte)0x02, (byte)0x89, (byte)0x96, (byte)0x98, (byte)0x77, (byte)0xB0, (byte)0x11, (byte)0x94, (byte)0x54, (byte)0xDE, (byte)0x9C, (byte)0xC3, (byte)0x48, (byte)0x4D, (byte)0xF8},
        {(byte)0x4A, (byte)0xAC, (byte)0x8C, (byte)0x65, (byte)0xFE, (byte)0x24, (byte)0x6B, (byte)0xF6, (byte)0xDD, (byte)0x20, (byte)0x3C, (byte)0xE4, (byte)0x88, (byte)0x31, (byte)0xC8}
    };

    private static final byte[][] TV011D_TV6_SPLITS = {
        {(byte)0x49, (byte)0x27, (byte)0x19, (byte)0xF9, (byte)0x8C, (byte)0x92, (byte)0x7D, (byte)0x6A, (byte)0x80, (byte)0xF4, (byte)0xAB, (byte)0x2B, (byte)0xCD, (byte)0x72, (byte)0x3F},
        {(byte)0x30, (byte)0x87, (byte)0x38, (byte)0xA0, (byte)0x34, (byte)0xEB, (byte)0x94, (byte)0xC2, (byte)0xF2, (byte)0x2B, (byte)0xDE, (byte)0x20, (byte)0x87, (byte)0x50, (byte)0xE5},
        {(byte)0x78, (byte)0xA2, (byte)0x22, (byte)0x5D, (byte)0xBD, (byte)0x7F, (byte)0xEE, (byte)0xA0, (byte)0x7B, (byte)0xD5, (byte)0x7E, (byte)0x07, (byte)0x47, (byte)0x2C, (byte)0xD5},
        {(byte)0xDD, (byte)0x0E, (byte)0x49, (byte)0x40, (byte)0x9F, (byte)0x86, (byte)0xBD, (byte)0xB9, (byte)0x15, (byte)0x6F, (byte)0xA6, (byte)0xC1, (byte)0x58, (byte)0x10, (byte)0xD4},
        {(byte)0x95, (byte)0x2B, (byte)0x53, (byte)0xBD, (byte)0x16, (byte)0x12, (byte)0xC7, (byte)0xDB, (byte)0x9C, (byte)0x91, (byte)0x06, (byte)0xE6, (byte)0x98, (byte)0x6C, (byte)0xE4}
    };

//    private static final byte[][] TV011D_TV6_1_2_3_R = {
//        {
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x01, (byte)0x02)), polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x01, (byte)0x03))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x02)), polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x02, (byte)0x03))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x01, polynomial2.gfAdd(0x01, (byte)0x03)), polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x02, (byte)0x03))})
//        }
//    };
//
//    private static final byte[][] TV011D_TV6_2_3_4_R = {
//        {
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x02, (byte)0x03)), polynomial2.gfDiv(0x04, polynomial2.gfAdd(0x02, (byte)0x04))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x02, (byte)0x03)), polynomial2.gfDiv(0x04, polynomial2.gfAdd(0x03, (byte)0x04))}),
//            polynomial2.gfProd(new byte[]{polynomial2.gfDiv(0x02, polynomial2.gfAdd(0x02, (byte)0x04)), polynomial2.gfDiv(0x03, polynomial2.gfAdd(0x03, (byte)0x04))})
//        }
//    };

    private static final byte[][] TV011D_TV6_1_2_3_SPLITS = {
        {(byte)0x49, (byte)0x27, (byte)0x19, (byte)0xF9, (byte)0x8C, (byte)0x92, (byte)0x7D, (byte)0x6A, (byte)0x80, (byte)0xF4, (byte)0xAB, (byte)0x2B, (byte)0xCD, (byte)0x72, (byte)0x3F},
        {(byte)0x30, (byte)0x87, (byte)0x38, (byte)0xA0, (byte)0x34, (byte)0xEB, (byte)0x94, (byte)0xC2, (byte)0xF2, (byte)0x2B, (byte)0xDE, (byte)0x20, (byte)0x87, (byte)0x50, (byte)0xE5},
        {(byte)0x78, (byte)0xA2, (byte)0x22, (byte)0x5D, (byte)0xBD, (byte)0x7F, (byte)0xEE, (byte)0xA0, (byte)0x7B, (byte)0xD5, (byte)0x7E, (byte)0x07, (byte)0x47, (byte)0x2C, (byte)0xD5}
    };

    private static final byte[][] TV011D_TV6_2_3_4_SPLITS = {
        {(byte)0x30, (byte)0x87, (byte)0x38, (byte)0xA0, (byte)0x34, (byte)0xEB, (byte)0x94, (byte)0xC2, (byte)0xF2, (byte)0x2B, (byte)0xDE, (byte)0x20, (byte)0x87, (byte)0x50, (byte)0xE5},
        {(byte)0x78, (byte)0xA2, (byte)0x22, (byte)0x5D, (byte)0xBD, (byte)0x7F, (byte)0xEE, (byte)0xA0, (byte)0x7B, (byte)0xD5, (byte)0x7E, (byte)0x07, (byte)0x47, (byte)0x2C, (byte)0xD5},
        {(byte)0xDD, (byte)0x0E, (byte)0x49, (byte)0x40, (byte)0x9F, (byte)0x86, (byte)0xBD, (byte)0xB9, (byte)0x15, (byte)0x6F, (byte)0xA6, (byte)0xC1, (byte)0x58, (byte)0x10, (byte)0xD4}
    };

    private static final byte[] TV011D_TV6_SECRET =
        {(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F};

    private interface PolynomialFactory
    {
        ShamirSecretSplitter newInstance(int l, int m, int n, SecureRandom random);

        ShamirSplitSecret newInstance(ShamirSplitSecretShare[] secretShares);
    }

    @Override
    public String getName()
    {
        return "Polynomial Test";
    }

    public void testPolynomial()
        throws IOException
    {
        testPolynoimial1(new PolynomialFactory()
        {
            @Override
            public ShamirSecretSplitter newInstance(int l, int m, int n, SecureRandom random)
            {
                return new ShamirSecretSplitter(ShamirSecretSplitter.Algorithm.AES, ShamirSecretSplitter.Mode.Native, l, random);
            }

            @Override
            public ShamirSplitSecret newInstance(ShamirSplitSecretShare[] secretShares)
            {
                return new ShamirSplitSecret(ShamirSecretSplitter.Algorithm.AES, ShamirSecretSplitter.Mode.Native, secretShares);
            }

        });
        testPolynoimial1(new PolynomialFactory()
        {
            @Override
            public ShamirSecretSplitter newInstance(int l, int m, int n, SecureRandom random)
            {
                return new ShamirSecretSplitter(ShamirSecretSplitter.Algorithm.AES, ShamirSecretSplitter.Mode.Table, l, random);
            }

            @Override
            public ShamirSplitSecret newInstance(ShamirSplitSecretShare[] secretShares)
            {
                return new ShamirSplitSecret(ShamirSecretSplitter.Algorithm.AES, ShamirSecretSplitter.Mode.Table, secretShares);
            }
        });

        testPolynoimial2(new PolynomialFactory()
        {
            @Override
            public ShamirSecretSplitter newInstance(int l, int m, int n, SecureRandom random)
            {
                return new ShamirSecretSplitter(ShamirSecretSplitter.Algorithm.RSA, ShamirSecretSplitter.Mode.Native, l, random);
            }

            @Override
            public ShamirSplitSecret newInstance(ShamirSplitSecretShare[] secretShares)
            {
                return new ShamirSplitSecret(ShamirSecretSplitter.Algorithm.RSA, ShamirSecretSplitter.Mode.Native, secretShares);
            }
        });

        testPolynoimial2(new PolynomialFactory()
        {
            @Override
            public ShamirSecretSplitter newInstance(int l, int m, int n, SecureRandom random)
            {
                return new ShamirSecretSplitter(ShamirSecretSplitter.Algorithm.RSA, ShamirSecretSplitter.Mode.Table, l, random);
            }

            @Override
            public ShamirSplitSecret newInstance(ShamirSplitSecretShare[] secretShares)
            {
                return new ShamirSplitSecret(ShamirSecretSplitter.Algorithm.RSA, ShamirSecretSplitter.Mode.Table, secretShares);
            }
        });
    }

    private void testPolynoimial1(PolynomialFactory polynomialFactory)
        throws IOException
    {
        ShamirSecretSplitter splitter = polynomialFactory.newInstance(5, 2, 2, getSecureRandom(TV011B_TV1_SR));
        testMatrixMultiplication(splitter, TV011B_TV1_SPLITS, 2, 2);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2}, TV011B_TV1_1_2_SPLITS)), TV011B_TV1_SECRET);
        splitter = polynomialFactory.newInstance(5, 2, 4, getSecureRandom(TV011B_TV2_SR));
        testMatrixMultiplication(splitter, TV011B_TV2_SPLITS, 2, 4);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2}, TV011B_TV2_1_2_SPLITS)), TV011B_TV2_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 4}, TV011B_TV2_1_4_SPLITS)), TV011B_TV2_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{3, 4}, TV011B_TV2_3_4_SPLITS)), TV011B_TV2_SECRET);
        splitter = polynomialFactory.newInstance(5, 3, 4, getSecureRandom(TV011B_TV3_SR));
        testMatrixMultiplication(splitter, TV011B_TV3_SPLITS, 3, 4);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2, 3}, TV011B_TV3_1_2_3_SPLITS)), TV011B_TV3_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2, 4}, TV011B_TV3_1_2_4_SPLITS)), TV011B_TV3_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 3, 4}, TV011B_TV3_1_3_4_SPLITS)), TV011B_TV3_SECRET);
        splitter = polynomialFactory.newInstance(5, 4, 4, getSecureRandom(TV011B_TV4_SR));
        testMatrixMultiplication(splitter, TV011B_TV4_SPLITS, 4, 4);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2, 3, 4}, TV011B_TV4_1_2_3_4_SPLITS)), TV011B_TV4_SECRET);
        splitter = polynomialFactory.newInstance(9, 2, 9, getSecureRandom(TV011B_TV5_SR));
        testMatrixMultiplication(splitter, TV011B_TV5_SPLITS, 2, 9);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2}, TV011B_TV5_1_2_SPLITS)), TV011B_TV5_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{8, 9}, TV011B_TV5_8_9_SPLITS)), TV011B_TV5_SECRET);
        splitter = polynomialFactory.newInstance(15, 3, 5, getSecureRandom(TV011B_TV6_SR));
        testMatrixMultiplication(splitter, TV011B_TV6_SPLITS, 3, 5);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2, 3}, TV011B_TV6_1_2_3_SPLITS)), TV011B_TV6_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{2, 3, 4}, TV011B_TV6_2_3_4_SPLITS)), TV011B_TV6_SECRET);
    }

    private void testPolynoimial2(PolynomialFactory polynomialFactory)
        throws IOException
    {
        ShamirSecretSplitter poly = polynomialFactory.newInstance(5, 2, 2, getSecureRandom(TV011D_TV1_SR));
        testMatrixMultiplication(poly, TV011D_TV1_SPLITS, 2, 2);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2}, TV011D_TV1_1_2_SPLITS)), TV011D_TV1_SECRET);
        poly = polynomialFactory.newInstance(5, 2, 4, getSecureRandom(TV011D_TV2_SR));
        testMatrixMultiplication(poly, TV011D_TV2_SPLITS, 2, 4);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2}, TV011D_TV2_1_2_SPLITS)), TV011D_TV2_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 4}, TV011D_TV2_1_4_SPLITS)), TV011D_TV2_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{3, 4}, TV011D_TV2_3_4_SPLITS)), TV011D_TV2_SECRET);
        poly = polynomialFactory.newInstance(5, 3, 4, getSecureRandom(TV011D_TV3_SR));
        testMatrixMultiplication(poly, TV011D_TV3_SPLITS, 3, 4);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2, 3}, TV011D_TV3_1_2_3_SPLITS)), TV011D_TV3_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2, 4}, TV011D_TV3_1_2_4_SPLITS)), TV011D_TV3_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 3, 4}, TV011D_TV3_1_3_4_SPLITS)), TV011D_TV3_SECRET);
        poly = polynomialFactory.newInstance(5, 4, 4, getSecureRandom(TV011D_TV4_SR));
        testMatrixMultiplication(poly, TV011D_TV4_SPLITS, 4, 4);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2, 3, 4}, TV011D_TV4_1_2_3_4_SPLITS)), TV011D_TV4_SECRET);
        poly = polynomialFactory.newInstance(9, 2, 9, getSecureRandom(TV011D_TV5_SR));
        testMatrixMultiplication(poly, TV011D_TV5_SPLITS, 2, 9);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2}, TV011D_TV5_1_2_SPLITS)), TV011D_TV5_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{8, 9}, TV011D_TV5_8_9_SPLITS)), TV011D_TV5_SECRET);
        poly = polynomialFactory.newInstance(15, 3, 5, getSecureRandom(TV011D_TV6_SR));
        testMatrixMultiplication(poly, TV011D_TV6_SPLITS, 3, 5);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{1, 2, 3}, TV011D_TV6_1_2_3_SPLITS)), TV011D_TV6_SECRET);
        testRecombine(polynomialFactory.newInstance(getShamirSplitSecretShareArray(new int[]{2, 3, 4}, TV011D_TV6_2_3_4_SPLITS)), TV011D_TV6_SECRET);
    }

    static SecureRandom getSecureRandom(byte[][] sr)
    {
        byte[] source = new byte[sr.length * sr[0].length];
        int currentIndex = 0;

        for (int i = 0; i != sr.length; i++)
        {
            byte[] subArray = sr[i];
            System.arraycopy(subArray, 0, source, currentIndex, subArray.length);
            currentIndex += subArray.length;
        }
        return new FixedSecureRandom(new FixedSecureRandom.Source[]{new FixedSecureRandom.Data(source)});
    }

    static ShamirSplitSecretShare[] getShamirSplitSecretShareArray(int[] rr, byte[][] splits)
    {
        ShamirSplitSecretShare[] secretShares = new ShamirSplitSecretShare[rr.length];
        for (int i = 0; i < secretShares.length; ++i)
        {
            secretShares[i] = new ShamirSplitSecretShare(splits[i], rr[i]);
        }
        return secretShares;
    }

    static void testMatrixMultiplication(ShamirSecretSplitter poly, byte[][] splits, int m, int n)
        throws IOException
    {
        SecretShare[] secretShares = poly.split(m, n).getSecretShares();
        byte[][] result = new byte[splits.length][splits[0].length];
        for (int i = 0; i < result.length; ++i)
        {
            result[i] = secretShares[i].getEncoded();
            assertTrue(Arrays.areEqual(splits[i], result[i]));
        }
    }

    public void testRecombine(ShamirSplitSecret splitSecret, byte[] secret)
        throws IOException
    {
        byte[] result = splitSecret.getSecret();
        assertTrue(Arrays.areEqual(secret, result));
    }
}
