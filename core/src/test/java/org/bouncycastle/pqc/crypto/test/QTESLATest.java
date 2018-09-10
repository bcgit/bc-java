package org.bouncycastle.pqc.crypto.test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.qtesla.CommonFunction;
import org.bouncycastle.pqc.crypto.qtesla.Parameter;
import org.bouncycastle.pqc.crypto.qtesla.Polynomial;
import org.bouncycastle.pqc.crypto.qtesla.PolynomialProvablySecure;
import org.bouncycastle.pqc.crypto.qtesla.QTESLA;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.crypto.qtesla.RandomNumberGenerator;
import org.bouncycastle.pqc.crypto.qtesla.Sample;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

public class QTESLATest
    extends TestCase
{

    static SecureRandom secureRandom = new SecureRandom();
    static short shortNumber = (short)0xCCDD;
    static int integerNumber = 0xCCDDEEFF;
    static long longNumber = 0xCCDDEEFFAABB0011L;

    static byte[] byteArray = {

        (byte)0xAB, (byte)0xBC, (byte)0xCD, (byte)0xDE,
        (byte)0xEF, (byte)0xF0, (byte)0x01, (byte)0x12,
        (byte)0x23, (byte)0x34, (byte)0x45, (byte)0x56,
        (byte)0x67, (byte)0x78, (byte)0x89, (byte)0x9A

    };

    static byte[] seed = {

        (byte)0x12, (byte)0x23, (byte)0x34, (byte)0x45, (byte)0x56, (byte)0x67, (byte)0x78, (byte)0x89,
        (byte)0x9A, (byte)0xAB, (byte)0xBC, (byte)0xCD, (byte)0xDE, (byte)0xEF, (byte)0xF1, (byte)0x13,
        (byte)0x24, (byte)0x35, (byte)0x46, (byte)0x57, (byte)0x68, (byte)0x79, (byte)0x8A, (byte)0x9B,
        (byte)0xAC, (byte)0xBD, (byte)0xCE, (byte)0xDF, (byte)0xE1, (byte)0xF2, (byte)0x14, (byte)0x25

    };

    /* Test for Memory Equivalence in Common Function */

    public void testMemoryEquivalence()
    {

        System.out.println("Test for Memory Equivalence in Common Function\n");

        byte[] newByteArray = new byte[8];

        System.arraycopy(newByteArray, 0, byteArray, 2, 8);

        System.out.printf("%B\n\n", CommonFunction.memoryEqual(byteArray, 2, newByteArray, 0, 8));

        Arrays.fill(newByteArray, (byte)0xAA);

        System.out.printf("%B\n\n", CommonFunction.memoryEqual(byteArray, 2, newByteArray, 0, 8));

    }

    /* Test for Loading Short Number in Common Function */

    public void testLoadShortNumber()
    {

        System.out.println("Test for Loading Short Number in Common Function\n");

        System.out.printf("%X\n\n", CommonFunction.load16(byteArray, 15));

    }

    /* Test for Loading Integer Number in Common Function */

    public void testLoadIntegerNumber()
    {

        System.out.println("Test for Loading Integer Number in Common Function\n");

        System.out.printf("%X\n\n", CommonFunction.load32(byteArray, 13));

    }

    /* Test for Loading Long Number in Common Function */

    public void testLoadLongNumber()
    {

        System.out.println("Test for Loading Long Number in Common Function\n");

        System.out.printf("%X\n\n", CommonFunction.load64(byteArray, 9));

    }

    /* Test for Storing Short Number in Common Function */

    public void testStoreShortNumber()
    {

        System.out.println("Test for Storing Short Number in Common Function\n");

        byte[] newByteArray = new byte[Long.SIZE];

        CommonFunction.store16(newByteArray, 4, shortNumber);

        for (short i = 0; i < Short.SIZE / Byte.SIZE; i++)
        {

            System.out.printf("%02X\t", newByteArray[i + 4]);

        }

        System.out.printf("\n\n");

    }

    /* Test for Storing Integer Number in Common Function */

    public void testStoreIntegerNumber()
    {

        byte[] newByteArray = new byte[Long.SIZE];

        System.out.println("Test for Storing Integer Number in Common Function\n");

        CommonFunction.store32(newByteArray, 4, integerNumber);

        for (short i = 0; i < Integer.SIZE / Byte.SIZE; i++)
        {

            System.out.printf("%02X\t", newByteArray[i + 4]);

        }

        System.out.printf("\n\n");

    }

    /* Test for Storing Long Number in Common Function */

    public void testStoreLongNumber()
    {

        System.out.println("Test for Storing Long Number in Common Function\n");

        byte[] newByteArray = new byte[Long.SIZE];

        CommonFunction.store64(newByteArray, 0, longNumber);

        for (short i = 0; i < Long.SIZE / Byte.SIZE; i++)
        {

            System.out.printf("%02X\t", newByteArray[i]);

        }

        System.out.printf("\n\n");

    }

    /* Test for Left Bit Rotation in Federal Information Processing Standard 202 */

//	public static void testLeftBitRotation () {
//		
//		System.out.println ("Test for Left Bit Rotation in Federal Information Processing Standard 202\n");
//		
//		System.out.printf ("%X\n\n", fips.leftRotation (longNumber, (short) 16));
//		
//	}

    /* Test for Theta Step 1 in Federal Information Processing Standard 202 */

//	public static void testThetaStep1 () {
//		
//		System.out.println ("Test for Theta Step 1 in Federal Information Processing Standard 202\n");
//		
//		long[] longArray1 = new long[25];
//		long[] longArray2 = new long[5];
//		
//		for (short i = 0; i < 25; i++) {
//			
//			longArray1[i] = PolynomialProvablySecure.ZETA_III_P[i];
//			
//		}
//		
//		fips.thetaStep1 (longArray2, longArray1);
//		
//		for (short i = 0; i < 5; i++) {
//			
//			System.out.printf ("%08X\t", longArray2[i]);
//			
//		}
//		
//		System.out.printf ("\n\n");
//		
//	}

    /* Test for Theta Step 2 in Federal Information Processing Standard 202 */

//	public static void testThetaStep2 () {
//		
//		System.out.println ("Test for Theta Step 2 in Federal Information Processing Standard 202\n");
//		
//		long[] longArray1 = new long[5];
//		long[] longArray2 = new long[5];
//		
//		function.memoryCopy (PolynomialProvablySecure.ZETA_III_P, 0, longArray1, 0, 5);
//		
//		fips.thetaStep2 (longArray2, longArray1);
//		
//		for (short i = 0; i < 5; i++) {
//			
//			System.out.printf ("%08X\t", longArray2[i]);
//			
//		}
//		
//		System.out.printf ("\n\n");
//		
//	}

    /* Test for CHI in Federal Information Processing Standard 202 */

//	public static void testChi () {
//		
//		System.out.println ("Test for CHI in Federal Information Processing Standard 202\n");
//		
//		long[] longArray1 = new long[25];
//		long[] longArray2 = new long[5];
//		
//		function.memoryCopy (longArray1, 0, PolynomialProvablySecure.ZETA_III_P, 25, 25);
//		function.memoryCopy (longArray2, 0, PolynomialProvablySecure.ZETA_III_P, 50, 5);
//		
//		fips.chi (longArray1, longArray2, (short)  0, (short)  5);
//		fips.chi (longArray1, longArray2, (short)  5, (short) 10);
//		fips.chi (longArray1, longArray2, (short) 10, (short) 15);
//		fips.chi (longArray1, longArray2, (short) 15, (short) 20);
//		fips.chi (longArray1, longArray2, (short) 20, (short) 25);
//		
//		for (short i = 0; i < 25; i++) {
//			
//			System.out.printf ("%08X\t", longArray1[i]);
//			
//			if (i % 5 == 4) {
//				
//				System.out.println ("LINE " + (i / 5 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for State Permutation in Federal Information Processing Standard 202 */

//	public static void testStatePermutation () {
//		
//		System.out.println ("Test for State Permutation in Federal Information Processing Standard 202\n");
//		
//		long[] longArray1 = new long[25];
//		long[] longArray2 = new long[5];
//		long[] longArray3 = new long[5];
//		long[] longArray4 = new long[25];
//		
//		function.memoryCopy (longArray1, 0, PolynomialProvablySecure.ZETA_III_P, 75,	25);
//		function.memoryCopy (longArray2, 0, PolynomialProvablySecure.ZETA_III_P, 100,	 5);
//		function.memoryCopy (longArray3, 0, PolynomialProvablySecure.ZETA_III_P, 125,	 5);
//		function.memoryCopy (longArray4, 0, PolynomialProvablySecure.ZETA_III_P, 150,	25);
//		
//		fips.statePermutation (longArray1, longArray2, longArray3, longArray4, (short) 2);
//		
//		for (short i = 0; i < 25; i++) {
//			
//			System.out.printf ("%016X\t", longArray4[i]);
//			
//			if (i % 5 == 4) {
//				
//				System.out.println ("LINE " + (i / 5 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for KECCAK F1600 State Permutation in Federal Information Processing Standard 202 */

//	public static void testKECCAKF1600StatePermutation () {
//		
//		System.out.println ("Test for KECCAK F1600 State Permutation in Federal Information Processing Standard 202\n");
//		
//		long[] longArray = new long[25];
//		
//		function.memoryCopy (longArray, 0, PolynomialProvablySecure.ZETA_III_P, 175, 25);
//		
//		fips.keccakF1600StatePermution (longArray);
//		
//		for (short i = 0; i < 25; i++) {
//			
//			System.out.printf ("%016X\t", longArray[i]);
//			
//			if (i % 5 == 4) {
//				
//				System.out.println ("LINE " + (i / 5 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Modulus 7 in Sample */

//	public static void testModulus7 () {
//		
//		System.out.println ("Test for Modulus 7 in Sample\n");
//		
//		System.out.printf ("%X\n\n", Sample.modulus7 (0xABCDEFEDCBABCDEFL));
//		
//	}

    /* Test for Bernoulli in Sample */

//	public static void testBernoulli () {
//		
//		System.out.println ("Test for Bernoulli in Sample\n");
//		
//		System.out.printf ("%X\n\n", sample.bernoulli (0x123456789ABCDEF0L, 0x56789ABCDEF01234L, Sample.EXPONENTIAL_DISTRIBUTION_P));
//		
//	}

    /* Test for Sampling Y in Sample for Provably-Secure qTESLA Security Category-3 */

    public static void testSampleYIIIP()
    {

        long[] Y = new long[Parameter.N_III_P];

        System.out.println("Test for Sampling Y in Sample for Provably-Secure qTESLA Security Category-3\n");

        Sample.sampleY(Y, seed, 0, 16, Parameter.N_III_P, Parameter.Q_III_P, Parameter.B_III_P, Parameter.B_BIT_III_P);

        for (short i = 0; i < Parameter.N_III_P; i++)
        {

            System.out.printf("%016X\t", Y[i]);

            if (i % 4 == 3)
            {

                System.out.printf("LINE %3d\n", (i / 4 + 1));

            }

        }

        System.out.printf("\n");

    }

    /* Test for Polynomial Gauss Sampler in Sample for Heuristic qTESLA Security Category-1 */

    public static void testPolynomialGaussSamplerI()
    {

        System.out.println("Test for Polynomial Gauss Sampler in Sample for Heuristic qTESLA Security Category-1\n");

        long[] data = new long[Parameter.N_I];

        Sample.polynomialGaussSamplerI(data, 0, seed, 0, 128, Parameter.N_I, Parameter.XI_I, Sample.EXPONENTIAL_DISTRIBUTION_I);

        for (short i = 0; i < Parameter.N_I; i++)
        {

            System.out.printf("%016X\t", data[i]);

            if (i % 4 == 3)
            {

                System.out.printf("LINE %3d\n", (i / 4 + 1));

            }

        }

        System.out.printf("\n");

    }

    /* Test for Polynomial Gauss Sampler in Sample for Provably-Secure qTESLA Security Category-3 */

    public static void testPolynomialGaussSamplerIIIP()
    {

        System.out.println("Test for Polynomial Gauss Sampler in Sample for Provably-Secure qTESLA Security Category-3\n");

        long[] data = new long[Parameter.N_III_P];

        Sample.polynomialGaussSamplerIII(data, 0, seed, 0, 256, Parameter.N_III_P, Parameter.XI_III_P, Sample.EXPONENTIAL_DISTRIBUTION_P);

        for (short i = 0; i < Parameter.N_III_P; i++)
        {

            System.out.printf("%016X\t", data[i]);

            if (i % 4 == 3)
            {

                System.out.printf("LINE %3d\n", (i / 4 + 1));

            }

        }

        System.out.printf("\n");

    }

    /* Test for Encoding C in Sample for Provably-Secure qTESLA Security Category-3 */

    public static void testEncodeC()
    {

        System.out.println("Test for Encoding C in Sample\n");

        int[] positionList = new int[Parameter.W_III_P];
        short[] signList = new short[Parameter.W_III_P];

        Sample.encodeC(positionList, signList, seed, 0, Parameter.N_III_P, Parameter.W_III_P);

        System.out.println("Position List\n");

        for (short i = 0; i < Parameter.W_III_P; i++)
        {

            System.out.printf("%4d\t", positionList[i]);

            if (i % 8 == 7)
            {

                System.out.printf("LINE %d\n", (i / 8 + 1));

            }

        }

        System.out.println("\nSignature List\n");

        for (short i = 0; i < Parameter.W_III_P; i++)
        {

            if (signList[i] > 0)
            {

                System.out.printf("+");

            }

            System.out.printf("%d\t", signList[i]);

            if (i % 8 == 7)
            {

                System.out.printf("LINE %d\n", (i / 8 + 1));

            }

        }

    }

    /* Test for Montgomery Reduction in Polynomial */

//	public static void testMontgomeryReduction () {
//		
//		System.out.println ("Test for Montgomery Reduction in Polynomial\n");
//		
//		System.out.printf ("%X\n\n", polynomial.montgomery (longNumber, Parameter.N_III_P, Parameter.Q_INVERSE_III_P));
//		
//	}

    /* Test for Barrett Reduction in Polynomial for Heuristic qTESLA Security Category-3 (Option for Size) */

    public static void testBarrettReductionIIISize()
    {

        System.out.println("Test for Barrett Reduction in Polynomial for Heuristic qTESLA Security Category-3 (Option for Size)\n");

        System.out.printf("%X\n\n", Polynomial.barrett(longNumber, Parameter.Q_III_SIZE, Parameter.BARRETT_MULTIPLICATION_III_SIZE, Parameter.BARRETT_DIVISION_III_SIZE));

    }

    /* Test for Barrett Reduction in Polynomial for Provably-Secure qTESLA Security Category-3 */

    public static void testBarrettReductionIIIP()
    {

        System.out.println("Test for Barrett Reduction in Polynomial for Provably-Secure qTESLA Security Category-3\n");

        System.out.printf("%X\n\n", Polynomial.barrettP(longNumber, Parameter.Q_III_P, Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P));

    }

    /* Test for Number Theoretic Transform in Polynomial for Heuristic qTESLA Security Category-3 (Option for Size) */

//	public static void testNumberTheoreticTransformIIISize() {
//		
//		System.out.println ("Test for Number Theoretic Transform in Polynomial for Heuristic qTESLA Security Category-3 (Option for Size)\n");
//		
//		long[] longArray = new long[Parameter.N_III_SIZE];
//		
//		for (short i = 0; i < Parameter.N_III_SIZE; i++) {
//			
//			longArray[i] = PolynomialHeuristic.ZETA_III_SIZE[i];
//			
//		}
//		
//		polynomial.numberTheoreticTransform (longArray, PolynomialHeuristic.ZETA_INVERSE_III_SIZE, Parameter.N_III_SIZE, Parameter.Q_III_SIZE, Parameter.Q_INVERSE_III_SIZE);
//		
//		for (short i = 0; i < Parameter.N_III_SIZE; i++) {
//			
//			System.out.printf ("%06X\t", longArray[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %2d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Number Theoretic Transform in Polynomial for Provably-Secure qTESLA Security Category-3 */

//	public static void testNumberTheoreticTransformIIIP () {
//		
//		System.out.println ("Test for Number Theoretic Transform in Polynomial for Provably-Secure qTESLA Security Category-3\n");
//		
//		long[] longArray = new long[Parameter.N_III_P];
//	
//		for (short i = 0; i < Parameter.N_III_P; i++) {
//		
//			longArray[i] = PolynomialProvablySecure.ZETA_III_P[i];
//		
//		}
//	
//		polynomial.numberTheoreticTransform (longArray, PolynomialProvablySecure.ZETA_INVERSE_III_P);
//	
//		for (short i = 0; i < Parameter.N_III_P; i++) {
//		
//			System.out.printf ("%016X\t", longArray[i]);
//		
//			if (i % 4 == 3) {
//			
//				System.out.printf ("LINE %3d\n", (i / 4 + 1));
//			
//			}
//		
//		}
//	
//		System.out.printf ("\n");
//		
//	}

    /* Test for Inverse Number Theoretic Transform in Polynomial for Heuristic qTESLA Security Category-1 */

//	public static void testInverseNumberTheoreticTransformI () {
//		
//		System.out.println ("Test for Inverse Number Theoretic Transform in Polynomial for Heuristic qTESLA Security Category-1\n");
//		
//		long[] longArray = new long[Parameter.N_I];
//		
//		for (short i = 0; i < Parameter.N_I; i++) {
//			
//			longArray[i] = PolynomialHeuristic.ZETA_I[i];
//			
//		}
//		
//		polynomial.inverseNumberTheoreticTransformI (longArray, PolynomialHeuristic.ZETA_INVERSE_I);
//		
//		for (short i = 0; i < Parameter.N_I; i++) {
//			
//			System.out.printf ("%06X\t", longArray[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %2d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Inverse Number Theoretic Transform in Polynomial for Heuristic qTESLA Security Category-3 (Option for Size) */

//	public static void testInverseNumberTheoreticTransformIIISize () {
//		
//		System.out.println ("Test for Inverse Number Theoretic Transform in Polynomial for Heuristic qTESLA Security Category-3 (Option for Size)\n");
//		
//		long[] longArray = new long[Parameter.N_III_SIZE];
//		
//		for (short i = 0; i < Parameter.N_III_SIZE; i++) {
//		
//			longArray[i] = PolynomialHeuristic.ZETA_III_SIZE[i];
//		
//		}
//	
//		polynomial.inverseNumberTheoreticTransform (
//				longArray,
//				PolynomialHeuristic.ZETA_INVERSE_III_SIZE,
//				Parameter.N_III_SIZE,
//				Parameter.Q_III_SIZE,
//				Parameter.Q_INVERSE_III_SIZE,
//				Parameter.BARRETT_MULTIPLICATION_III_SIZE,
//				Parameter.BARRETT_DIVISION_III_SIZE
//		);
//	
//		for (short i = 0; i < Parameter.N_III_SIZE; i++) {
//		
//			System.out.printf ("%06X\t", longArray[i]);
//		
//			if (i % 16 == 15) {
//			
//				System.out.printf ("LINE %2d\n", (i / 16 + 1));
//			
//			}
//		
//		}
//	
//		System.out.printf ("\n");
//		
//	}

    /* Test for Inverse Number Theoretic Transform in Polynomial for Provably-Secure qTESLA Security Category-1 */

//	public static void testInverseNumberTheoreticTransformIP () {
//		
//		System.out.println ("Test for Inverse Number Theoretic Transform in Polynomial for Provably-Secure qTESLA Security Category-1\n");
//		
//		long[] longArray = new long[Parameter.N_I_P];
//		
//		for (short i = 0; i < Parameter.N_I_P; i++) {
//		
//			longArray[i] = PolynomialProvablySecure.ZETA_I_P[i];
//		
//		}
//	
//		polynomial.inverseNumberTheoreticTransform (
//				longArray,
//				PolynomialProvablySecure.ZETA_INVERSE_I_P,
//				Parameter.N_I_P,
//				Parameter.Q_I_P,
//				Parameter.Q_INVERSE_I_P,
//				Parameter.BARRETT_MULTIPLICATION_I_P,
//				Parameter.BARRETT_DIVISION_I_P
//		);
//	
//		for (short i = 0; i < Parameter.N_I_P; i++) {
//		
//			System.out.printf ("%08X\t", longArray[i]);
//		
//			if (i % 8 == 7) {
//			
//				System.out.printf ("LINE %3d\n", (i / 8 + 1));
//			
//			}
//		
//		}
//	
//		System.out.printf ("\n");
//		
//	}

    /* Test for Inverse Number Theoretic Transform in Polynomial for Provably-Secure qTESLA Security Category-3 */

//	public static void testInverseNumberTheoreticTransformIIIP () {
//		
//		System.out.println ("Test for Inverse Number Theoretic Transform in Polynomial for Provably-Secure qTESLA Security Category-3\n");
//		
//		long[] longArray = new long[Parameter.N_III_P];
//		
//		for (short i = 0; i < Parameter.N_III_P; i++) {
//			
//			longArray[i] = PolynomialProvablySecure.ZETA_III_P[i];
//		
//		}
//		
//		polynomial.inverseNumberTheoreticTransformIIIP (longArray, PolynomialProvablySecure.ZETA_INVERSE_III_P);
//		
//		for (short i = 0; i < Parameter.N_III_P; i++) {
//			
//			System.out.printf ("%08X\t", longArray[i]);
//		
//			if (i % 8 == 7) {
//			
//				System.out.printf ("LINE %3d\n", (i / 8 + 1));
//			
//			}
//		
//		}
//	
//		System.out.printf ("\n");
//		
//	}

    /* Test for Component Wise Polynomial Multiplication in Polynomial for Provably-Secure qTESLA Security Category-3 */

//	public static void testComponentWisePolynomialMultiplicationIIIP () {
//		
//		System.out.println ("Test for Component Wise Polynomial Multiplication in Polynomial for Provably-Secure qTESLA Security Category-3\n");
//		
//		long[] longArray = new long[Parameter.N_III_P];
//		
//		polynomial.componentWisePolynomialMultiplication (
//				longArray,
//				PolynomialProvablySecure.ZETA_III_P,
//				PolynomialProvablySecure.ZETA_INVERSE_III_P,
//				Parameter.N_III_P,
//				Parameter.Q_III_P,
//				Parameter.Q_INVERSE_III_P
//		);
//		
//		for (short i = 0; i < Parameter.N_III_P; i++) {
//			
//			System.out.printf ("%08X\t", longArray[i]);
//			
//			if (i % 8 == 7) {
//				
//				System.out.printf ("LINE %3d\n", (i / 8 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}
    
    /* Test for Polynomial Multiplication in Polynomial for Polynomial Multiplication for Provably-Secure qTESLA Security Category-3 */

    public static void testPolynomialMultiplicationIIIP()
    {

        System.out.println("Test for Polynomial Multiplication in Polynomial for Polynomial Multiplication for Provably-Secure qTESLA Security Category-3\n");

        long[] longArray = new long[Parameter.N_III_P];

        Polynomial.polynomialMultiplication(
            longArray, 0,
            PolynomialProvablySecure.ZETA_III_P, 0,
            PolynomialProvablySecure.ZETA_INVERSE_III_P, 0,
            Parameter.N_III_P,
            Parameter.Q_III_P,
            Parameter.Q_INVERSE_III_P
        );

        for (short i = 0; i < Parameter.N_III_P; i++)
        {

            System.out.printf("%08X\t", longArray[i]);

            if (i % 8 == 7)
            {

                System.out.printf("LINE %3d\n", (i / 8 + 1));

            }

        }

        System.out.printf("\n");

    }

    /* Test for Polynomial Addition in Polynomial for Provably-Secure qTESLA Security Category-3 */

    public static void testPolynomialAdditionIIIP()
    {

        System.out.println("Test for Polynomial Addition in Polynomial for Provably-Secure qTESLA Security Category-3\n");

        long[] longArray = new long[Parameter.N_III_P];

        Polynomial.polynomialAddition(longArray, 0, PolynomialProvablySecure.ZETA_III_P, 0, PolynomialProvablySecure.ZETA_INVERSE_III_P, (short)0, Parameter.N_III_P);

        for (short i = 0; i < Parameter.N_III_P; i++)
        {

            System.out.printf("%08X\t", longArray[i]);

            if (i % 8 == 7)
            {

                System.out.printf("LINE %3d\n", (i / 8 + 1));

            }

        }

        System.out.printf("\n");

    }


    /* Test for Polynomial Subtraction in Polynomial for Provably-Secure qTESLA Security Category-3 */

    public static void testPolynomialSubtractionIIIP()
    {

        System.out.println("Test for Polynomial Subtraction in Polynomial for Provably-Secure qTESLA Security Category-3\n");

        long[] longArray = new long[Parameter.N_III_P];

        Polynomial.polynomialSubtractionP(
            longArray, 0,
            PolynomialProvablySecure.ZETA_III_P, 0,
            PolynomialProvablySecure.ZETA_INVERSE_III_P, 0,
            Parameter.N_III_P,
            Parameter.Q_III_P,
            Parameter.BARRETT_MULTIPLICATION_III_P,
            Parameter.BARRETT_DIVISION_III_P
        );

        for (short i = 0; i < Parameter.N_III_P; i++)
        {

            System.out.printf("%08X\t", longArray[i]);

            if (i % 8 == 7)
            {

                System.out.printf("LINE %3d\n", (i / 8 + 1));

            }

        }

        System.out.printf("\n");

    }

    /* Test for Polynomial Uniform in Polynomial for Provably-Secure qTESLA Security Category-3 */

    public static void testPolynomialUniformIIIP()
    {

        System.out.println("Test for Polynomial Uniform in Polynomial for Provably-Secure qTESLA Security Category-3\n");

        long[] A = new long[Parameter.N_III_P * Parameter.K_III_P];

        Polynomial.polynomialUniform(
            A,
            seed, 0,
            Parameter.N_III_P, Parameter.K_III_P, Parameter.Q_III_P, Parameter.Q_INVERSE_III_P, Parameter.Q_LOGARITHM_III_P,
            Parameter.GENERATOR_A_III_P, Parameter.INVERSE_NUMBER_THEORETIC_TRANSFORM_III_P
        );

        for (short k = 0; k < Parameter.K_III_P; k++)
        {

            System.out.printf("SAMPLE %d\n\n", (k + 1));

            for (short i = 0; i < Parameter.N_III_P; i++)
            {

                System.out.printf("%08X\t", A[i]);

                if (i % 8 == 7)
                {

                    System.out.printf("LINE %3d\n", (i / 8 + 1));

                }

            }

            System.out.printf("\n");

        }

    }

    /* Test for Absolute Value in QTESLA */

//	public static void testAbsoluteValue () {
//		
//		System.out.println ("Test for Absolute Value in QTESLA\n");
//		
//		System.out.printf ("Absolute Value of %d is %d and %d\n\n", longNumber, QTESLA.absolute(longNumber), Math.abs(longNumber));
//		
//	}

    /* Test for Testing Rejection in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testTestRejectionIIIP () {
//		
//		System.out.println ("Test for Testing Rejection in QTESLA for Provably-Secure qTESLA Security Category-3\n");
//		
//		System.out.printf ("%B\n\n", QTESLA.testRejection (PolynomialProvablySecure.ZETA_III_P, Parameter.N_III_P, Parameter.B_III_P, Parameter.U_III_P));
//		
//	}

    /* Test for Testing Z in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testTestZIIIP () {
//		
//		System.out.println ("Test for Testing Z in QTESLA for Provably-Secure qTESLA Security Category-3\n");
//		
//		System.out.printf ("%B\n\n", QTESLA.testZ (PolynomialProvablySecure.ZETA_III_P, Parameter.N_III_P, Parameter.B_III_P, Parameter.U_III_P));
//		
//	}

    /* Test for Testing V in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testTestVIIIP () {
//		
//		System.out.println ("Test for Testing V in QTESLA for Provably-Secure qTESLA Security Category-3\n");
//		
//		System.out.printf ("%B\n\n", QTESLA.testV (PolynomialProvablySecure.ZETA_III_P, Parameter.N_III_P, Parameter.D_III_P, Parameter.Q_III_P, Parameter.REJECTION_III_P));
//		
//	}

    /* Test for Checking Error Polynomial in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testCheckErrorPolynomialIIIP () {
//		
//		System.out.println ("Test for Checking Error Polynomial in QTESLA\n");
//		
//		long[] errorPolynomial		= new long[Parameter.N_III_P];
//		byte[] randomnessExtended	= new byte[Polynomial.SEED_BYTE * 4];
//		
//		System.out.println ("Test for Secure Hash Algorithm KECCAK 256 in Federal Information Processing Standard 202\n");
//		
//		fips.secureHashAlgorithmKECCAK256 (
//				randomnessExtended, (short) 0, (short) (Polynomial.SEED_BYTE * 4), seed, 0, Polynomial.RANDOM_BYTE
//		);
//		
//		for (short i = 0; i < randomnessExtended.length; i++) {
//			
//			System.out.printf ("%02X\t", randomnessExtended[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//		sample.polynomialGaussSamplerIII (
//				errorPolynomial, randomnessExtended, (short) 0, 63, Parameter.N_III_P, Parameter.XI_III_P, Sample.EXPONENTIAL_DISTRIBUTION_P
//		);
//		
//		System.out.printf ("%B\n\n", QTESLA.checkPolynomial (errorPolynomial, (short) 0, Parameter.KEY_GENERATOR_BOUND_E_III_P, Parameter.N_III_P, Parameter.W_III_P));
//		
//	}

    /* Test for Checking Secret Polynomial in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testCheckSecretPolynomialIIIP () {
//		
//		System.out.println ("Test for Checking Secret Polynomial in QTESLA\n");
//		
//		long[] secretPolynomial		= new long[Parameter.N_III_P];
//		byte[] randomnessExtended	= new byte[Polynomial.SEED_BYTE * 4];
//		
//		System.out.println ("Test for Secure Hash Algorithm KECCAK 256 in Federal Information Processing Standard 202\n");
//		
//		fips.secureHashAlgorithmKECCAK256 (
//				randomnessExtended, (short) 0, (short) (Polynomial.SEED_BYTE * 4), seed, 0, Polynomial.RANDOM_BYTE
//		);
//		
//		for (short i = 0; i < randomnessExtended.length; i++) {
//			
//			System.out.printf ("%02X\t", randomnessExtended[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//		sample.polynomialGaussSamplerIII (
//				secretPolynomial, randomnessExtended, (short) 0, 63, Parameter.N_III_P, Parameter.XI_III_P, Sample.EXPONENTIAL_DISTRIBUTION_P
//		);
//		
//		System.out.printf ("%B\n\n", QTESLA.checkPolynomial (secretPolynomial, (short) 0, Parameter.KEY_GENERATOR_BOUND_S_III_P, Parameter.N_III_P, Parameter.W_III_P));
//		
//	}

    /* Test for Encoding Public Key in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size) */

//	public static void testEncodePublicKeyIIISize () {
//		
//		System.out.println ("Test for Encoding Public Key in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size)\n");
//		
//		byte[] randomnessExtended	= new byte[Polynomial.SEED_BYTE * 4];
//		byte[] publicKey			= new byte[Parameter.N_III_SIZE * Parameter.Q_LOGARITHM_III_SIZE / Integer.SIZE];
//		
//		fips.secureHashAlgorithmKECCAK256 (randomnessExtended, (short) 0, (short) (Polynomial.SEED_BYTE * 4), seed, 0, Polynomial.RANDOM_BYTE);
//		
//		QTESLA.encodePublicKey (publicKey, PolynomialHeuristic.ZETA_III_SIZE, randomnessExtended, Polynomial.SEED_BYTE * 2, Parameter.N_III_SIZE, Parameter.Q_LOGARITHM_III_SIZE);
//		
//		for (short i = 0; i < Parameter.N_III_SIZE * Parameter.Q_LOGARITHM_III_SIZE / Integer.SIZE; i++) {
//			
//			System.out.printf ("%02X\t", publicKey[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %2d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n"); 
//		
//	}

    /* Test for Encoding Public Key in QTESLA for Heuristic qTESLA Security Category-3 (Option for Speed) */

//	public static void testEncodePublicKeyIIISpeed () {
//		
//		System.out.println ("Test for Encoding Public Key in QTESLA for Heuristic qTESLA Security Category-3 (Option for Speed)\n");
//		
//		byte[] randomnessExtended	= new byte[Polynomial.SEED_BYTE * 4];
//		byte[] publicKey			= new byte[Parameter.N_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED / Integer.SIZE];
//		
//		fips.secureHashAlgorithmKECCAK256 (randomnessExtended, (short) 0, (short) (Polynomial.SEED_BYTE * 4), seed, 0, Polynomial.RANDOM_BYTE);
//		
//		QTESLA.encodePublicKeyIIISpeed (publicKey, PolynomialHeuristic.ZETA_III_SPEED, randomnessExtended, Polynomial.SEED_BYTE * 2);
//		
//		for (short i = 0; i < Parameter.N_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED / Integer.SIZE; i++) {
//			
//			System.out.printf ("%02X\t", publicKey[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %2d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n"); 
//		
//	}

    /* Test for Encoding Public Key in QTESLA for Provably-Secure qTESLA Security Category-1 */

//	public static void testEncodePublicKeyIP () {
//		
//		System.out.println ("Test for Encoding Public Key in QTESLA for Provably-Secure qTESLA Security Category-1\n");
//		
//		byte[] randomnessExtended	= new byte[Polynomial.SEED_BYTE * 4];
//		long[] T					= new long[Parameter.N_I_P * Parameter.K_I_P];
//		byte[] publicKey			= new byte[Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / Integer.SIZE];
//		
//		for (short k = 0; k < Parameter.K_I_P; k++) {
//		
//			function.memoryCopy(T, Parameter.N_I_P * k, PolynomialProvablySecure.ZETA_I_P, 0, Parameter.N_I_P);
//		
//		}
//		
//		fips.secureHashAlgorithmKECCAK128 (randomnessExtended, (short) 0, (short) (Polynomial.SEED_BYTE * 4), seed, 0, Polynomial.RANDOM_BYTE);
//		
//		QTESLA.encodePublicKeyIP (publicKey, T, randomnessExtended, Polynomial.SEED_BYTE * 2);
//		
//		for (short i = 0; i < Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / Integer.SIZE; i++) {
//			
//			System.out.printf ("%02X\t", publicKey[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %3d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n"); 
//		
//	}

    /* Test for Encoding Public Key in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testEncodePublicKeyIIIP () {
//		
//		System.out.println ("Test for Encoding Public Key in QTESLA for Provably-Secure qTESLA Security Category-3\n");
//		
//		byte[] randomnessExtended	= new byte[Polynomial.SEED_BYTE * 4];
//		long[] T					= new long[Parameter.N_III_P * Parameter.K_III_P];
//		byte[] publicKey			= new byte[Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / Integer.SIZE];
//		
//		for (short k = 0; k < Parameter.K_III_P; k++) {
//		
//			function.memoryCopy (T, Parameter.N_III_P * k, PolynomialProvablySecure.ZETA_III_P, 0, Parameter.N_III_P);
//		
//		}
//		
//		fips.secureHashAlgorithmKECCAK256 (randomnessExtended, (short) 0, (short) (Polynomial.SEED_BYTE * 4), seed, 0, Polynomial.RANDOM_BYTE);
//		
//		QTESLA.encodePublicKeyIP (publicKey, T, randomnessExtended, Polynomial.SEED_BYTE * 2);
//		
//		for (short i = 0; i < Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / Integer.SIZE; i++) {
//			
//			System.out.printf ("%02X\t", publicKey[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %3d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n"); 
//		
//	}

    /* Test for Decoding Public Key in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size) */

//	public static void testDecodePublicKeyIIISize () {
//		
//		System.out.println ("Test for Decoding Public Key in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size)\n");
//		
//		byte[] publicKeyInput	= new byte[Parameter.Q_LOGARITHM_III_SIZE * Integer.SIZE * 4];
//		int[] publicKey			= new int[Parameter.N_III_SIZE];
//		
//		for (short j = 0; j < 4; j++) {
//		
//			for (short i = 0; i < Parameter.Q_LOGARITHM_III_SIZE * Integer.SIZE; i++) {
//			
//				publicKeyInput[i + Parameter.Q_LOGARITHM_III_SIZE * Integer.SIZE * j] = (byte) (PolynomialHeuristic.ZETA_III_SIZE[i] & 0xFFL);
//			
//			}
//		
//		}
//		
//		QTESLA.decodePublicKey (publicKey, seed, 0, publicKeyInput, Parameter.N_III_SIZE, Parameter.Q_LOGARITHM_III_SIZE);
//		
//		for (short i = 0; i < Parameter.N_III_SIZE; i++) {
//			
//			System.out.printf ("%06X\t", publicKey[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %2d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Decoding Public Key in QTESLA for Heuristic qTESLA Security Category-3 (Option for Speed) */

//	public static void testDecodePublicKeyIIISpeed () {
//		
//		System.out.println ("Test for Decoding Public Key in QTESLA for Heuristic qTESLA Security Category-3 (Option for Speed)\n");
//		
//		byte[] publicKeyInput	= new byte[Parameter.Q_LOGARITHM_III_SPEED * Integer.SIZE * 4];
//		int[] publicKey			= new int[Parameter.N_III_SPEED];
//		
//		for (short j = 0; j < 4; j++) {
//		
//			for (short i = 0; i < Parameter.Q_LOGARITHM_III_SPEED * Integer.SIZE; i++) {
//			
//				publicKeyInput[i + Parameter.Q_LOGARITHM_III_SPEED * Integer.SIZE * j] = (byte) (PolynomialHeuristic.ZETA_III_SPEED[i] & 0xFFL);
//			
//			}
//		
//		}
//		
//		QTESLA.decodePublicKeyIIISpeed (publicKey, seed, 0, publicKeyInput);
//		
//		for (short i = 0; i < Parameter.N_III_SPEED; i++) {
//			
//			System.out.printf ("%06X\t", publicKey[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %2d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Decoding Public Key in QTESLA for Provably-Secure qTESLA Security Category-1 */

//	public static void testDecodePublicKeyIP () {
//		
//		System.out.println ("Test for Decoding Public Key in QTESLA for Provably-Secure qTESLA Security Category-1\n");
//		
//		byte[] publicKeyInput	= new byte[Parameter.Q_LOGARITHM_I_P * Integer.SIZE * Parameter.K_I_P * 4];
//		int[] publicKey			= new int[Parameter.N_I_P * Parameter.K_I_P];
//		
//		for (short j = 0; j < 4; j++) {
//		
//			for (short k = 0; k < Parameter.K_I_P; k++) {
//		
//				for (short i = 0; i < Parameter.Q_LOGARITHM_I_P * Integer.SIZE; i++) {
//			
//					publicKeyInput[i + Parameter.Q_LOGARITHM_I_P * Integer.SIZE * k + Parameter.Q_LOGARITHM_I_P * Integer.SIZE * Parameter.K_I_P * j] = (byte) (PolynomialProvablySecure.ZETA_I_P[i] & 0xFFL);
//			
//				}
//		
//			}
//		
//		}
//		
//		QTESLA.decodePublicKeyIP (publicKey, seed, 0, publicKeyInput);
//		
//		for (short i = 0; i < Parameter.N_I_P * Parameter.K_I_P; i++) {
//			
//			System.out.printf ("%08X\t", publicKey[i]);
//			
//			if (i % 8 == 7) {
//				
//				System.out.printf ("LINE %3d\n", (i / 8 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Decoding Public Key in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testDecodePublicKeyIIIP () {
//		
//		System.out.println ("Test for Decoding Public Key in QTESLA for Provably-Secure qTESLA Security Category-3\n");
//		
//		byte[] publicKeyInput	= new byte[Parameter.Q_LOGARITHM_III_P * Integer.SIZE * Parameter.K_III_P * 8];
//		int[] publicKey			= new int[Parameter.N_III_P * Parameter.K_III_P];
//		
//		for (short j = 0; j < 8; j++) {
//		
//			for (short k = 0; k < Parameter.K_III_P; k++) {
//		
//				for (short i = 0; i < Parameter.Q_LOGARITHM_III_P * Integer.SIZE; i++) {
//			
//					publicKeyInput[i + Parameter.Q_LOGARITHM_III_P * Integer.SIZE * k + Parameter.Q_LOGARITHM_III_P * Integer.SIZE * Parameter.K_III_P * j] = (byte) (PolynomialProvablySecure.ZETA_III_P[i] & 0xFFL);
//			
//				}
//		
//			}
//		
//		}
//		
//		QTESLA.decodePublicKeyIIIP (publicKey, seed, 0, publicKeyInput);
//		
//		for (short i = 0; i < Parameter.N_III_P * Parameter.K_III_P; i++) {
//			
//			System.out.printf ("%08X\t", publicKey[i]);
//			
//			if (i % 8 == 7) {
//				
//				System.out.printf ("LINE %4d\n", (i / 8 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Encoding Signature in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size) */

//	public static void testEncodeSignatureIIISize () {
//		
//		System.out.println ("Test for Encoding Signature in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size)\n");
//		
//		long[] Z			= new long[Parameter.N_III_SIZE];
//		byte[] signature	= new byte[Parameter.N_III_SIZE * Parameter.D_III_SIZE / Byte.SIZE + Polynomial.C_BYTE];
//		
//		function.memoryCopy (Z, 0, PolynomialHeuristic.ZETA_III_SIZE, 0, Parameter.N_III_SIZE);
//		
//		QTESLA.encodeSignature (signature, 0, seed, (short) 0, Z, Parameter.N_III_SIZE, Parameter.D_III_SIZE);
//		
//		for (short i = 0; i < Parameter.N_III_SIZE * Parameter.D_III_SIZE / Byte.SIZE + Polynomial.C_BYTE; i++) {
//			
//			System.out.printf ("%02X\t", signature[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %3d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Encoding Signature in QTESLA for Heuristic qTESLA Security Category-3 (Option for Speed) */

//	public static void testEncodeSignatureIIISpeed () {
//		
//		System.out.println ("Test for Encoding Signature in QTESLA for Heuristic qTESLA Security Category-3 (Option for Speed)\n");
//		
//		long[] Z			= new long[Parameter.N_III_SPEED];
//		byte[] signature	= new byte[Parameter.N_III_SPEED * Parameter.D_III_SPEED / Byte.SIZE + Polynomial.C_BYTE];
//		
//		function.memoryCopy (Z, 0, PolynomialHeuristic.ZETA_III_SPEED, 0, Parameter.N_III_SPEED);
//		
//		QTESLA.encodeSignatureIIISpeedIP (signature, 0, seed, (short) 0, Z, Parameter.N_III_SPEED, Parameter.D_III_SPEED);
//		
//		for (short i = 0; i < Parameter.N_III_SPEED * Parameter.D_III_SPEED / Byte.SIZE + Polynomial.C_BYTE; i++) {
//			
//			System.out.printf ("%02X\t", signature[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %3d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Encoding Signature in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testEncodeSignatureIIIP () {
//		
//		System.out.println ("Test for Encoding Signature in QTESLA for Provably-Secure qTESLA Security Category-3\n");
//		
//		long[] Z			= new long[Parameter.N_III_P];
//		byte[] signature	= new byte[Parameter.N_III_P * Parameter.D_III_P / Byte.SIZE + Polynomial.C_BYTE];
//		
//		function.memoryCopy (Z, 0, PolynomialProvablySecure.ZETA_III_P, 0, Parameter.N_III_P);
//		
//		QTESLA.encodeSignature (signature, 0, seed, (short) 0, Z);
//		
//		for (short i = 0; i < Parameter.N_III_P * Parameter.D_III_P / Byte.SIZE + Polynomial.C_BYTE; i++) {
//			
//			System.out.printf ("%02X\t", signature[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %3d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Decoding Signature in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size) */

//	public static void testDecodeSignatureIIISize () {
//		
//		System.out.println ("Test for Decoding Signature in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size)\n");
//		
//		long[] Z			= new long[Parameter.N_III_SIZE];
//		byte[] C			= new byte[Polynomial.C_BYTE];
//		byte[] signature	= new byte[Parameter.N_III_SIZE * Parameter.D_III_SIZE / Byte.SIZE + Polynomial.C_BYTE];
//		
//		for (short j = 0; j < Integer.SIZE / Byte.SIZE; j++) {
//			
//			for (short i = 0; i < Parameter.N_III_SIZE * Parameter.D_III_SIZE / Integer.SIZE; i++) {
//				
//				signature[i + Parameter.N_III_SIZE * Parameter.D_III_SIZE / Integer.SIZE * j] = (byte) (PolynomialHeuristic.ZETA_III_SIZE[i] & 0xFFL);
//				
//			}
//			
//		}
//		
//		for (short i = 0; i < Polynomial.C_BYTE; i++) {
//			
//			signature[i + Parameter.N_III_SIZE * Parameter.D_III_SIZE / Byte.SIZE] = (byte) (PolynomialHeuristic.ZETA_III_SIZE[i] & 0xFFL);
//		
//		}
//		
//		QTESLA.decodeSignature (C, Z, signature, 0, Parameter.N_III_SIZE, Parameter.D_III_SIZE);
//		
//		System.out.println ("Display C\n");
//		
//		for (short i = 0; i < Polynomial.C_BYTE; i++) {
//			
//			System.out.printf ("%02X\t", C[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.println ("\nDisplay Z\n");
//		
//		for (short i = 0; i < Parameter.N_III_SIZE; i++) {
//			
//			System.out.printf ("%06X\t", Z[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %2d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Decoding Signature in QTESLA for Heuristic qTESLA Security Category-3 (Option for Speed) */

//	public static void testDecodeSignatureIIISpeed () {
//		
//		System.out.println ("Test for Decoding Signature in QTESLA for Heuristic qTESLA Security Category-3 (Option for Speed)\n");
//		
//		long[] Z			= new long[Parameter.N_III_SPEED];
//		byte[] C			= new byte[Polynomial.C_BYTE];
//		byte[] signature	= new byte[Parameter.N_III_SPEED * Parameter.D_III_SPEED / Byte.SIZE + Polynomial.C_BYTE];
//		
//		for (short j = 0; j < Integer.SIZE / Byte.SIZE; j++) {
//			
//			for (short i = 0; i < Parameter.N_III_SPEED * Parameter.D_III_SPEED / Integer.SIZE; i++) {
//				
//				signature[i + Parameter.N_III_SPEED * Parameter.D_III_SPEED / Integer.SIZE * j] = (byte) (PolynomialHeuristic.ZETA_III_SPEED[i] & 0xFFL);
//				
//			}
//			
//		}
//		
//		for (short i = 0; i < Polynomial.C_BYTE; i++) {
//			
//			signature[i + Parameter.N_III_SPEED * Parameter.D_III_SPEED / Byte.SIZE] = (byte) (PolynomialHeuristic.ZETA_III_SPEED[i] & 0xFFL);
//		
//		}
//		
//		QTESLA.decodeSignatureIIISpeedIP (C, Z, signature, 0, Parameter.N_III_SPEED, Parameter.D_III_SPEED);
//		
//		System.out.println ("Display C\n");
//		
//		for (short i = 0; i < Polynomial.C_BYTE; i++) {
//			
//			System.out.printf ("%02X\t", C[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.println ("\nDisplay Z\n");
//		
//		for (short i = 0; i < Parameter.N_III_SPEED; i++) {
//			
//			System.out.printf ("%06X\t", Z[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %2d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Decoding Signature in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testDecodeSignatureIIIP () {
//		
//		System.out.println ("Test for Decoding Signature in QTESLA for Provably-Secure qTESLA Security Category-3\n");
//		
//		long[] Z			= new long[Parameter.N_III_P];
//		byte[] C			= new byte[Polynomial.C_BYTE];
//		byte[] signature	= new byte[Parameter.N_III_P * Parameter.D_III_P / Byte.SIZE + Polynomial.C_BYTE];
//		
//		for (short j = 0; j < Integer.SIZE / Byte.SIZE; j++) {
//			
//			for (short i = 0; i < Parameter.N_III_P * Parameter.D_III_P / Integer.SIZE; i++) {
//				
//				signature[i + Parameter.N_III_P * Parameter.D_III_P / Integer.SIZE * j] = (byte) (PolynomialProvablySecure.ZETA_III_P[i] & 0xFFL);
//				
//			}
//			
//		}
//		
//		for (short i = 0; i < Polynomial.C_BYTE; i++) {
//			
//			signature[i + Parameter.N_III_P * Parameter.D_III_P / Byte.SIZE] = (byte) (PolynomialProvablySecure.ZETA_III_P[i] & 0xFFL);
//		
//		}
//		
//		QTESLA.decodeSignature (C, Z, signature, 0);
//		
//		System.out.println ("Display C\n");
//		
//		for (short i = 0; i < Polynomial.C_BYTE; i++) {
//			
//			System.out.printf ("%02X\t", C[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.println ("\nDisplay Z\n");
//		
//		for (short i = 0; i < Parameter.N_III_P; i++) {
//			
//			System.out.printf ("%06X\t", Z[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %3d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Sparse Polynomial Multiplication of 16-Bit in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size) */

//	public static void testSparsePolynomialMultiplication16 () {
//		
//		System.out.println ("Test for Sparse Polynomial Multiplication of 16-Bit in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size)\n");
//		
//		short[] positionList	= new short[Parameter.W_III_SIZE];
//		short[] signList		= new short[Parameter.W_III_SIZE];
//		byte[] secretKey		= new byte[Parameter.N_III_SIZE];
//		long[] product			= new long[Parameter.N_III_SIZE];
//		
//		sample.encodeC (positionList, signList, seed, (short) 0, Parameter.N_III_SIZE, Parameter.W_III_SIZE);
//		
//		System.out.println ("Position List\n");
//		
//		for (short i = 0; i < Parameter.W_III_SIZE; i++) {
//			
//			System.out.printf ("%4d\t", positionList[i]);
//		
//			if (i % 8 == 7) {
//			
//				System.out.printf ("LINE %d\n", (i / 8 + 1));
//			
//			}
//		
//		}
//	
//		System.out.println ("\nSignature List\n");
//		
//		for (short i = 0; i < Parameter.W_III_SIZE; i++) {
//			
//			if (signList[i] > 0) {
//		
//				System.out.printf ("+");
//				
//			}
//			
//			System.out.printf ("%d\t", signList[i]);
//			
//			if (i % 8 == 7) {
//			
//				System.out.printf ("LINE %d\n", (i / 8 + 1));
//			
//			}
//		
//		}
//		
//		System.out.println ("\nDisplay Product\n");
//		
//		for (short i = 0; i < Parameter.N_III_SIZE; i++) {
//			
//			secretKey[i] = (byte) (PolynomialHeuristic.ZETA_III_SIZE[i] & 0xFFL);
//			
//		}
//		
//		QTESLA.sparsePolynomialMultiplication16 (product, secretKey, (short) 0, positionList, signList, Parameter.N_III_SIZE, Parameter.W_III_SIZE);
//		
//		for (short i = 0; i < Parameter.N_III_SIZE; i++) {
//			
//			System.out.printf ("%016X\t", product[i]);
//			
//			if (i % 4 == 3) {
//				
//				System.out.printf ("LINE %3d\n", (i / 4 + 1));
//				
//			}
//		
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Sparse Polynomial Multiplication of 8-Bit in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testSparsePolynomialMultiplication8 () {
//		
//		System.out.println ("Test for Sparse Polynomial Multiplication of 8-Bit in QTESLA for Provably-Secure qTESLA Security Category-3\n");
//		
//		short[] positionList	= new short[Parameter.W_III_P];
//		short[] signList		= new short[Parameter.W_III_P];
//		byte[] secretKey		= new byte[Parameter.N_III_P];
//		long[] product			= new long[Parameter.N_III_P];
//		
//		sample.encodeC (positionList, signList, seed, (short) 0, Parameter.N_III_P, Parameter.W_III_P);
//		
//		System.out.println ("Position List\n");
//		
//		for (short i = 0; i < Parameter.W_III_P; i++) {
//			
//			System.out.printf ("%4d\t", positionList[i]);
//		
//			if (i % 8 == 7) {
//			
//				System.out.printf ("LINE %d\n", (i / 8 + 1));
//			
//			}
//		
//		}
//	
//		System.out.println ("\nSignature List\n");
//		
//		for (short i = 0; i < Parameter.W_III_P; i++) {
//			
//			if (signList[i] > 0) {
//		
//				System.out.printf ("+");
//				
//			}
//			
//			System.out.printf ("%d\t", signList[i]);
//			
//			if (i % 8 == 7) {
//			
//				System.out.printf ("LINE %d\n", (i / 8 + 1));
//			
//			}
//		
//		}
//		
//		System.out.println ("\nDisplay Product\n");
//		
//		for (short i = 0; i < Parameter.N_III_P; i++) {
//			
//			secretKey[i] = (byte) (PolynomialProvablySecure.ZETA_III_P[i] & 0xFFL);
//			
//		}
//		
//		QTESLA.sparsePolynomialMultiplication8 (product, secretKey, (short) 0, positionList, signList, Parameter.N_III_P, Parameter.W_III_P);
//		
//		for (short i = 0; i < Parameter.N_III_P; i++) {
//			
//			System.out.printf ("%016X\t", product[i]);
//			
//			if (i % 4 == 3) {
//				
//				System.out.printf ("LINE %3d\n", (i / 4 + 1));
//				
//			}
//		
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Sparse Polynomial Multiplication of 32-Bit in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testSparsePolynomialMultiplication32 () {
//		
//		System.out.println ("Test for Sparse Polynomial Multiplication of 32-Bit in QTESLA for Provably-Secure qTESLA Security Category-3\n");
//		
//		short[] positionList	= new short[Parameter.W_III_P];
//		short[] signList		= new short[Parameter.W_III_P];
//		int[] publicKey			= new int[Parameter.N_III_P];
//		long[] product			= new long[Parameter.N_III_P];
//		
//		sample.encodeC (positionList, signList, seed, (short) 0, Parameter.N_III_P, Parameter.W_III_P);
//		
//		System.out.println ("Position List\n");
//		
//		for (short i = 0; i < Parameter.W_III_P; i++) {
//			
//			System.out.printf ("%4d\t", positionList[i]);
//		
//			if (i % 8 == 7) {
//			
//				System.out.printf ("LINE %d\n", (i / 8 + 1));
//			
//			}
//		
//		}
//	
//		System.out.println ("\nSignature List\n");
//		
//		for (short i = 0; i < Parameter.W_III_P; i++) {
//			
//			if (signList[i] > 0) {
//		
//				System.out.printf ("+");
//				
//			}
//			
//			System.out.printf ("%d\t", signList[i]);
//			
//			if (i % 8 == 7) {
//			
//				System.out.printf ("LINE %d\n", (i / 8 + 1));
//			
//			}
//		
//		}
//		
//		System.out.println ("\nDisplay Product\n");
//		
//		for (short i = 0; i < Parameter.N_III_P; i++) {
//			
//			publicKey[i] = (int) (PolynomialProvablySecure.ZETA_III_P[i] & 0xFFFFFFFFL);
//			
//		}
//		
//		QTESLA.sparsePolynomialMultiplication32 (
//				product,
//				publicKey, (short) 0,
//				positionList, signList,
//				Parameter.N_III_P, Parameter.W_III_P, Parameter.Q_III_P,
//				Parameter.BARRETT_MULTIPLICATION_III_P, Parameter.BARRETT_DIVISION_III_P
//		);
//		
//		for (short i = 0; i < Parameter.N_III_P; i++) {
//			
//			System.out.printf ("%016X\t", product[i]);
//			
//			if (i % 4 == 3) {
//				
//				System.out.printf ("LINE %3d\n", (i / 4 + 1));
//				
//			}
//		
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Hash Function in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size) */

//	public static void testHashFunctionIIISize () {
//		
//		System.out.println ("Test for Hash Function in QTESLA for Heuristic qTESLA Security Category-3 (Option for Size)\n");
//		
//		byte[] message	= new byte[Parameter.N_III_SIZE * Long.SIZE / Byte.SIZE];
//		byte[] output	= new byte[Polynomial.C_BYTE];
//		
//		for (short i = 0; i < Parameter.N_III_SIZE; i++) {
//			
//			function.store64 (message, i * Long.SIZE / Byte.SIZE, PolynomialHeuristic.ZETA_INVERSE_III_SIZE[i]);
//			
//		}
//		
//		System.out.println ("Message\n");
//		
//		for (short i = 0; i < Parameter.N_III_SIZE * Long.SIZE / Byte.SIZE; i++) {
//			
//			System.out.printf ("%02X\t", message[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %3d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\nSignature\n\n");
//		
//		QTESLA.hashFunction (
//				output, (short) 0,
//				PolynomialHeuristic.ZETA_III_SIZE,
//				message, 0, Parameter.N_III_SIZE * Long.SIZE / Byte.SIZE,
//				Parameter.N_III_SIZE, Parameter.D_III_SIZE, Parameter.Q_III_SIZE
//		);
//		
//		for (short i = 0; i < Polynomial.C_BYTE; i++) {
//			
//			System.out.printf ("%02X", output[i]);
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Hash Function in QTESLA for Provably-Secure qTESLA Security Category-3 */

//	public static void testHashFunctionIIIP () {
//		
//		System.out.println ("Test for Hash Function in QTESLA for Provably-Secure qTESLA Security Category-3\n");
//		
//		long[] V		= new long[Parameter.N_III_P * Parameter.K_III_P];
//		byte[] message	= new byte[Parameter.N_III_P * Long.SIZE / Byte.SIZE];
//		byte[] output	= new byte[Polynomial.C_BYTE];
//		
//		for (short i = 0; i < Parameter.N_III_P; i++) {
//			
//			function.store64 (message, i * Long.SIZE / Byte.SIZE, PolynomialProvablySecure.ZETA_INVERSE_III_P[i]);
//			
//		}
//		
//		System.out.println ("Message\n");
//		
//		for (short i = 0; i < Parameter.N_III_P * Long.SIZE / Byte.SIZE; i++) {
//			
//			System.out.printf ("%02X\t", message[i]);
//			
//			if (i % 16 == 15) {
//				
//				System.out.printf ("LINE %4d\n", (i / 16 + 1));
//				
//			}
//			
//		}
//		
//		System.out.printf ("\nSignature\n\n");
//		
//		for (short k = 0; k < Parameter.K_III_P; k++) {
//			
//			for (short i = 0; i < Parameter.N_III_P; i++) {
//				
//				V[Parameter.N_III_P * k + i] = PolynomialProvablySecure.ZETA_III_P[i];
//				
//			}
//			
//		}
//		
//		QTESLA.hashFunction (
//				output, (short) 0,
//				V,
//				message, 0, Parameter.N_III_P * Long.SIZE / Byte.SIZE,
//				Parameter.N_III_P, Parameter.K_III_P, Parameter.D_III_P, Parameter.Q_III_P
//		);
//		
//		for (short i = 0; i < Polynomial.C_BYTE; i++) {
//			
//			System.out.printf ("%02X", output[i]);
//			
//		}
//		
//		System.out.printf ("\n");
//		
//	}

    /* Test for Generation of the Key Pair, Signing and Verifying for Heuristic qTESLA Security Category-3 (Option for Size) */

    public void testGenerateKeyPairSigningVerifyingIIISize()
    {

        System.out.println("Test for Generation of the Key Pair for Heuristic qTESLA Security Category-3 (Option for Size)\n");

        QTESLAKeyPairGenerator kpGen = new QTESLAKeyPairGenerator();

        kpGen.init(new QTESLAKeyGenerationParameters(QTESLASecurityCategory.HEURISTIC_III_SIZE, secureRandom));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        byte[] publicKey = ((QTESLAPublicKeyParameters)kp.getPublic()).getPublicData();
        byte[] privateKey = ((QTESLAPrivateKeyParameters)kp.getPrivate()).getSecret();
        System.out.println("Public Key:\n");

        for (int i = 0; i < Polynomial.PUBLIC_KEY_III_SIZE; i++)
        {

            System.out.printf("%02X\t", publicKey[i]);

            if (i % 16 == 15)
            {

                System.out.printf("LINE %3d\n", (i / 16 + 1));

            }

        }

        System.out.println("\nPrivate Key:\n");

        for (int i = 0; i < Polynomial.PRIVATE_KEY_III_SIZE; i++)
        {

            System.out.printf("%02X\t", privateKey[i]);

            if (i % 16 == 15)
            {

                System.out.printf("LINE %3d\n", (i / 16 + 1));

            }

        }

        System.out.println("\nTest for Signing for Heuristic qTESLA Security Category-3 (Option for Size)\n");

        int[] signatureLength = new int[1];
        int[] messageLength = new int[1];
        byte[] signature = new byte[Polynomial.SIGNATURE_III_SIZE + 59];
        byte[] messageInput = new byte[59];

        secureRandom.nextBytes(messageInput);

        System.out.println("Message:\n");

        for (int i = 0; i < 59; i++)
        {

            System.out.printf("%02X\t", messageInput[i]);

            if (i % 16 == 15)
            {

                System.out.printf("LINE %d\n", (i / 16 + 1));

            }

        }

        System.out.println("\n\nSignature:\n");

        QTESLA.signingIIISize(signature, 0, signatureLength, messageInput, 0, 59, privateKey, secureRandom);

        for (int i = 0; i < signature.length; i++)
        {

            System.out.printf("%02X\t", signature[i]);

            if (i % 16 == 15)
            {

                System.out.printf("LINE %d\n", (i / 16 + 1));

            }

        }

        System.out.printf("\n\nThe Length of Signature is %d and the Length of Signature Package is %d\n\n", signature.length, signatureLength[0]);

        int valid;
        int response;
        byte[] messageOutput = new byte[Polynomial.SIGNATURE_III_SIZE + 59];

        System.out.println("Test for Verifying for Heuristic qTESLA Security Category-3 (Option for Size)\n");

        valid = QTESLA.verifyingIIISize(messageOutput, 0, messageLength, signature, 0, signatureLength[0], publicKey);

        if (valid != 0)
        {

            System.out.println("Signature Verification Failed with " + valid + "\n");

        }
        else if (messageLength[0] != 59)
        {

            System.out.println("Verifying Returned BAD Message Length with " + messageLength[0] + " Bytes\n");

        }

        for (short i = 0; i < messageLength[0]; i++)
        {

            if (messageInput[i] != messageOutput[i])
            {

                System.out.println("Verifying Returned BAD Message Value with Message Input " + messageInput[i] + "and Message Output " + messageOutput[i] + "\n");
                break;

            }

        }

        signature[secureRandom.nextInt(32) % (Polynomial.SIGNATURE_III_SIZE + 59)] ^= 1;

        response = QTESLA.verifyingIIISize(messageOutput, 0, messageLength, signature, 0, signatureLength[0], publicKey);

        if (response == 0)
        {

            System.out.println("Corrupted Signature Verified with " + response + "\n");

        }

        System.out.println("Signature Tests Passed\n");

    }

    /* Test for Generation of the Key Pair, Signing and Verifying for Provably-Secure qTESLA Security Category-3 */

    public void testGenerateKeyPairSigningVerifyingIIIP()
    {

        System.out.println("Test for Generation of the Key Pair for Provably-Secure qTESLA Security Category-3\n");

        QTESLAKeyPairGenerator kpGen = new QTESLAKeyPairGenerator();

        kpGen.init(new QTESLAKeyGenerationParameters(QTESLASecurityCategory.PROVABLY_SECURE_III, secureRandom));

        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        byte[] publicKey = ((QTESLAPublicKeyParameters)kp.getPublic()).getPublicData();
        byte[] privateKey = ((QTESLAPrivateKeyParameters)kp.getPrivate()).getSecret();
        
        System.out.println("Public Key:\n");

        for (int i = 0; i < Polynomial.PUBLIC_KEY_III_P; i++)
        {

            System.out.printf("%02X\t", publicKey[i]);

            if (i % 16 == 15)
            {

                System.out.printf("LINE %4d\n", (i / 16 + 1));

            }

        }

        System.out.println("\nPrivate Key:\n");

        for (int i = 0; i < Polynomial.PRIVATE_KEY_III_P; i++)
        {

            System.out.printf("%02X\t", privateKey[i]);

            if (i % 16 == 15)
            {

                System.out.printf("LINE %3d\n", (i / 16 + 1));

            }

        }

        System.out.println("\nTest for Signing for Provably-Secure qTESLA Security Category-3\n");

        int[] signatureLength = new int[1];
        int[] messageLength = new int[1];
        byte[] signature = new byte[Polynomial.SIGNATURE_III_P + 59];
        byte[] messageInput = new byte[59];

        secureRandom.nextBytes(messageInput);

        System.out.println("Message:\n");

        for (int i = 0; i < 59; i++)
        {

            System.out.printf("%02X\t", messageInput[i]);

            if (i % 16 == 15)
            {

                System.out.printf("LINE %d\n", (i / 16 + 1));

            }

        }

        System.out.println("\n\nSignature:\n");

        QTESLA.signingIIIP(signature, 0, signatureLength, messageInput, 0, 59, privateKey, secureRandom);

        for (int i = 0; i < signature.length; i++)
        {

            System.out.printf("%02X\t", signature[i]);

            if (i % 16 == 15)
            {

                System.out.printf("LINE %d\n", (i / 16 + 1));

            }

        }

        System.out.printf("\n\nThe Length of Signature is %d and the Length of Signature Package is %d\n\n", signature.length, signatureLength[0]);

        int valid;
        int response;
        byte[] messageOutput = new byte[Polynomial.SIGNATURE_III_P + 59];

        System.out.println("Test for Verifying for Provably-Secure qTESLA Security Category-3\n");

        valid = QTESLA.verifyingIIISize(messageOutput, 0, messageLength, signature, 0, signatureLength[0], publicKey);

        if (valid != 0)
        {

            System.out.println("Signature Verification Failed with " + valid + "\n");

        }
        else if (messageLength[0] != 59)
        {

            System.out.println("Verifying Returned BAD Message Length with " + messageLength[0] + " Bytes\n");

        }

        for (short i = 0; i < messageLength[0]; i++)
        {

            if (messageInput[i] != messageOutput[i])
            {

                System.out.println("Verifying Returned BAD Message Value with Message Input " + messageInput[i] + "and Message Output " + messageOutput[i] + "\n");
                break;

            }

        }

        signature[secureRandom.nextInt(32) % (Polynomial.SIGNATURE_III_P + 59)] ^= 1;

        response = QTESLA.verifyingIIIP(messageOutput, 0, messageLength, signature, 0, signatureLength[0], publicKey);

        if (response == 0)
        {

            System.out.println("Corrupted Signature Verified with " + response + "\n");

        }

        System.out.println("Signature Tests Passed\n");

    }

    /**
     * # qTesla-I
     *
     * count = 0
     * seed = 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1
     * mlen = 33
     * msg = D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8
     * pk = D1A8328AB997DF974E1933437AE5A0410F8C7FE23216345AC4A5C78AD3B5A548C865320EEB017238F4790A3286130E56206AA8DCF6732FAE84244557A9068A50E0B130C94DA9503577EECD89516736715450C56A357BD912B7082C4AD8D900C11A869DDFC6B76FF5E443B8A818315E1A80367872AC1DB9720F1B52088637A0A064B89A31A8088802D4159BB51553095B65FACE5ECA26836D081504EC6632B04C23505806A5704F08FDCE2770A1331E719E59EDB5A6E0725519850D76131036CECE0B1434CF323BE8A18138164C4E20A6E138B1C1CBF00BEBF642C327EED1A9609C9E576652618619BFF36945989B4D9521C4002C423143183D0848D2526AC5B9750993ECB9EB01F3A37CFB61EAEAD1E856143A1088E30515CD083584049300827FF1DBDC4BA9D93278E9244698306FC08C8C69A26714067AF1AB9F1389DCE3D8EE1B911D1B22A9D50A8544ED9002ACF28B3CE0401C3952AE7595D41A8EB6C0D5A86A4A7A016C366B317C516DA90A107115EFA5FBAD8FDA098EA1C903C583C165F9E98047745E5A2259BC728BD9F9364E83A1652733305F61A19BEDFAFB31579EA57E6752ED032567AAE0C700AAD55B34FE080A0017BEEFAB0B801BF2674376EFA6D3E9E8C168FCD4766A03638D8CA69A2D52C3048A29732129A381A733C5499F42F9149D401E29C40090D2C89E8E966E7D130B7758FC1A8EF8157FD6901475CBF3998124273740BC511C94BC6A60722A0637A982060FA0CCF26CA5F913477C331293EC739EC463185E9738E2BE049145A5D20DD4BA90DBCFB0351A5ECE0C49D6C63E3DE647AA01CF427425ED6EF125DA35B96BCE5813FD38B1BA7D9F1799E493B121D85F68D7F34804D9066D662AA9AC08F05F187FABE8B4B586CA1114A534A5FA5C477546FF9AE610CCB5A3A410A4A57D11EAE73C25939FDA490BCEF620686A0CD5EE2E8928E252FDF3359D5DCAE85EBD2B7D6024BDA3420BEB830433B49DAA9216CD1DDE72BAFC4429748E72CE406F2A8F1A7CC0EA665323C6045B6192A4009992235673DBCA3DE54ADF008F7AE140EEA5EA58FE77185C521CB20E55EFF60C60CB94723C52E998B0F48462352F9E9108B4E1939F668E6AD974754B20D46FBD288AA4401DA6068B7DFA1A3CDC02CC4D929F94DAC9C3555C42381244EC9730286A433D1DE1ED631704C7C84FCFF9AC8AC89133FB2439A00B89C26F42F9AAA35060C32F04E837B8E21B7382C68E27674A036D6651AAB40553BB05D2B07DF2FC1D62D22323209850698827CE0AC364AC0A1F7E953C308EAD14F838376BFE0686B58AACA9F357FD49CBCE19FDE9E8235DA5381707FD9693496F63C5A431B93386839C4CB3FC717E15B69C3D42184322A2DB1FF579DD41AB6E7152EE2871217A9C972A1B1F63804C16DBB4C5BEEABDCBB889DDDA5C1AA2E5239C71448F9B057CECB7CA054081244D920C1AAA12261812FA61DEB7BAC9C047315D0B014527484F8ADABE093C048E6845C3C8CDA9E2CCC35290617B22EDA5208E791CF41491C1539211A68BD518420A464823E5294600D0603DC03E051F8C91A215E90462644218C8BEC7D056EAEE617D4B57BFE98547F15D65757AF536D53364E1605E2D569E002CAD27BF074702C58235A8248AFE5876F08D2D5DA8992522F73F0777977CBD6455AC438C56434FCCB0B33D288A652B25A64C1FD6D262A46E30C0A18EE968474CE03DB0526AF0B8A0B171078F6825C070F2A9C28A504C6527EAD2564305991504EAD3AD3501A360417EF44B3C9A6D5B2B8E714E229912D649DE63ACC85AFEE6D5B3B2CB3198276AA01E4E36F8B8DC5C5DDA1323E5C354EA3E18B23E84D2E4EC600E63FAB91B3BC3A1FF82A07A82501DF9E33CEDC8FEDC536F8CAB0D5CD9C503D8A5862C959DAC6B497F34ACAACA65013CA683416B41AC4B278C39856DCC30F2C0C1E79024FF53FD630ADF6F8F038821AD68C11531F1016760EDAA88115EA068A48238537E648E38AA07061D3A4FAEDDDF35C4A60A07230EE9984D47236E598947F023A3A86A5D8A752CBA4EADDCA006ECD6E676231F340284FAB8F57C0081E766667A993B08009265B8004398CF119F95FCC217D38228F1D1F14BCFC5B7160986C339
     * sk = 20001D000F00F8FFEEFF0E0028001900EEFFE5FFE4FF1F00FBFFFBFF02001B00FBFFE0FF1900050007001A00F4FF1500EBFF0600F8FF22000A000C00FAFF0900D1FFFCFFF9FFE1FF1A00EDFFE3FF0D000800FAFFE6FF120004000200EEFFEDFFFDFF0B000000FEFFD7FFD9FF1600CCFFEFFFF2FFFCFFDEFFEAFF190019001000F5FFF0FF0E000C002800D9FF18001200F5FFFAFFFBFFFEFFF9FF0B000B003500F7FF20001800EBFFF5FF0F00FDFFF9FFDCFF0900DCFF0000D3FFEEFF05000A00F1FF14000C001B001B00F6FFE8FFEBFF1300E7FF15003200FFFF17000F0020001F000E00DDFF0500E1FF0D000A000A0012000000F5FF2300D1FFF9FF1100220005000B00E5FFF6FFFBFF0E00F9FF1A000D00D2FF0F002000F9FF060007002600E3FFF5FFEFFFE8FFD5FF0900F9FFFCFF09002700DDFF010027000000D1FFE2FF020017001B001D00E1FF0F00E0FFF1FFFCFFEDFF0D00280008000C00FFFFD8FF0B001400170007001B00F8FF0B001600180012000500E4FFF8FFFFFF19001A001E001900C0FFF2FFE4FF0B00F6FFEAFFF4FFF7FF1B00EAFF020001002400BAFFAFFFF6FFDFFFE6FFDFFFF6FF1F000200ECFF0B00F0FF270010001A001A000500F2FFE5FF1C00E5FF0B000A00FBFFC4FF0F00F3FF0200FEFFE7FF0E00FDFFE4FFF4FFFCFFF5FF1C00FFFF1A00190002000100FBFFDCFF1100F4FF1900FEFFC7FFEDFFF6FFFDFF33000200E0FFE5FF18000800F4FFF2FF18000C000A00D4FFF5FF2F00D5FFFAFFE7FF0500F4FFE2FFF2FFD3FF07001600EFFF0000E2FF15000E00EAFF07001A00E0FFF2FFFCFFEDFF0200E2FF1700F6FF06002D0004000200FBFFF8FFF6FF1A001B001E000B001B000C00F7FF3300FDFF2900EEFF2E001600210011001700EBFFE1FFCEFFF5FF0D00CFFF1700F8FF0100E6FF0800FDFFFFFFBFFFEAFF0400FAFFF5FFF8FF1300DFFF1500FBFFC9FF1800FBFFE5FF08001A002A0004001C000300FAFFFEFFF7FFDFFF0400FBFF1800DBFF0B00FCFF1200F6FFE4FF2A00F8FFDBFF2800D9FFE9FF0B00F4FF09000700E4FFF1FF1700ECFFFBFF1B00F9FF1A00F6FFFAFF1300E9FFF3FF2700E9FFE5FFDEFF0200F7FF0E00DCFFFBFF2000F8FF1100F0FFF2FF0300F6FFE0FFE7FFE7FFF3FF1700F7FF0A001B0001001B00FAFFC7FFE7FFE3FF1400F5FFF5FFFDFFDCFF1A000400EFFF0C000B00EFFFF8FFEDFF1900F2FF1400F2FFFFFF0000EDFFE6FFEEFF3700E5FF0A00E9FFF1FFE1FF140020000600F3FF0F00ECFF05000C0002002800DDFF01000000D9FF1E0006001300F3FF1300E6FF0B0006001E002800F5FF0400F3FF0D0020001A00E3FF0A0012000100DCFFF8FF4200EEFF02001700D3FF1100F4FF0A00040011001A00160015001C00F2FFDCFF1F00F9FFEDFF0100010025002200FDFFEBFF0B00E3FF15002C00F9FF1700D4FF05000B00FFFFF0FF1B001100FEFFD8FFEAFF2F00160013001300D9FF0F00ECFF1300FAFFFDFF14000D000F000E00FEFF2600F5FF0500DDFFE4FFF2FFEFFFEBFF1B00E0FF04001C00F3FF02001D00CFFF09000100FDFFEDFFE5FF20000E00E5FFFFFF0B00F9FF0E002100F7FF0600F2FF1300E3FFFEFFEDFF1100DAFF22000800FFFF19000100FEFFD6FFFCFF0200F5FFFEFF1800EBFFF3FFE8FF0800F2FFFBFF1300EEFFF4FF1100F5FF0B00DEFFECFF0E000B000E00F5FF0D001B00F7FFE4FF0200E8FF160003000000ECFFF5FF180005000500F0FFF2FFEBFFF3FFECFF1500E8FFEAFFF8FF0800C8FF0A000A000800FEFF0F00F4FFF3FFF1FFFCFFFDFF0800260010001000E7FFF7FFDFFF0B00F8FFF7FF1D00F9FF0C00FBFFEEFF1500EDFFE8FF0600F9FF080005000300FAFF190008002800F7FFFFFF33001B0008000B0013000F000700F4FF08000500CDFF09002900FEFF10001D00E6FF1000FFFFF8FF1600EDFF0100C7FFE2FF0D002000F5FFFAFFE7FFDFFFDFFFF6FFF9FFDEFFF4FF0E00E3FFD9FF0B001A00280015002B00E6FF320012000A00FAFFE9FFC9FFE5FF06000F001B002100F3FF410016001D00EBFFCFFFDFFF0300F3FFF4FF0E00ECFFE5FF16001200E0FF170003001300EDFFFEFFEFFFEBFFF7FFE4FF2100ECFFF7FF3100E3FF0200FBFFEEFFDAFF0800EAFFF4FF20000400E0FFFDFFFCFF070017001A000300200009000600EDFF08000000F2FFF6FF2100E1FF1200D9FFF9FFE4FF26001B001D00F3FF0B0023002B00E3FFE5FFEDFF0C00DBFF060007001D000300F5FFECFF22001C0014001700FEFFD4FFF7FF0C00F5FFE2FF0C002500E8FFEAFFEAFFFEFF2200F8FFF9FF250003001D000600F1FF0E001B00F4FF240028001C00E6FFDDFFFAFFE4FF060009002800F4FF0400FFFFF7FFECFF1F002C00D2FF0C00E0FFF0FF03000200FCFFE2FF0A00E8FF14000C00E6FFE8FF0F00DDFF0600EBFF0E000F002A00F8FFF9FF32000900E1FF050029000500E3FFF4FF1500060019001900C8FF0500E9FFE5FFF5FF1A000C00FCFF160014000D00FFFF00002300FEFF15000F004B00D9FF04002600EDFF24001500FAFFF0FF0A00D3FF01000D00DDFF3100E9FF0E00CEFF0F00ECFFDCFF25000B000300D7FF08000A0004001A0027001600F7FFD0FFF6FF2200F6FFE5FF23000A00140015000300070006000600F8FF0600F7FFD5FFEAFF0D00F2FF2E000C000000FBFFF6FF1C00120012000B00FAFFF9FFF5FF01002E001B000F0002002200F9FFE5FF1500E5FF0200EFFF1A00F4FFF0FF1B000900F0FF170028001B00EBFF1700E9FF1200E1FFFAFF2E00FCFF02000200F7FFF1FFF5FFEFFF12001F00ECFF2C00E9FF1700E2FF1700DDFFFCFF11001C000600F5FFE5FFF8FF0400DAFF2F000C00FEFF1B00993B08009265B8004398CF119F95FCC217D38228F1D1F14BCFC5B7160986C339F23EB15423271EF1CF476289657DBBB1460665D3944B78BEE92D15AA609768F9
     * smlen = 1409
     * sm = 73F0146209A9A0E9B7D70D9C92785CC084305749CE186A22A49B901E0AB202659A5FDE2CA6055C113F01DD52A83411B0F36E0F6287066EB3646C660961067680F8779A254A0929BA34490A97E8B1951E78287023FB699EDD5FC0EEB330FF10FFECC6F0AA224FD1925200C666121758CB7D8238C9F281594A872AA433803089841C1ECCE2947AF06597BAAE5F8B3B81866FD601B772F4C824A2E1729498085B9CA7760BBBFC20C3F4AF5D56783DD908292A4DDBFEEF546112C4EC06B32D8B74245DA6613FC533CE33D439F7BB21CC112E3165DBB48AA0D8E62421F2153B7366A99CCF2925F5D094B6F38BCF011FF0A58E474D08FF748B238017465202C47598F84AAABE303AFC794052B09AB057B9D2D90BF7E26D085111E3F07223BD5417CF123D211F75530AD1C557AC22F864B79EF94585B4D6C203A2BF74192D25E99530CC0DE6F62DBE3CA0B8161D340492C715B49626B265B89E00D5DD10B151CB57D039E94EF23DF831EDDA97CB7F022B680EAE6B39F9092248ADDDE155F76A62D4DCA3961197438870D3B14A5B9592CF4BFB18ACF47E3821502825FA0D8810162FE1D9679A172F674A32D2CA98E747DC32C4B7317A9CB0E01C510AB92BCE6C3CF31435B9F63775A6A3D1FC1D29BAFF93BE7F068C590C2AA753779A9D87678BD49411E3F4C3C3B245C2146A7BA1259416551B95D1AB3F197A621C37DFE9B19BE241A787C2A00FBC01E7435043974A683FC5B30BF69A8E55224F94F1F524C862760B99F28DDA98FB244EAE9A29F4F4911468ECE6590EC89D0E8708EEF8D6B204F38955F14B3664C4B7D6DC27A27ED41B010B83996DA7864101822AB1F78A5F2099C69D70CC2777244BD4124524F61B2BE8F18DE6DE36F1E053FF6B1B799A8A38BE4442A1F717BE47B556F61641499776B4895E7DD7D6D3C53529E1C792219FBB5F25F56E71255F00E5D09E677D5AB3C159984A5076DA7FA342993D857FA319DEA21E48FF63DB49DB07A5D8EFBAF660139D2CB269C55448DA3B8753B256CEBB881924DF6F0463727A6B821BB10A4FD6543A48ACA35E5B5529AD472ACFCB7C129CB4EE92FF0CE4AB3762722F283F3A5EF207659EB85FCE3FDEBCB88502BE8623259FB7B1ED40F2DA7C71319A926B60436DF76C71CCDAC818E842DAEBDB438F6ED4B871638DB49EABCE9AD734D4B5664EC74E5D72B23AD131589F3BDC9119F5E311549E1031461F045B34B8E6B88FD7D84713830A533F4084E9DECE9B9C4825745CD2FAF3183EEA89050476C770244B2A754A13D96B3E19F3B98FA777290ADEBD9863265D6A9ED6EDA6E3106C31A05A7B035AAACFB2AA76F7A5A04EEDC7F08B13BC1F9C5142FE58BF0CA7F389C7C6704D4D7BF0507D16EC1FF58130388E80C40A44A73CDC22CDC9B643C0A258805FB7CC2CFCCEEF1CE24CDB55B96B9A1EB3D1EEE9BB5AAFD37BA9C4A2387CCE3A39335C498A366E736653BE7DCC39ACB598984179391E6A521D13736B9C56EECFE71B71894E59D9E19863254E3415BBDD0D3D497BA5267999711F6B08A3519BC55A029F5945033B2593963624D0082C20FF437C0CAB61F7B9538AE4F456BD827ADEED1FDAF580A41789E5E86C2462058EEE793526DA59329C822491237173D8D01B1D22CAC6FBEE92C839D19AC193D6848084298A525EA881CC449E3B610C7A7BED083AA32D9830F8862BBD12261C9047C3F8DEE6744FF0603B38CCBBA3BFAE6B4042D5BEE0816923635E6AF9536EFC8E8670C7D3291BDF90F1CC1DD923B6B51CFBB161A43D2C7D3EA2FCF0D75D894EE95F448D6E930CF6CB90CA1708FD214961980C6CAC65CE4CDA5BEA9E703D845A7029DEC205FBCF31492C73FB7D17215B18F8BAD562C535EB1B76A3216AD55796EB2DEECAD8605F177BDC3AFB196E944D886C343F85D9F288871687012092C77000A8B1BA851EC5DB17D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8
     */
    public void testCat1Vector()
    {
        // seed after processing with the reference implementation RNG
        byte[] seed = Hex.decode("8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f");

        byte[] publicKey = Hex.decode("D1A8328AB997DF974E1933437AE5A0410F8C7FE23216345AC4A5C78AD3B5A548C865320EEB017238F4790A3286130E56206AA8DCF6732FAE84244557A9068A50E0B130C94DA9503577EECD89516736715450C56A357BD912B7082C4AD8D900C11A869DDFC6B76FF5E443B8A818315E1A80367872AC1DB9720F1B52088637A0A064B89A31A8088802D4159BB51553095B65FACE5ECA26836D081504EC6632B04C23505806A5704F08FDCE2770A1331E719E59EDB5A6E0725519850D76131036CECE0B1434CF323BE8A18138164C4E20A6E138B1C1CBF00BEBF642C327EED1A9609C9E576652618619BFF36945989B4D9521C4002C423143183D0848D2526AC5B9750993ECB9EB01F3A37CFB61EAEAD1E856143A1088E30515CD083584049300827FF1DBDC4BA9D93278E9244698306FC08C8C69A26714067AF1AB9F1389DCE3D8EE1B911D1B22A9D50A8544ED9002ACF28B3CE0401C3952AE7595D41A8EB6C0D5A86A4A7A016C366B317C516DA90A107115EFA5FBAD8FDA098EA1C903C583C165F9E98047745E5A2259BC728BD9F9364E83A1652733305F61A19BEDFAFB31579EA57E6752ED032567AAE0C700AAD55B34FE080A0017BEEFAB0B801BF2674376EFA6D3E9E8C168FCD4766A03638D8CA69A2D52C3048A29732129A381A733C5499F42F9149D401E29C40090D2C89E8E966E7D130B7758FC1A8EF8157FD6901475CBF3998124273740BC511C94BC6A60722A0637A982060FA0CCF26CA5F913477C331293EC739EC463185E9738E2BE049145A5D20DD4BA90DBCFB0351A5ECE0C49D6C63E3DE647AA01CF427425ED6EF125DA35B96BCE5813FD38B1BA7D9F1799E493B121D85F68D7F34804D9066D662AA9AC08F05F187FABE8B4B586CA1114A534A5FA5C477546FF9AE610CCB5A3A410A4A57D11EAE73C25939FDA490BCEF620686A0CD5EE2E8928E252FDF3359D5DCAE85EBD2B7D6024BDA3420BEB830433B49DAA9216CD1DDE72BAFC4429748E72CE406F2A8F1A7CC0EA665323C6045B6192A4009992235673DBCA3DE54ADF008F7AE140EEA5EA58FE77185C521CB20E55EFF60C60CB94723C52E998B0F48462352F9E9108B4E1939F668E6AD974754B20D46FBD288AA4401DA6068B7DFA1A3CDC02CC4D929F94DAC9C3555C42381244EC9730286A433D1DE1ED631704C7C84FCFF9AC8AC89133FB2439A00B89C26F42F9AAA35060C32F04E837B8E21B7382C68E27674A036D6651AAB40553BB05D2B07DF2FC1D62D22323209850698827CE0AC364AC0A1F7E953C308EAD14F838376BFE0686B58AACA9F357FD49CBCE19FDE9E8235DA5381707FD9693496F63C5A431B93386839C4CB3FC717E15B69C3D42184322A2DB1FF579DD41AB6E7152EE2871217A9C972A1B1F63804C16DBB4C5BEEABDCBB889DDDA5C1AA2E5239C71448F9B057CECB7CA054081244D920C1AAA12261812FA61DEB7BAC9C047315D0B014527484F8ADABE093C048E6845C3C8CDA9E2CCC35290617B22EDA5208E791CF41491C1539211A68BD518420A464823E5294600D0603DC03E051F8C91A215E90462644218C8BEC7D056EAEE617D4B57BFE98547F15D65757AF536D53364E1605E2D569E002CAD27BF074702C58235A8248AFE5876F08D2D5DA8992522F73F0777977CBD6455AC438C56434FCCB0B33D288A652B25A64C1FD6D262A46E30C0A18EE968474CE03DB0526AF0B8A0B171078F6825C070F2A9C28A504C6527EAD2564305991504EAD3AD3501A360417EF44B3C9A6D5B2B8E714E229912D649DE63ACC85AFEE6D5B3B2CB3198276AA01E4E36F8B8DC5C5DDA1323E5C354EA3E18B23E84D2E4EC600E63FAB91B3BC3A1FF82A07A82501DF9E33CEDC8FEDC536F8CAB0D5CD9C503D8A5862C959DAC6B497F34ACAACA65013CA683416B41AC4B278C39856DCC30F2C0C1E79024FF53FD630ADF6F8F038821AD68C11531F1016760EDAA88115EA068A48238537E648E38AA07061D3A4FAEDDDF35C4A60A07230EE9984D47236E598947F023A3A86A5D8A752CBA4EADDCA006ECD6E676231F340284FAB8F57C0081E766667A993B08009265B8004398CF119F95FCC217D38228F1D1F14BCFC5B7160986C339");
        byte[] secretKey = Hex.decode("20001D000F00F8FFEEFF0E0028001900EEFFE5FFE4FF1F00FBFFFBFF02001B00FBFFE0FF1900050007001A00F4FF1500EBFF0600F8FF22000A000C00FAFF0900D1FFFCFFF9FFE1FF1A00EDFFE3FF0D000800FAFFE6FF120004000200EEFFEDFFFDFF0B000000FEFFD7FFD9FF1600CCFFEFFFF2FFFCFFDEFFEAFF190019001000F5FFF0FF0E000C002800D9FF18001200F5FFFAFFFBFFFEFFF9FF0B000B003500F7FF20001800EBFFF5FF0F00FDFFF9FFDCFF0900DCFF0000D3FFEEFF05000A00F1FF14000C001B001B00F6FFE8FFEBFF1300E7FF15003200FFFF17000F0020001F000E00DDFF0500E1FF0D000A000A0012000000F5FF2300D1FFF9FF1100220005000B00E5FFF6FFFBFF0E00F9FF1A000D00D2FF0F002000F9FF060007002600E3FFF5FFEFFFE8FFD5FF0900F9FFFCFF09002700DDFF010027000000D1FFE2FF020017001B001D00E1FF0F00E0FFF1FFFCFFEDFF0D00280008000C00FFFFD8FF0B001400170007001B00F8FF0B001600180012000500E4FFF8FFFFFF19001A001E001900C0FFF2FFE4FF0B00F6FFEAFFF4FFF7FF1B00EAFF020001002400BAFFAFFFF6FFDFFFE6FFDFFFF6FF1F000200ECFF0B00F0FF270010001A001A000500F2FFE5FF1C00E5FF0B000A00FBFFC4FF0F00F3FF0200FEFFE7FF0E00FDFFE4FFF4FFFCFFF5FF1C00FFFF1A00190002000100FBFFDCFF1100F4FF1900FEFFC7FFEDFFF6FFFDFF33000200E0FFE5FF18000800F4FFF2FF18000C000A00D4FFF5FF2F00D5FFFAFFE7FF0500F4FFE2FFF2FFD3FF07001600EFFF0000E2FF15000E00EAFF07001A00E0FFF2FFFCFFEDFF0200E2FF1700F6FF06002D0004000200FBFFF8FFF6FF1A001B001E000B001B000C00F7FF3300FDFF2900EEFF2E001600210011001700EBFFE1FFCEFFF5FF0D00CFFF1700F8FF0100E6FF0800FDFFFFFFBFFFEAFF0400FAFFF5FFF8FF1300DFFF1500FBFFC9FF1800FBFFE5FF08001A002A0004001C000300FAFFFEFFF7FFDFFF0400FBFF1800DBFF0B00FCFF1200F6FFE4FF2A00F8FFDBFF2800D9FFE9FF0B00F4FF09000700E4FFF1FF1700ECFFFBFF1B00F9FF1A00F6FFFAFF1300E9FFF3FF2700E9FFE5FFDEFF0200F7FF0E00DCFFFBFF2000F8FF1100F0FFF2FF0300F6FFE0FFE7FFE7FFF3FF1700F7FF0A001B0001001B00FAFFC7FFE7FFE3FF1400F5FFF5FFFDFFDCFF1A000400EFFF0C000B00EFFFF8FFEDFF1900F2FF1400F2FFFFFF0000EDFFE6FFEEFF3700E5FF0A00E9FFF1FFE1FF140020000600F3FF0F00ECFF05000C0002002800DDFF01000000D9FF1E0006001300F3FF1300E6FF0B0006001E002800F5FF0400F3FF0D0020001A00E3FF0A0012000100DCFFF8FF4200EEFF02001700D3FF1100F4FF0A00040011001A00160015001C00F2FFDCFF1F00F9FFEDFF0100010025002200FDFFEBFF0B00E3FF15002C00F9FF1700D4FF05000B00FFFFF0FF1B001100FEFFD8FFEAFF2F00160013001300D9FF0F00ECFF1300FAFFFDFF14000D000F000E00FEFF2600F5FF0500DDFFE4FFF2FFEFFFEBFF1B00E0FF04001C00F3FF02001D00CFFF09000100FDFFEDFFE5FF20000E00E5FFFFFF0B00F9FF0E002100F7FF0600F2FF1300E3FFFEFFEDFF1100DAFF22000800FFFF19000100FEFFD6FFFCFF0200F5FFFEFF1800EBFFF3FFE8FF0800F2FFFBFF1300EEFFF4FF1100F5FF0B00DEFFECFF0E000B000E00F5FF0D001B00F7FFE4FF0200E8FF160003000000ECFFF5FF180005000500F0FFF2FFEBFFF3FFECFF1500E8FFEAFFF8FF0800C8FF0A000A000800FEFF0F00F4FFF3FFF1FFFCFFFDFF0800260010001000E7FFF7FFDFFF0B00F8FFF7FF1D00F9FF0C00FBFFEEFF1500EDFFE8FF0600F9FF080005000300FAFF190008002800F7FFFFFF33001B0008000B0013000F000700F4FF08000500CDFF09002900FEFF10001D00E6FF1000FFFFF8FF1600EDFF0100C7FFE2FF0D002000F5FFFAFFE7FFDFFFDFFFF6FFF9FFDEFFF4FF0E00E3FFD9FF0B001A00280015002B00E6FF320012000A00FAFFE9FFC9FFE5FF06000F001B002100F3FF410016001D00EBFFCFFFDFFF0300F3FFF4FF0E00ECFFE5FF16001200E0FF170003001300EDFFFEFFEFFFEBFFF7FFE4FF2100ECFFF7FF3100E3FF0200FBFFEEFFDAFF0800EAFFF4FF20000400E0FFFDFFFCFF070017001A000300200009000600EDFF08000000F2FFF6FF2100E1FF1200D9FFF9FFE4FF26001B001D00F3FF0B0023002B00E3FFE5FFEDFF0C00DBFF060007001D000300F5FFECFF22001C0014001700FEFFD4FFF7FF0C00F5FFE2FF0C002500E8FFEAFFEAFFFEFF2200F8FFF9FF250003001D000600F1FF0E001B00F4FF240028001C00E6FFDDFFFAFFE4FF060009002800F4FF0400FFFFF7FFECFF1F002C00D2FF0C00E0FFF0FF03000200FCFFE2FF0A00E8FF14000C00E6FFE8FF0F00DDFF0600EBFF0E000F002A00F8FFF9FF32000900E1FF050029000500E3FFF4FF1500060019001900C8FF0500E9FFE5FFF5FF1A000C00FCFF160014000D00FFFF00002300FEFF15000F004B00D9FF04002600EDFF24001500FAFFF0FF0A00D3FF01000D00DDFF3100E9FF0E00CEFF0F00ECFFDCFF25000B000300D7FF08000A0004001A0027001600F7FFD0FFF6FF2200F6FFE5FF23000A00140015000300070006000600F8FF0600F7FFD5FFEAFF0D00F2FF2E000C000000FBFFF6FF1C00120012000B00FAFFF9FFF5FF01002E001B000F0002002200F9FFE5FF1500E5FF0200EFFF1A00F4FFF0FF1B000900F0FF170028001B00EBFF1700E9FF1200E1FFFAFF2E00FCFF02000200F7FFF1FFF5FFEFFF12001F00ECFF2C00E9FF1700E2FF1700DDFFFCFF11001C000600F5FFE5FFF8FF0400DAFF2F000C00FEFF1B00993B08009265B8004398CF119F95FCC217D38228F1D1F14BCFC5B7160986C339F23EB15423271EF1CF476289657DBBB1460665D3944B78BEE92D15AA609768F9");
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] sm = Hex.decode("73F0146209A9A0E9B7D70D9C92785CC084305749CE186A22A49B901E0AB202659A5FDE2CA6055C113F01DD52A83411B0F36E0F6287066EB3646C660961067680F8779A254A0929BA34490A97E8B1951E78287023FB699EDD5FC0EEB330FF10FFECC6F0AA224FD1925200C666121758CB7D8238C9F281594A872AA433803089841C1ECCE2947AF06597BAAE5F8B3B81866FD601B772F4C824A2E1729498085B9CA7760BBBFC20C3F4AF5D56783DD908292A4DDBFEEF546112C4EC06B32D8B74245DA6613FC533CE33D439F7BB21CC112E3165DBB48AA0D8E62421F2153B7366A99CCF2925F5D094B6F38BCF011FF0A58E474D08FF748B238017465202C47598F84AAABE303AFC794052B09AB057B9D2D90BF7E26D085111E3F07223BD5417CF123D211F75530AD1C557AC22F864B79EF94585B4D6C203A2BF74192D25E99530CC0DE6F62DBE3CA0B8161D340492C715B49626B265B89E00D5DD10B151CB57D039E94EF23DF831EDDA97CB7F022B680EAE6B39F9092248ADDDE155F76A62D4DCA3961197438870D3B14A5B9592CF4BFB18ACF47E3821502825FA0D8810162FE1D9679A172F674A32D2CA98E747DC32C4B7317A9CB0E01C510AB92BCE6C3CF31435B9F63775A6A3D1FC1D29BAFF93BE7F068C590C2AA753779A9D87678BD49411E3F4C3C3B245C2146A7BA1259416551B95D1AB3F197A621C37DFE9B19BE241A787C2A00FBC01E7435043974A683FC5B30BF69A8E55224F94F1F524C862760B99F28DDA98FB244EAE9A29F4F4911468ECE6590EC89D0E8708EEF8D6B204F38955F14B3664C4B7D6DC27A27ED41B010B83996DA7864101822AB1F78A5F2099C69D70CC2777244BD4124524F61B2BE8F18DE6DE36F1E053FF6B1B799A8A38BE4442A1F717BE47B556F61641499776B4895E7DD7D6D3C53529E1C792219FBB5F25F56E71255F00E5D09E677D5AB3C159984A5076DA7FA342993D857FA319DEA21E48FF63DB49DB07A5D8EFBAF660139D2CB269C55448DA3B8753B256CEBB881924DF6F0463727A6B821BB10A4FD6543A48ACA35E5B5529AD472ACFCB7C129CB4EE92FF0CE4AB3762722F283F3A5EF207659EB85FCE3FDEBCB88502BE8623259FB7B1ED40F2DA7C71319A926B60436DF76C71CCDAC818E842DAEBDB438F6ED4B871638DB49EABCE9AD734D4B5664EC74E5D72B23AD131589F3BDC9119F5E311549E1031461F045B34B8E6B88FD7D84713830A533F4084E9DECE9B9C4825745CD2FAF3183EEA89050476C770244B2A754A13D96B3E19F3B98FA777290ADEBD9863265D6A9ED6EDA6E3106C31A05A7B035AAACFB2AA76F7A5A04EEDC7F08B13BC1F9C5142FE58BF0CA7F389C7C6704D4D7BF0507D16EC1FF58130388E80C40A44A73CDC22CDC9B643C0A258805FB7CC2CFCCEEF1CE24CDB55B96B9A1EB3D1EEE9BB5AAFD37BA9C4A2387CCE3A39335C498A366E736653BE7DCC39ACB598984179391E6A521D13736B9C56EECFE71B71894E59D9E19863254E3415BBDD0D3D497BA5267999711F6B08A3519BC55A029F5945033B2593963624D0082C20FF437C0CAB61F7B9538AE4F456BD827ADEED1FDAF580A41789E5E86C2462058EEE793526DA59329C822491237173D8D01B1D22CAC6FBEE92C839D19AC193D6848084298A525EA881CC449E3B610C7A7BED083AA32D9830F8862BBD12261C9047C3F8DEE6744FF0603B38CCBBA3BFAE6B4042D5BEE0816923635E6AF9536EFC8E8670C7D3291BDF90F1CC1DD923B6B51CFBB161A43D2C7D3EA2FCF0D75D894EE95F448D6E930CF6CB90CA1708FD214961980C6CAC65CE4CDA5BEA9E703D845A7029DEC205FBCF31492C73FB7D17215B18F8BAD562C535EB1B76A3216AD55796EB2DEECAD8605F177BDC3AFB196E944D886C343F85D9F288871687012092C77000A8B1BA851EC5DB17D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");


        byte[] sig = new byte[4000];
        int[] sigL = new int[1];
        QTESLA.signingI(sig, 0, sigL, msg, 0, msg.length, secretKey, new FixedSecureRandom(seed));

        assertTrue(Arrays.equals(sm, Arrays.copyOfRange(sig, 0, sigL[0])));
        int status = QTESLA.verifyingI(msg, 0, new int[] {msg.length}, sig, 0, sigL[0], publicKey);
        assertEquals(0, status);
    }
}
