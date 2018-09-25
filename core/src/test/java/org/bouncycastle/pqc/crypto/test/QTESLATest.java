package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;
import java.util.Arrays;

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
import org.bouncycastle.pqc.crypto.qtesla.Sample;
import org.bouncycastle.util.encoders.Hex;

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
    public void testCat1Vector0()
    {
        byte[] seed = Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1");

        byte[] publicKey = Hex.decode("D1A8328AB997DF974E1933437AE5A0410F8C7FE23216345AC4A5C78AD3B5A548C865320EEB017238F4790A3286130E56206AA8DCF6732FAE84244557A9068A50E0B130C94DA9503577EECD89516736715450C56A357BD912B7082C4AD8D900C11A869DDFC6B76FF5E443B8A818315E1A80367872AC1DB9720F1B52088637A0A064B89A31A8088802D4159BB51553095B65FACE5ECA26836D081504EC6632B04C23505806A5704F08FDCE2770A1331E719E59EDB5A6E0725519850D76131036CECE0B1434CF323BE8A18138164C4E20A6E138B1C1CBF00BEBF642C327EED1A9609C9E576652618619BFF36945989B4D9521C4002C423143183D0848D2526AC5B9750993ECB9EB01F3A37CFB61EAEAD1E856143A1088E30515CD083584049300827FF1DBDC4BA9D93278E9244698306FC08C8C69A26714067AF1AB9F1389DCE3D8EE1B911D1B22A9D50A8544ED9002ACF28B3CE0401C3952AE7595D41A8EB6C0D5A86A4A7A016C366B317C516DA90A107115EFA5FBAD8FDA098EA1C903C583C165F9E98047745E5A2259BC728BD9F9364E83A1652733305F61A19BEDFAFB31579EA57E6752ED032567AAE0C700AAD55B34FE080A0017BEEFAB0B801BF2674376EFA6D3E9E8C168FCD4766A03638D8CA69A2D52C3048A29732129A381A733C5499F42F9149D401E29C40090D2C89E8E966E7D130B7758FC1A8EF8157FD6901475CBF3998124273740BC511C94BC6A60722A0637A982060FA0CCF26CA5F913477C331293EC739EC463185E9738E2BE049145A5D20DD4BA90DBCFB0351A5ECE0C49D6C63E3DE647AA01CF427425ED6EF125DA35B96BCE5813FD38B1BA7D9F1799E493B121D85F68D7F34804D9066D662AA9AC08F05F187FABE8B4B586CA1114A534A5FA5C477546FF9AE610CCB5A3A410A4A57D11EAE73C25939FDA490BCEF620686A0CD5EE2E8928E252FDF3359D5DCAE85EBD2B7D6024BDA3420BEB830433B49DAA9216CD1DDE72BAFC4429748E72CE406F2A8F1A7CC0EA665323C6045B6192A4009992235673DBCA3DE54ADF008F7AE140EEA5EA58FE77185C521CB20E55EFF60C60CB94723C52E998B0F48462352F9E9108B4E1939F668E6AD974754B20D46FBD288AA4401DA6068B7DFA1A3CDC02CC4D929F94DAC9C3555C42381244EC9730286A433D1DE1ED631704C7C84FCFF9AC8AC89133FB2439A00B89C26F42F9AAA35060C32F04E837B8E21B7382C68E27674A036D6651AAB40553BB05D2B07DF2FC1D62D22323209850698827CE0AC364AC0A1F7E953C308EAD14F838376BFE0686B58AACA9F357FD49CBCE19FDE9E8235DA5381707FD9693496F63C5A431B93386839C4CB3FC717E15B69C3D42184322A2DB1FF579DD41AB6E7152EE2871217A9C972A1B1F63804C16DBB4C5BEEABDCBB889DDDA5C1AA2E5239C71448F9B057CECB7CA054081244D920C1AAA12261812FA61DEB7BAC9C047315D0B014527484F8ADABE093C048E6845C3C8CDA9E2CCC35290617B22EDA5208E791CF41491C1539211A68BD518420A464823E5294600D0603DC03E051F8C91A215E90462644218C8BEC7D056EAEE617D4B57BFE98547F15D65757AF536D53364E1605E2D569E002CAD27BF074702C58235A8248AFE5876F08D2D5DA8992522F73F0777977CBD6455AC438C56434FCCB0B33D288A652B25A64C1FD6D262A46E30C0A18EE968474CE03DB0526AF0B8A0B171078F6825C070F2A9C28A504C6527EAD2564305991504EAD3AD3501A360417EF44B3C9A6D5B2B8E714E229912D649DE63ACC85AFEE6D5B3B2CB3198276AA01E4E36F8B8DC5C5DDA1323E5C354EA3E18B23E84D2E4EC600E63FAB91B3BC3A1FF82A07A82501DF9E33CEDC8FEDC536F8CAB0D5CD9C503D8A5862C959DAC6B497F34ACAACA65013CA683416B41AC4B278C39856DCC30F2C0C1E79024FF53FD630ADF6F8F038821AD68C11531F1016760EDAA88115EA068A48238537E648E38AA07061D3A4FAEDDDF35C4A60A07230EE9984D47236E598947F023A3A86A5D8A752CBA4EADDCA006ECD6E676231F340284FAB8F57C0081E766667A993B08009265B8004398CF119F95FCC217D38228F1D1F14BCFC5B7160986C339");
        byte[] secretKey = Hex.decode("20001D000F00F8FFEEFF0E0028001900EEFFE5FFE4FF1F00FBFFFBFF02001B00FBFFE0FF1900050007001A00F4FF1500EBFF0600F8FF22000A000C00FAFF0900D1FFFCFFF9FFE1FF1A00EDFFE3FF0D000800FAFFE6FF120004000200EEFFEDFFFDFF0B000000FEFFD7FFD9FF1600CCFFEFFFF2FFFCFFDEFFEAFF190019001000F5FFF0FF0E000C002800D9FF18001200F5FFFAFFFBFFFEFFF9FF0B000B003500F7FF20001800EBFFF5FF0F00FDFFF9FFDCFF0900DCFF0000D3FFEEFF05000A00F1FF14000C001B001B00F6FFE8FFEBFF1300E7FF15003200FFFF17000F0020001F000E00DDFF0500E1FF0D000A000A0012000000F5FF2300D1FFF9FF1100220005000B00E5FFF6FFFBFF0E00F9FF1A000D00D2FF0F002000F9FF060007002600E3FFF5FFEFFFE8FFD5FF0900F9FFFCFF09002700DDFF010027000000D1FFE2FF020017001B001D00E1FF0F00E0FFF1FFFCFFEDFF0D00280008000C00FFFFD8FF0B001400170007001B00F8FF0B001600180012000500E4FFF8FFFFFF19001A001E001900C0FFF2FFE4FF0B00F6FFEAFFF4FFF7FF1B00EAFF020001002400BAFFAFFFF6FFDFFFE6FFDFFFF6FF1F000200ECFF0B00F0FF270010001A001A000500F2FFE5FF1C00E5FF0B000A00FBFFC4FF0F00F3FF0200FEFFE7FF0E00FDFFE4FFF4FFFCFFF5FF1C00FFFF1A00190002000100FBFFDCFF1100F4FF1900FEFFC7FFEDFFF6FFFDFF33000200E0FFE5FF18000800F4FFF2FF18000C000A00D4FFF5FF2F00D5FFFAFFE7FF0500F4FFE2FFF2FFD3FF07001600EFFF0000E2FF15000E00EAFF07001A00E0FFF2FFFCFFEDFF0200E2FF1700F6FF06002D0004000200FBFFF8FFF6FF1A001B001E000B001B000C00F7FF3300FDFF2900EEFF2E001600210011001700EBFFE1FFCEFFF5FF0D00CFFF1700F8FF0100E6FF0800FDFFFFFFBFFFEAFF0400FAFFF5FFF8FF1300DFFF1500FBFFC9FF1800FBFFE5FF08001A002A0004001C000300FAFFFEFFF7FFDFFF0400FBFF1800DBFF0B00FCFF1200F6FFE4FF2A00F8FFDBFF2800D9FFE9FF0B00F4FF09000700E4FFF1FF1700ECFFFBFF1B00F9FF1A00F6FFFAFF1300E9FFF3FF2700E9FFE5FFDEFF0200F7FF0E00DCFFFBFF2000F8FF1100F0FFF2FF0300F6FFE0FFE7FFE7FFF3FF1700F7FF0A001B0001001B00FAFFC7FFE7FFE3FF1400F5FFF5FFFDFFDCFF1A000400EFFF0C000B00EFFFF8FFEDFF1900F2FF1400F2FFFFFF0000EDFFE6FFEEFF3700E5FF0A00E9FFF1FFE1FF140020000600F3FF0F00ECFF05000C0002002800DDFF01000000D9FF1E0006001300F3FF1300E6FF0B0006001E002800F5FF0400F3FF0D0020001A00E3FF0A0012000100DCFFF8FF4200EEFF02001700D3FF1100F4FF0A00040011001A00160015001C00F2FFDCFF1F00F9FFEDFF0100010025002200FDFFEBFF0B00E3FF15002C00F9FF1700D4FF05000B00FFFFF0FF1B001100FEFFD8FFEAFF2F00160013001300D9FF0F00ECFF1300FAFFFDFF14000D000F000E00FEFF2600F5FF0500DDFFE4FFF2FFEFFFEBFF1B00E0FF04001C00F3FF02001D00CFFF09000100FDFFEDFFE5FF20000E00E5FFFFFF0B00F9FF0E002100F7FF0600F2FF1300E3FFFEFFEDFF1100DAFF22000800FFFF19000100FEFFD6FFFCFF0200F5FFFEFF1800EBFFF3FFE8FF0800F2FFFBFF1300EEFFF4FF1100F5FF0B00DEFFECFF0E000B000E00F5FF0D001B00F7FFE4FF0200E8FF160003000000ECFFF5FF180005000500F0FFF2FFEBFFF3FFECFF1500E8FFEAFFF8FF0800C8FF0A000A000800FEFF0F00F4FFF3FFF1FFFCFFFDFF0800260010001000E7FFF7FFDFFF0B00F8FFF7FF1D00F9FF0C00FBFFEEFF1500EDFFE8FF0600F9FF080005000300FAFF190008002800F7FFFFFF33001B0008000B0013000F000700F4FF08000500CDFF09002900FEFF10001D00E6FF1000FFFFF8FF1600EDFF0100C7FFE2FF0D002000F5FFFAFFE7FFDFFFDFFFF6FFF9FFDEFFF4FF0E00E3FFD9FF0B001A00280015002B00E6FF320012000A00FAFFE9FFC9FFE5FF06000F001B002100F3FF410016001D00EBFFCFFFDFFF0300F3FFF4FF0E00ECFFE5FF16001200E0FF170003001300EDFFFEFFEFFFEBFFF7FFE4FF2100ECFFF7FF3100E3FF0200FBFFEEFFDAFF0800EAFFF4FF20000400E0FFFDFFFCFF070017001A000300200009000600EDFF08000000F2FFF6FF2100E1FF1200D9FFF9FFE4FF26001B001D00F3FF0B0023002B00E3FFE5FFEDFF0C00DBFF060007001D000300F5FFECFF22001C0014001700FEFFD4FFF7FF0C00F5FFE2FF0C002500E8FFEAFFEAFFFEFF2200F8FFF9FF250003001D000600F1FF0E001B00F4FF240028001C00E6FFDDFFFAFFE4FF060009002800F4FF0400FFFFF7FFECFF1F002C00D2FF0C00E0FFF0FF03000200FCFFE2FF0A00E8FF14000C00E6FFE8FF0F00DDFF0600EBFF0E000F002A00F8FFF9FF32000900E1FF050029000500E3FFF4FF1500060019001900C8FF0500E9FFE5FFF5FF1A000C00FCFF160014000D00FFFF00002300FEFF15000F004B00D9FF04002600EDFF24001500FAFFF0FF0A00D3FF01000D00DDFF3100E9FF0E00CEFF0F00ECFFDCFF25000B000300D7FF08000A0004001A0027001600F7FFD0FFF6FF2200F6FFE5FF23000A00140015000300070006000600F8FF0600F7FFD5FFEAFF0D00F2FF2E000C000000FBFFF6FF1C00120012000B00FAFFF9FFF5FF01002E001B000F0002002200F9FFE5FF1500E5FF0200EFFF1A00F4FFF0FF1B000900F0FF170028001B00EBFF1700E9FF1200E1FFFAFF2E00FCFF02000200F7FFF1FFF5FFEFFF12001F00ECFF2C00E9FF1700E2FF1700DDFFFCFF11001C000600F5FFE5FFF8FF0400DAFF2F000C00FEFF1B00993B08009265B8004398CF119F95FCC217D38228F1D1F14BCFC5B7160986C339F23EB15423271EF1CF476289657DBBB1460665D3944B78BEE92D15AA609768F9");
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] sm = Hex.decode("73F0146209A9A0E9B7D70D9C92785CC084305749CE186A22A49B901E0AB202659A5FDE2CA6055C113F01DD52A83411B0F36E0F6287066EB3646C660961067680F8779A254A0929BA34490A97E8B1951E78287023FB699EDD5FC0EEB330FF10FFECC6F0AA224FD1925200C666121758CB7D8238C9F281594A872AA433803089841C1ECCE2947AF06597BAAE5F8B3B81866FD601B772F4C824A2E1729498085B9CA7760BBBFC20C3F4AF5D56783DD908292A4DDBFEEF546112C4EC06B32D8B74245DA6613FC533CE33D439F7BB21CC112E3165DBB48AA0D8E62421F2153B7366A99CCF2925F5D094B6F38BCF011FF0A58E474D08FF748B238017465202C47598F84AAABE303AFC794052B09AB057B9D2D90BF7E26D085111E3F07223BD5417CF123D211F75530AD1C557AC22F864B79EF94585B4D6C203A2BF74192D25E99530CC0DE6F62DBE3CA0B8161D340492C715B49626B265B89E00D5DD10B151CB57D039E94EF23DF831EDDA97CB7F022B680EAE6B39F9092248ADDDE155F76A62D4DCA3961197438870D3B14A5B9592CF4BFB18ACF47E3821502825FA0D8810162FE1D9679A172F674A32D2CA98E747DC32C4B7317A9CB0E01C510AB92BCE6C3CF31435B9F63775A6A3D1FC1D29BAFF93BE7F068C590C2AA753779A9D87678BD49411E3F4C3C3B245C2146A7BA1259416551B95D1AB3F197A621C37DFE9B19BE241A787C2A00FBC01E7435043974A683FC5B30BF69A8E55224F94F1F524C862760B99F28DDA98FB244EAE9A29F4F4911468ECE6590EC89D0E8708EEF8D6B204F38955F14B3664C4B7D6DC27A27ED41B010B83996DA7864101822AB1F78A5F2099C69D70CC2777244BD4124524F61B2BE8F18DE6DE36F1E053FF6B1B799A8A38BE4442A1F717BE47B556F61641499776B4895E7DD7D6D3C53529E1C792219FBB5F25F56E71255F00E5D09E677D5AB3C159984A5076DA7FA342993D857FA319DEA21E48FF63DB49DB07A5D8EFBAF660139D2CB269C55448DA3B8753B256CEBB881924DF6F0463727A6B821BB10A4FD6543A48ACA35E5B5529AD472ACFCB7C129CB4EE92FF0CE4AB3762722F283F3A5EF207659EB85FCE3FDEBCB88502BE8623259FB7B1ED40F2DA7C71319A926B60436DF76C71CCDAC818E842DAEBDB438F6ED4B871638DB49EABCE9AD734D4B5664EC74E5D72B23AD131589F3BDC9119F5E311549E1031461F045B34B8E6B88FD7D84713830A533F4084E9DECE9B9C4825745CD2FAF3183EEA89050476C770244B2A754A13D96B3E19F3B98FA777290ADEBD9863265D6A9ED6EDA6E3106C31A05A7B035AAACFB2AA76F7A5A04EEDC7F08B13BC1F9C5142FE58BF0CA7F389C7C6704D4D7BF0507D16EC1FF58130388E80C40A44A73CDC22CDC9B643C0A258805FB7CC2CFCCEEF1CE24CDB55B96B9A1EB3D1EEE9BB5AAFD37BA9C4A2387CCE3A39335C498A366E736653BE7DCC39ACB598984179391E6A521D13736B9C56EECFE71B71894E59D9E19863254E3415BBDD0D3D497BA5267999711F6B08A3519BC55A029F5945033B2593963624D0082C20FF437C0CAB61F7B9538AE4F456BD827ADEED1FDAF580A41789E5E86C2462058EEE793526DA59329C822491237173D8D01B1D22CAC6FBEE92C839D19AC193D6848084298A525EA881CC449E3B610C7A7BED083AA32D9830F8862BBD12261C9047C3F8DEE6744FF0603B38CCBBA3BFAE6B4042D5BEE0816923635E6AF9536EFC8E8670C7D3291BDF90F1CC1DD923B6B51CFBB161A43D2C7D3EA2FCF0D75D894EE95F448D6E930CF6CB90CA1708FD214961980C6CAC65CE4CDA5BEA9E703D845A7029DEC205FBCF31492C73FB7D17215B18F8BAD562C535EB1B76A3216AD55796EB2DEECAD8605F177BDC3AFB196E944D886C343F85D9F288871687012092C77000A8B1BA851EC5DB17D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");


        byte[] sig = new byte[4000];
        int[] sigL = new int[1];
        QTESLA.signingI(sig, 0, sigL, msg, 0, msg.length, secretKey, QTESLASecureRandomFactory.getFixed(seed,256));

        assertTrue(Arrays.equals(sm, Arrays.copyOfRange(sig, 0, sigL[0])));
        int status = QTESLA.verifyingI(msg, 0, new int[] {msg.length}, sig, 0, sigL[0], publicKey);
        assertEquals(0, status);
    }

    /**
     * # qTesla-I
     *
     * count = 1
     * seed = 64335BF29E5DE62842C941766BA129B0643B5E7121CA26CFC190EC7DC3543830557FDD5C03CF123A456D48EFEA43C868
     * mlen = 66
     * msg = 225D5CE2CEAC61930A07503FB59F7C2F936A3E075481DA3CA299A80F8C5DF9223A073E7B90E02EBF98CA2227EBA38C1AB2568209E46DBA961869C6F83983B17DCD49
     * pk = C3081552A6050BEC6105D4E24F04D83628899151CE511B7B8916D8875B975609081810B010503C52E4DF04129D27B594133B408C9CA3422BDCF4F7A85365A231F22DCED8363EE522623A4E176D62A3D8015A6DA9D75F7D35D8603D153A6A2D8E240A24588B3AC636422763AEC664DA0F6A7462D6D888353A58D8B3CEC296D3E93528A464B5DEB73266259D839FDF1A50BAE0C5D89DA0B2A33203222D7CD8A4AB193E6A060CC940B2A12DD359129555294247E59AA47E0555304184DB4BDE5D880E0D66C088E151F8F48551F88ACE28AFD1BA89100E5DE02CC10790AB3A53B52BA10E70AE403210EC896C8101BE8125F74B354EDE9B854A405588B0972C37442485D18080688D4686D04D092AA78160F293D4E80761C60A519D5A852A2E1AFF464D2F3378E4945EEE86502FD6408546438B4A46801096E0B7E0985BAFCD017E32B10C610088E269D975F46BCACEF0EA4A19BEFC582365EE48262DB71C12DFC37BF62B0401524572B9A86B0DE936723D15CCFCADACD50DCD7D84F7CB82638C79BA49FD6B04A21E4E35E5BD9D9C09EA5A4BA443665EA9C87FBDC84BFB8E7049A0941E18CB1819432D474085AEFD01B0AA41494B0AD10736A8393CBD8B24C864AA34659404B0720CB89CCDE003800FC8A8A153480D3DCAEB45B55753D0E4E389720A3C112AE17A979D9C4FA06705F58321418153FB9A21FAF29E7179DA6631917D82564F0B8BE885EA0C90CC0509C8EED0C044CC1735286E90F784C97A927018A10936FDE933F198306EC7412FCE132055FE87835A50D96560045825D2114C403D68322461E71CD2BD277D46C0464E38A2291CA4EEA64929807A00CEF853EA56483777B6FF925073457818FCF05856322ABA8E344F0D5F61EF96B63FC04AE7CBB01D3C7A5439CE46040F865A95DF03695D17BEAB5BB4BA2CBE3F5C4574242DB48BA54EE65B275620A2B0CE6118F07044CC3CBF5F607F3DB3E10854CB6482C0432130A1C12D953727D4CF7B046308A2C4DAAC7CC1405862F7DA29D71F49F942B4834CEDCD8F698AC4067C86C8B327DEF9AA5359B43BD7FEF250C89985C40FDC828F0713F14045C1BB0F85680711F8FA044D768C8E438A7F910AF159653B48CBB8C8B0BB3BA87810E5408EF42655694EC6F28F14EDBEF90EE754795E3AC9171B00A331AC0D1FFAC05DAA80FA8A504B2E7531269C0239D0399B271D90454E4B3CD405819FF0E77BB524CBFA335A086CB7897AC95AE60C5BE366354F23A197CC8F1F5E8E65CA62137F0A131D8B247FD7A29070496668C95FD96C791B396288C22D5C620F8425D1E0A44EAB2A3611C174529222E1B403082F4E332D2CDC6347800A8B29C54499980E4B7F2132B45473D35EFCCD6678A759E980ECB9F4D336D270281F2B3BD17F88F55A0D757C61625C9828D2802BE7C8685C2A43A21F8F8A3462C3DD6781EF87626FE6B99C55F8A958F7AC87515D84C6D0A0164540D861E2404AB1A3AC84F90C09A59B92089123BC45867EC3580A7B98735C4199FC060FCB688FC30B57EB5564A2C587FC72A134312091C858640CEE463F393B59DABF490CA5269B5ED8197EDC5660602F0C2835BB43C3D206BB2FB188A1AA94BBAAFC18110286BF4C88AF2FED3AD8FCDB0CDD9DE5A2B6E0418C4087CAAE9A1410543283640FC2A10B416F6367B47340ECB020ABDE9C5DF8C83146D119AFA2A911B7363FFEF8294F5CA2DF027366EFF50E7856135795A98FAB8711612AB4C71C590D806B6C622B02CC83112813C3E1CB906CB44B38164C60980C2E662AAE3DA74EDD645D8C1E30826C8CD0396BAD104F6EBB1956B3185F14C0B9DA27D1F907397AE98704E81B93543702424F335F2CD1913EEDD1AC956F562A7600E511C7FE675942DCAB95EC49E4A3802ABC808615E0A81FC81CE57A274350100DF95D0C55F001CC52B55090C35897C1945B920648F140AE017108DE64858524F20CA0DB67107C3510827209BDF90CF8FF8783380AA46111F7CDA8533848A6B2AAA62DACC9AE98DB474AAE4AA6B4B27043298840B0EB8B362B109B19BB2CA840A2A0255117155192537E2F4C0493BADB2D1916EC44B52B4BA993C5FBE705800B2C070B09CF36E0908FB89F71E2F7AD9448
     * sk = 1200E4FFFCFFE3FF1E00EBFFCCFFD5FF0C00D9FFFBFFE2FF0900EAFF0900FCFF1B0001001300100010000E001000E3FFDFFFF2FF0700F8FFF6FFFCFFFCFFF8FF13001200E5FF33000B00F3FFFAFF0C000600E6FF1100DCFF06000800E6FFF0FF0F000100F1FFF6FF0E000500ECFFF5FFEAFF09001300FCFFD9FF010005000A0018001B0008000F0021000D000B00FFFF10001C00D1FF0000F0FFF7FF0100F2FF0D002300F2FF1200FBFFFFFF1A0002003100F5FFF6FFFEFF0100EEFF060000001C00F0FF17002700F7FF0E001300E4FFCDFF08001000FCFF0100F9FFE0FF0500F7FF0E004000F1FFF8FF02001E00CBFF0B0021000900EEFF3500E5FF09000100DEFFEAFF0700FAFFFBFF0C00E5FF1100E0FF020011000100180004002D000D00D3FF1E00E2FFF9FF090015000700D4FFEEFFF9FF0A000F000C0003001000DBFF0800F5FF0100F6FF0E00ECFF0E0006000500D6FF0C00030011001100D4FFDAFFFCFF2900ECFFF0FF19000300F2FFE8FF1C00E1FFE4FF2600F1FF0900F6FFF7FFDDFF04000D00FAFFF5FF0300E5FF2C00FEFF1400060030001400FFFF0600F7FF07000C00E7FFE9FF1D000A00DCFFE8FFF3FFF9FFF6FF1A000C00FEFF01003C000100E7FF15000200E8FF0000FDFFF4FFFEFF0C00E7FF0200FBFFEDFF12001A00040008000E002100FDFFEBFFDDFF04001000F3FF0E0022000100040022000300DFFF0200F7FFD3FF0900E2FFE9FFDCFFE3FFEEFF01001C00E5FFF4FF1200FCFF18002700FBFFF3FF0E001800E9FF0C00EFFF0600DCFF0800020017001B00FAFF0300EBFFEDFF1B001300FCFFDEFF1500E6FFF5FFC8FF2200FEFFFDFF1300F6FFEFFF10001300FEFFEDFF25001B0022001E00F7FFFFFF1B000600FEFFEEFF2200F4FFFBFF15001B00FFFFF4FFEFFF0900F1FF0A00E5FF3400F7FFEBFF110025000E000A00ECFFD5FF0500FAFF0400ECFF03001B0009000C001500FEFF32001100FBFFF0FFF0FFE6FF1000070000004000E7FF04001A000200F3FFF6FF1B00FDFFF5FFFAFF09001000FCFF1F000400F1FF1300D7FF2500FCFF0B00C7FF130007001B001900FBFF1600E5FF1C00E8FFE3FF0000ECFF30002B00E5FFFBFF06000800E2FF1B00FBFFFBFF010003000800FFFFCDFFDCFF1B00EEFF3200BFFF0A0019000700EFFF0B000200DBFF0B00D5FFCFFF1B0015002800E5FF1C000D00DEFF05003500E9FFFFFFF5FFFEFFF6FFF3FFDDFFC8FF2E001500F7FF35001A00F6FFF6FFE7FFE2FFE2FFD3FF00001B0013000500F8FF080003002700EFFF07002700F8FF0C0022001400F5FF0300DEFF1700E9FFFDFF1500FCFF080017003100200014000900000000000D00DEFF1B00F2FF0100F1FFFBFF32002E00FBFF04002000FAFFE7FF1000D9FF060012000400F9FFD4FFD0FFF9FF0000FDFFDDFF1900E4FF07002000F2FF19001400E7FF0200EEFFF5FF0100F0FF0D000600EDFF290013001200E5FFECFF0D00E7FFE3FF240016001800FBFF1D00F5FFEAFFEAFF3000D7FFFDFFECFFEAFF16001B000B00F3FFE8FFFEFFF9FFF4FFD3FFECFFFEFF2600E0FFF7FFE8FFDCFF0500EFFFFBFF2400160008000E000600EAFF1B00120013002B00E6FF05002100EDFF1C00F7FFF9FFF3FFF3FFE9FF0E002000040006000C001400E5FF03001C00F0FF0F001200F6FFFBFF1D00000000001100FFFFE7FFE6FFE3FFF6FF22001200210028000E000C00F7FF04001600F1FF0F00F0FFD3FF0700250002000F00E5FFF9FF2100070008000700E6FFFFFF2500E0FFE0FF2B00E3FFEDFFE3FFFDFFE4FF2700F4FFF5FF2900FBFF00001B00F5FF0800F8FFE6FF1800F8FFDDFFF3FF0700CDFF1400E5FF15000A00E6FF120015001B000100200000000E00E5FFFCFFF9FFDEFFF6FFFFFF1E00EEFFFAFFF8FFD7FF0D00FCFF1E00FEFF0B001800E2FFC2FFE5FF2A00F8FF26003000F4FF1700FEFF1500EBFFF8FFFAFFE9FFF0FF3300F6FF0C002E0005000D00F2FF08000500F7FF0E00EEFF2C000200F3FFEBFF3A00E5FFE1FF2F00DBFFD6FFFEFFCCFFF5FF1600F0FF2300FDFFCFFF0300E6FFE6FFF3FF140011000700F6FF1800F2FFD0FF0600EFFF0B00FCFFE6FFEFFF08002E000E00FFFF080010001D0005000000E0FFF2FF0F00E9FFDCFFCCFF0400110019000400DBFF01002700FEFFF5FF06000F000A00E5FFEFFF2F00ECFF1D00EDFFE6FF0200F2FFFEFFE5FF0E001D0016000100E4FF0E001200E7FF2B00020015000A00EDFFD9FFEBFF2000FCFFF0FFF6FFE1FF0900DCFFD7FFFAFF21001A001B00D0FF0F000800E8FFEDFFDFFF16000D0011000700FDFFE5FF2600FCFF2300F9FF19000900EFFF100011001B00FBFFF2FF12000D0024000F001200280013000F00FDFF1600E3FFFCFFF7FFFDFF1F000000FAFFF6FFFDFF0900D0FFFCFFDAFFE0FFF4FFEAFFFDFF05002500CFFF190007001B00FBFF06000600F8FFF3FF010019001400FDFFF2FFE1FFF9FF28000100EBFFF5FFF0FF1500FAFFEDFF2E00F0FFD2FFF3FF1B000200FBFF02001A0025002E0031001F00FDFF1B001100ECFF08000500020015000C00E5FFF3FF130019000300F7FFEDFFCDFFE3FF2C00F3FF0B0001000F0001000700DCFFF3FFDEFFC9FFD2FF0500EFFF2E00F3FF0300D8FF0900DCFFFFFF1400FBFFF3FFE5FFF3FFFCFF1B0007000100FDFF19000E00FFFFF1FFFEFFD6FFF7FF0C001000FBFF1B000E002C00D2FF1200DEFF0C00ECFFECFFF7FFF0FFE6FF1B000500F1FFFBFFDBFFF4FF03002A00FAFFE8FF23000500F0FF2500FDFFA0FFFEFFE5FF1E00EEFF37001E001E00DEFF0100F8FF0000F0FF1C00E3FF0200F6FFEFFFEEFFE3FF050000000200D8FFFBFF010003001500F7FFF2FFFBFF1A001916EC44B52B4BA993C5FBE705800B2C070B09CF36E0908FB89F71E2F7AD944898B305452F9EFEA0237F6BACBE4022FC80E5DE2D66D398814A7C835419435744
     * smlen = 1442
     * sm = 955C15E5D2C82576C31D598550CC76CB8A1E2E64F5E238ADE433ED52C933F0636B25AED4F4AABDD6AD950D8168EEDB368F97BCF35AE2CE19104B675B36E2EA8157A95D89A4242508F9A0589C1FD814A7482E0FFC96088395ED617DDFBBE2AB037A7FDC84CCC7494698029E0B99D7694F1EAEAE3209AAF47B01E6B102DBEFA3CE66FE7E1932C360327F30F30BCDFD841DC05C0E800D8E8E5B1564A681B1FF6F641259ACA4F6641059D70E5117781373B09435E168E8C725D00208EFC3A5AFCF8EDAD88B46BB24E76A1C263B0B2DEB3D5237F44767FF54C0718C23464A4822B3E232D767B27E0C0AC574DFD36BFC0F8DB2A3A1DA9BE4BD2F49BC5EF85E70AA7E9B6B891C43A894377607DD6CFE8D4D79F7404F5AA77196C049D91AE2BAA2D81AFB4A26437F7325548B636CCFDF79F6B356552F80D72003F186558423FC303239BFDE2F77706AB3784E7516E0D830D09800110A82741C2402D8C63B23C4A310FA2BD46234FF8C61DB38C1DB583DCB6CDA347B5F91A4AB33F4F0EFBCFDB4D166C28DCAF08DF06CCE0A0B015EA38C0E3E489F3F8C4C240DC1DA8103E3D29EB31836E86F2344C3A1178DA632A27B25E0260DB9A95CDEC04961A3254D66F945986B18ACC4E592BF7C84A5D4EE74AF17B649D301419379271FA51AC3EED8CADBFE915FECB882348516D3D08C89BD1423FBD817E90FCF4C0A3223848C7EC5CACA30B8B62DA5CDB989C33DA91FB64364C70C47D218AE590BFC546CB83E2D47D3FBCF19A3E596DC7DBC3EA4767D95CC9FE34694403A5F06106E3C00331CEAA6B20580D6BE72F35EF084A8B4B8EA3590F06D0224ECFBB9CAB6B3CCC60BC10E39D2DAE7110577AADD3CA815A4F60426994B5E537BBC359EB43E8585090B3EBC6378A1FE700C84617DEA746E5D287526CF927A7558F1866CAB7D62FB30BA2FD0F0E0202F0AFD7776E992F7742D93C894270332E1AE36ED08A7FC261313D52D1D68A6BB602A66534B96E6C83A215CD14AD2CF8C47D7A7AB4F180F01B088F3D516266BA3BE96C55E3775314C647CE76B835F03AEF6D7DA5C13922506A4031A9C73AF10BF069A6A55DD1E0EB40EAB13ACBEE1472DCE4C87CF3C9E541C53D7A48446C8ACD6023BC5A53BED1302B39512383924A76667F723956200BBE1EE6673349F93C3FD9A517247A8A9189E5EC6B72FDAFCF325A2D2E84903275E76C801EFA9710AF066ADAC3B007E8475B9EBB0CFAC1A158F010BD45F9433796CFEF9C77410EE605ADE1124A6B41DA945C3B623C55F78A45A4AC504A60AE452E1FE9D1A629D23BB0E8F5834E00C60C819D40FE3F86AACC879CBD3B57C22300C6D2D6AF6B84586F95C5348938E4340BF16CB04CAA5FDA19282CE15864D3C2B42688F6BAB8C737924999E3B7C728EA05523EEE7529AF49C29F0E41D44B7CD741E1C975306F78DA137DA3A673F5835522591743A23D9DC339FB813009F89AA337530C99EA8CFCC17701F117DEE58388BFE10A7389F605044B84D3EA42AEEDAE12B56B340CB70C9B0A4AE6D2AF68CF7E4C91DAD67D6D92BF13A2179C8D58C08C53634ED76863BAE33392B78159EB16D94E654B1789D3D804684F6AF6CD3573B72159662732281FB85EBD9F0FEEF400C483FFABBC37CFCF3FE9DEA3FA6F83367FC8A1D3F9C26A5402F30AAC97009B9076BC5ED64F0738F4818D615EE4A187EBCE141075BD8B585AD74E00FC438F16DC6DCBE429785641D06814579DC0D1F2235DAC597F5E87FC27EBD97944C2DCEDD45AF464476B838E6D0077DCEE10177332734539F4F4CB2BE6D1E3E84DF13B90AC0EEF436BB3F36AB18952ABFF141F1F8951DE87E3DEDC02338A8CCA0DA61D08A19C005309DFC5D471B026D5F77CB3A5167F804414C61D39FC3213FEC9AD59A6B0B10FC0DC7DA7B1EDC8137EA655F3DAF9B66502606AB38912AD5AE5F2189087B66225D5CE2CEAC61930A07503FB59F7C2F936A3E075481DA3CA299A80F8C5DF9223A073E7B90E02EBF98CA2227EBA38C1AB2568209E46DBA961869C6F83983B17DCD49
     */
    public void testCat1Vector1()
    {
        byte[] seed = Hex.decode("64335BF29E5DE62842C941766BA129B0643B5E7121CA26CFC190EC7DC3543830557FDD5C03CF123A456D48EFEA43C868");

        byte[] publicKey = Hex.decode("C3081552A6050BEC6105D4E24F04D83628899151CE511B7B8916D8875B975609081810B010503C52E4DF04129D27B594133B408C9CA3422BDCF4F7A85365A231F22DCED8363EE522623A4E176D62A3D8015A6DA9D75F7D35D8603D153A6A2D8E240A24588B3AC636422763AEC664DA0F6A7462D6D888353A58D8B3CEC296D3E93528A464B5DEB73266259D839FDF1A50BAE0C5D89DA0B2A33203222D7CD8A4AB193E6A060CC940B2A12DD359129555294247E59AA47E0555304184DB4BDE5D880E0D66C088E151F8F48551F88ACE28AFD1BA89100E5DE02CC10790AB3A53B52BA10E70AE403210EC896C8101BE8125F74B354EDE9B854A405588B0972C37442485D18080688D4686D04D092AA78160F293D4E80761C60A519D5A852A2E1AFF464D2F3378E4945EEE86502FD6408546438B4A46801096E0B7E0985BAFCD017E32B10C610088E269D975F46BCACEF0EA4A19BEFC582365EE48262DB71C12DFC37BF62B0401524572B9A86B0DE936723D15CCFCADACD50DCD7D84F7CB82638C79BA49FD6B04A21E4E35E5BD9D9C09EA5A4BA443665EA9C87FBDC84BFB8E7049A0941E18CB1819432D474085AEFD01B0AA41494B0AD10736A8393CBD8B24C864AA34659404B0720CB89CCDE003800FC8A8A153480D3DCAEB45B55753D0E4E389720A3C112AE17A979D9C4FA06705F58321418153FB9A21FAF29E7179DA6631917D82564F0B8BE885EA0C90CC0509C8EED0C044CC1735286E90F784C97A927018A10936FDE933F198306EC7412FCE132055FE87835A50D96560045825D2114C403D68322461E71CD2BD277D46C0464E38A2291CA4EEA64929807A00CEF853EA56483777B6FF925073457818FCF05856322ABA8E344F0D5F61EF96B63FC04AE7CBB01D3C7A5439CE46040F865A95DF03695D17BEAB5BB4BA2CBE3F5C4574242DB48BA54EE65B275620A2B0CE6118F07044CC3CBF5F607F3DB3E10854CB6482C0432130A1C12D953727D4CF7B046308A2C4DAAC7CC1405862F7DA29D71F49F942B4834CEDCD8F698AC4067C86C8B327DEF9AA5359B43BD7FEF250C89985C40FDC828F0713F14045C1BB0F85680711F8FA044D768C8E438A7F910AF159653B48CBB8C8B0BB3BA87810E5408EF42655694EC6F28F14EDBEF90EE754795E3AC9171B00A331AC0D1FFAC05DAA80FA8A504B2E7531269C0239D0399B271D90454E4B3CD405819FF0E77BB524CBFA335A086CB7897AC95AE60C5BE366354F23A197CC8F1F5E8E65CA62137F0A131D8B247FD7A29070496668C95FD96C791B396288C22D5C620F8425D1E0A44EAB2A3611C174529222E1B403082F4E332D2CDC6347800A8B29C54499980E4B7F2132B45473D35EFCCD6678A759E980ECB9F4D336D270281F2B3BD17F88F55A0D757C61625C9828D2802BE7C8685C2A43A21F8F8A3462C3DD6781EF87626FE6B99C55F8A958F7AC87515D84C6D0A0164540D861E2404AB1A3AC84F90C09A59B92089123BC45867EC3580A7B98735C4199FC060FCB688FC30B57EB5564A2C587FC72A134312091C858640CEE463F393B59DABF490CA5269B5ED8197EDC5660602F0C2835BB43C3D206BB2FB188A1AA94BBAAFC18110286BF4C88AF2FED3AD8FCDB0CDD9DE5A2B6E0418C4087CAAE9A1410543283640FC2A10B416F6367B47340ECB020ABDE9C5DF8C83146D119AFA2A911B7363FFEF8294F5CA2DF027366EFF50E7856135795A98FAB8711612AB4C71C590D806B6C622B02CC83112813C3E1CB906CB44B38164C60980C2E662AAE3DA74EDD645D8C1E30826C8CD0396BAD104F6EBB1956B3185F14C0B9DA27D1F907397AE98704E81B93543702424F335F2CD1913EEDD1AC956F562A7600E511C7FE675942DCAB95EC49E4A3802ABC808615E0A81FC81CE57A274350100DF95D0C55F001CC52B55090C35897C1945B920648F140AE017108DE64858524F20CA0DB67107C3510827209BDF90CF8FF8783380AA46111F7CDA8533848A6B2AAA62DACC9AE98DB474AAE4AA6B4B27043298840B0EB8B362B109B19BB2CA840A2A0255117155192537E2F4C0493BADB2D1916EC44B52B4BA993C5FBE705800B2C070B09CF36E0908FB89F71E2F7AD9448");
        byte[] secretKey = Hex.decode("1200E4FFFCFFE3FF1E00EBFFCCFFD5FF0C00D9FFFBFFE2FF0900EAFF0900FCFF1B0001001300100010000E001000E3FFDFFFF2FF0700F8FFF6FFFCFFFCFFF8FF13001200E5FF33000B00F3FFFAFF0C000600E6FF1100DCFF06000800E6FFF0FF0F000100F1FFF6FF0E000500ECFFF5FFEAFF09001300FCFFD9FF010005000A0018001B0008000F0021000D000B00FFFF10001C00D1FF0000F0FFF7FF0100F2FF0D002300F2FF1200FBFFFFFF1A0002003100F5FFF6FFFEFF0100EEFF060000001C00F0FF17002700F7FF0E001300E4FFCDFF08001000FCFF0100F9FFE0FF0500F7FF0E004000F1FFF8FF02001E00CBFF0B0021000900EEFF3500E5FF09000100DEFFEAFF0700FAFFFBFF0C00E5FF1100E0FF020011000100180004002D000D00D3FF1E00E2FFF9FF090015000700D4FFEEFFF9FF0A000F000C0003001000DBFF0800F5FF0100F6FF0E00ECFF0E0006000500D6FF0C00030011001100D4FFDAFFFCFF2900ECFFF0FF19000300F2FFE8FF1C00E1FFE4FF2600F1FF0900F6FFF7FFDDFF04000D00FAFFF5FF0300E5FF2C00FEFF1400060030001400FFFF0600F7FF07000C00E7FFE9FF1D000A00DCFFE8FFF3FFF9FFF6FF1A000C00FEFF01003C000100E7FF15000200E8FF0000FDFFF4FFFEFF0C00E7FF0200FBFFEDFF12001A00040008000E002100FDFFEBFFDDFF04001000F3FF0E0022000100040022000300DFFF0200F7FFD3FF0900E2FFE9FFDCFFE3FFEEFF01001C00E5FFF4FF1200FCFF18002700FBFFF3FF0E001800E9FF0C00EFFF0600DCFF0800020017001B00FAFF0300EBFFEDFF1B001300FCFFDEFF1500E6FFF5FFC8FF2200FEFFFDFF1300F6FFEFFF10001300FEFFEDFF25001B0022001E00F7FFFFFF1B000600FEFFEEFF2200F4FFFBFF15001B00FFFFF4FFEFFF0900F1FF0A00E5FF3400F7FFEBFF110025000E000A00ECFFD5FF0500FAFF0400ECFF03001B0009000C001500FEFF32001100FBFFF0FFF0FFE6FF1000070000004000E7FF04001A000200F3FFF6FF1B00FDFFF5FFFAFF09001000FCFF1F000400F1FF1300D7FF2500FCFF0B00C7FF130007001B001900FBFF1600E5FF1C00E8FFE3FF0000ECFF30002B00E5FFFBFF06000800E2FF1B00FBFFFBFF010003000800FFFFCDFFDCFF1B00EEFF3200BFFF0A0019000700EFFF0B000200DBFF0B00D5FFCFFF1B0015002800E5FF1C000D00DEFF05003500E9FFFFFFF5FFFEFFF6FFF3FFDDFFC8FF2E001500F7FF35001A00F6FFF6FFE7FFE2FFE2FFD3FF00001B0013000500F8FF080003002700EFFF07002700F8FF0C0022001400F5FF0300DEFF1700E9FFFDFF1500FCFF080017003100200014000900000000000D00DEFF1B00F2FF0100F1FFFBFF32002E00FBFF04002000FAFFE7FF1000D9FF060012000400F9FFD4FFD0FFF9FF0000FDFFDDFF1900E4FF07002000F2FF19001400E7FF0200EEFFF5FF0100F0FF0D000600EDFF290013001200E5FFECFF0D00E7FFE3FF240016001800FBFF1D00F5FFEAFFEAFF3000D7FFFDFFECFFEAFF16001B000B00F3FFE8FFFEFFF9FFF4FFD3FFECFFFEFF2600E0FFF7FFE8FFDCFF0500EFFFFBFF2400160008000E000600EAFF1B00120013002B00E6FF05002100EDFF1C00F7FFF9FFF3FFF3FFE9FF0E002000040006000C001400E5FF03001C00F0FF0F001200F6FFFBFF1D00000000001100FFFFE7FFE6FFE3FFF6FF22001200210028000E000C00F7FF04001600F1FF0F00F0FFD3FF0700250002000F00E5FFF9FF2100070008000700E6FFFFFF2500E0FFE0FF2B00E3FFEDFFE3FFFDFFE4FF2700F4FFF5FF2900FBFF00001B00F5FF0800F8FFE6FF1800F8FFDDFFF3FF0700CDFF1400E5FF15000A00E6FF120015001B000100200000000E00E5FFFCFFF9FFDEFFF6FFFFFF1E00EEFFFAFFF8FFD7FF0D00FCFF1E00FEFF0B001800E2FFC2FFE5FF2A00F8FF26003000F4FF1700FEFF1500EBFFF8FFFAFFE9FFF0FF3300F6FF0C002E0005000D00F2FF08000500F7FF0E00EEFF2C000200F3FFEBFF3A00E5FFE1FF2F00DBFFD6FFFEFFCCFFF5FF1600F0FF2300FDFFCFFF0300E6FFE6FFF3FF140011000700F6FF1800F2FFD0FF0600EFFF0B00FCFFE6FFEFFF08002E000E00FFFF080010001D0005000000E0FFF2FF0F00E9FFDCFFCCFF0400110019000400DBFF01002700FEFFF5FF06000F000A00E5FFEFFF2F00ECFF1D00EDFFE6FF0200F2FFFEFFE5FF0E001D0016000100E4FF0E001200E7FF2B00020015000A00EDFFD9FFEBFF2000FCFFF0FFF6FFE1FF0900DCFFD7FFFAFF21001A001B00D0FF0F000800E8FFEDFFDFFF16000D0011000700FDFFE5FF2600FCFF2300F9FF19000900EFFF100011001B00FBFFF2FF12000D0024000F001200280013000F00FDFF1600E3FFFCFFF7FFFDFF1F000000FAFFF6FFFDFF0900D0FFFCFFDAFFE0FFF4FFEAFFFDFF05002500CFFF190007001B00FBFF06000600F8FFF3FF010019001400FDFFF2FFE1FFF9FF28000100EBFFF5FFF0FF1500FAFFEDFF2E00F0FFD2FFF3FF1B000200FBFF02001A0025002E0031001F00FDFF1B001100ECFF08000500020015000C00E5FFF3FF130019000300F7FFEDFFCDFFE3FF2C00F3FF0B0001000F0001000700DCFFF3FFDEFFC9FFD2FF0500EFFF2E00F3FF0300D8FF0900DCFFFFFF1400FBFFF3FFE5FFF3FFFCFF1B0007000100FDFF19000E00FFFFF1FFFEFFD6FFF7FF0C001000FBFF1B000E002C00D2FF1200DEFF0C00ECFFECFFF7FFF0FFE6FF1B000500F1FFFBFFDBFFF4FF03002A00FAFFE8FF23000500F0FF2500FDFFA0FFFEFFE5FF1E00EEFF37001E001E00DEFF0100F8FF0000F0FF1C00E3FF0200F6FFEFFFEEFFE3FF050000000200D8FFFBFF010003001500F7FFF2FFFBFF1A001916EC44B52B4BA993C5FBE705800B2C070B09CF36E0908FB89F71E2F7AD944898B305452F9EFEA0237F6BACBE4022FC80E5DE2D66D398814A7C835419435744");
        byte[] msg = Hex.decode("225D5CE2CEAC61930A07503FB59F7C2F936A3E075481DA3CA299A80F8C5DF9223A073E7B90E02EBF98CA2227EBA38C1AB2568209E46DBA961869C6F83983B17DCD49");
        byte[] sm = Hex.decode("955C15E5D2C82576C31D598550CC76CB8A1E2E64F5E238ADE433ED52C933F0636B25AED4F4AABDD6AD950D8168EEDB368F97BCF35AE2CE19104B675B36E2EA8157A95D89A4242508F9A0589C1FD814A7482E0FFC96088395ED617DDFBBE2AB037A7FDC84CCC7494698029E0B99D7694F1EAEAE3209AAF47B01E6B102DBEFA3CE66FE7E1932C360327F30F30BCDFD841DC05C0E800D8E8E5B1564A681B1FF6F641259ACA4F6641059D70E5117781373B09435E168E8C725D00208EFC3A5AFCF8EDAD88B46BB24E76A1C263B0B2DEB3D5237F44767FF54C0718C23464A4822B3E232D767B27E0C0AC574DFD36BFC0F8DB2A3A1DA9BE4BD2F49BC5EF85E70AA7E9B6B891C43A894377607DD6CFE8D4D79F7404F5AA77196C049D91AE2BAA2D81AFB4A26437F7325548B636CCFDF79F6B356552F80D72003F186558423FC303239BFDE2F77706AB3784E7516E0D830D09800110A82741C2402D8C63B23C4A310FA2BD46234FF8C61DB38C1DB583DCB6CDA347B5F91A4AB33F4F0EFBCFDB4D166C28DCAF08DF06CCE0A0B015EA38C0E3E489F3F8C4C240DC1DA8103E3D29EB31836E86F2344C3A1178DA632A27B25E0260DB9A95CDEC04961A3254D66F945986B18ACC4E592BF7C84A5D4EE74AF17B649D301419379271FA51AC3EED8CADBFE915FECB882348516D3D08C89BD1423FBD817E90FCF4C0A3223848C7EC5CACA30B8B62DA5CDB989C33DA91FB64364C70C47D218AE590BFC546CB83E2D47D3FBCF19A3E596DC7DBC3EA4767D95CC9FE34694403A5F06106E3C00331CEAA6B20580D6BE72F35EF084A8B4B8EA3590F06D0224ECFBB9CAB6B3CCC60BC10E39D2DAE7110577AADD3CA815A4F60426994B5E537BBC359EB43E8585090B3EBC6378A1FE700C84617DEA746E5D287526CF927A7558F1866CAB7D62FB30BA2FD0F0E0202F0AFD7776E992F7742D93C894270332E1AE36ED08A7FC261313D52D1D68A6BB602A66534B96E6C83A215CD14AD2CF8C47D7A7AB4F180F01B088F3D516266BA3BE96C55E3775314C647CE76B835F03AEF6D7DA5C13922506A4031A9C73AF10BF069A6A55DD1E0EB40EAB13ACBEE1472DCE4C87CF3C9E541C53D7A48446C8ACD6023BC5A53BED1302B39512383924A76667F723956200BBE1EE6673349F93C3FD9A517247A8A9189E5EC6B72FDAFCF325A2D2E84903275E76C801EFA9710AF066ADAC3B007E8475B9EBB0CFAC1A158F010BD45F9433796CFEF9C77410EE605ADE1124A6B41DA945C3B623C55F78A45A4AC504A60AE452E1FE9D1A629D23BB0E8F5834E00C60C819D40FE3F86AACC879CBD3B57C22300C6D2D6AF6B84586F95C5348938E4340BF16CB04CAA5FDA19282CE15864D3C2B42688F6BAB8C737924999E3B7C728EA05523EEE7529AF49C29F0E41D44B7CD741E1C975306F78DA137DA3A673F5835522591743A23D9DC339FB813009F89AA337530C99EA8CFCC17701F117DEE58388BFE10A7389F605044B84D3EA42AEEDAE12B56B340CB70C9B0A4AE6D2AF68CF7E4C91DAD67D6D92BF13A2179C8D58C08C53634ED76863BAE33392B78159EB16D94E654B1789D3D804684F6AF6CD3573B72159662732281FB85EBD9F0FEEF400C483FFABBC37CFCF3FE9DEA3FA6F83367FC8A1D3F9C26A5402F30AAC97009B9076BC5ED64F0738F4818D615EE4A187EBCE141075BD8B585AD74E00FC438F16DC6DCBE429785641D06814579DC0D1F2235DAC597F5E87FC27EBD97944C2DCEDD45AF464476B838E6D0077DCEE10177332734539F4F4CB2BE6D1E3E84DF13B90AC0EEF436BB3F36AB18952ABFF141F1F8951DE87E3DEDC02338A8CCA0DA61D08A19C005309DFC5D471B026D5F77CB3A5167F804414C61D39FC3213FEC9AD59A6B0B10FC0DC7DA7B1EDC8137EA655F3DAF9B66502606AB38912AD5AE5F2189087B66225D5CE2CEAC61930A07503FB59F7C2F936A3E075481DA3CA299A80F8C5DF9223A073E7B90E02EBF98CA2227EBA38C1AB2568209E46DBA961869C6F83983B17DCD49");


        byte[] sig = new byte[4000];
        int[] sigL = new int[1];
        QTESLA.signingI(sig, 0, sigL, msg, 0, msg.length, secretKey, QTESLASecureRandomFactory.getFixed(seed, 256));

        assertTrue(Arrays.equals(sm, Arrays.copyOfRange(sig, 0, sigL[0])));
        int status = QTESLA.verifyingI(msg, 0, new int[] {msg.length}, sig, 0, sigL[0], publicKey);
        assertEquals(0, status);
    }

//    /**
//     * # qTesla-III-size
//     *
//     * count = 0
//     * seed = 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1
//     * mlen = 33
//     * msg = D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8
//     * pk = CBD291D6599F23872E227742166E71AD533DE6B8306805A539274B9A5CAC75298152C19732AB6F8AD5EED79EB918563A2533F89D782E80B1A8C784FEB08745F8AC1D0C1D6DFE80A8329D00AE7B8B956FB668A138480A5D151EA2324B5586B5769F997385EE2DA811D083190D397482EF72244B8E4D0FC41492DBA7C11DD344BC18F21860759E88484A37FBBC9EC4855B07F6EA4EDA62BB318A966479A20007A93C7DDF3E70CD08CEF7A6630F9071C7094FC4287CD754FC695B52152AA7C54D690693A2979C120312A689310B02355136F89656AACD54EC49E62A000F263092A1A0AA535E2C256A9B85657385E4E6055E91A3BA20300D87DDD1805E7C3A6EF094C826C12846E805D201848CEB0E11FC10D0BEDA60E6E2A78D105C8A084B5C38C7B3382A2E150C2FC0CE891E6DD09406978AEC134C7FD8E22CAE881A6DBD0930A8B46B211A2A24C6054639E546B2323BE14112C2F9D9D0AAA91CB1391884738452BDAE052354FBC96ABB54D58F9802BB7EFA6CA9B5CD4F8A3C82B472839DC7E2986FC5280972040C3E68942B9B936A1C855C94C45AB77BBAFBD9E60702477104CE25E665493B9B2A3BD5D7425BBA24F391BC449C6C307B57BAD0DA42D60FED3B0D80BB5A13B100F83AB7F00644A0A0AF339685E139AA8E9F72AAB439EB10386C212C3A6F620E9561EF5E3F596BB165B419B7F9F780A5BB5C44C156215B9CDD80C142124C2C60F33899F11820C82E39142E6AE9B8869D404C54BD6E7406B27E9020EB9B80B93FEA6750DF8709417D93BEC543725CF148C51A76B66D5FCD7C7240911A3E479401D35BCC1512F541E7620178752EAE40C211663907067F4202D7601D41D0FA09CADDAE38B9FF30457FD1D68C50DB8388FE69372955A638C0932A4CD3A65EB77642F2A100DE437A50E3DD40B7597A8B433501C9E0766335D4CA3ADF5618C481A0ED2D2551C0E164B520513766E24956778363170351C0C1A67C11CDF279C76E357639B06F0E3ED38F6EF2905D02EEC228E4B61AE017D974C05966B85FC21D2D7A978279820C94856011A149CC3B34C09E8A9A04FAE7B18A7806E74328EA44C7392339A56AD14BA188002FE6C081F221949294636B04D10F6D58E9AD74735CAA1F4315E899DBFC0384A2A0538E3160BE7954168C2D7F188342655ABE81ED5D3651660E4634F78063DF4B7D7E5EF628476ADA3478E1D9C0FDEBF73593FD79A17E845C2210B8DF2713D38ED3E156F2A72B9157C3CCE089A91C700B7D7C3B62118894159B096AEC01C551C78AD31B467F84CAB7D0AE0A83EAB3452A028C4127CECF3737088A6985FCF1CC4AE22F83BE00610804C8B8C7562645CC5B0A66F56C4C18EC47552BBD3996D787681E0043F451DD2DDA512EC0FE3A10D75D5D893AF17FCC49FDEEF0B120A9F5300908E49FC2FCCE4D88EE2627C6D5AC33EE6BF471F80E72D3B729AC4E4E5E405D86B467B48F6BD2EA45457293BDFB0DC0085D38E265589DB8AFECF259D098873F047144B288EEC338899B0ED949466F335004080AF0E3E6D744A49F6237244CB94F0A0837C135AFC0424E9FDC87C6CF372905CBF3E3A1CE7922FE1B53E5B5CE8A95E47FE72439A1ABAFE9250EC5B89E54C672C8BBB82F4D46AAAC88AF1BD1D14F48D3753D23CAE2485554C9373706DEADE5E70F8195392069BC4FE1D3B6D471693E7A0D49EBD2E65260B6DA26C95158C4ABB8EB7DB2BB1347810376BCDB1DF92E8B30C28BDF7AE7E28498F55AA61DDEE32A726F03045A81410865C87AB82AEF71F03324E63B2C0598FD40463006E3D407272C4631C9B019F211D69214CCAABD4B08D93A7B68A1884577D413D0A61CEDE21E0B5923211413CC599B3D0FC9B055D495139B0061E36D6A665CADD0BAC630D4B6C64C6F4B12BE8F8B986FB84B413C173C2A3C0B07691E8A9EAA993600E5BF2382B314E20F147A63AFB88437378AD627A4DB7F45C97D6966361469905A0039FF2400B094171DD5ABDBBA80CC976BD13C78F50D048145C4A330B5C8DFD7CB6B34D9446B35709A32D9372F2EAB05745C191DE6CB51FF02E222F7FAC560CF384566E42414674D7C91A2DF47F2DFA3DCAAB1668593CAF41893B7D81C5F5CD12BABD744C4BD061675A59238283CFDF0B94BFA44214265227527447577042901F5E11108529044D108AC9100EAD8349FAB49F53DA7CAEAF166D66176D175DB7416FA1BE7632DF72E54C04829424F01CB3733E6D3F5556200FE4D3A252C744EDC3706A5072E57CE2B8BA28E25EC7DCEEB7A9A26B06BEF4F76FDE56B24F2D5E858229924E0D2CE1F1D6AD912C14EC018AA4552B164BC98736E5280204E5E13789CD5229AA5D69D95A4930B4484E40AF229518346682C73BE1D2DDDFE9FFE53A31FC9C65067008F3AC155705E32338AED22FBB2425C462AAB3D43C70BE2E996CC680B8059222BB782836BC4B94A2CE68D42676D522AC2D44804C6C334672F3A49F6D257E608EBA187B230FBBE6014A2D4704007FC731E993295012303A3BA755FBA7872DB349E0C0E4B1FABD0007B90933CE48A71D647B3EC93A53FC5EBA17C994B21E7B2D2B8C60A6324B81361482B3223A031DEF2C0B0286052902F6317F19FCFE5C6377498323624290DF2F21A0C333E37963A4ECDD68BB1B4A0DCE55014E9B52B60A8C14FBC780C6625DEEF87A428A2149C286BFCBBCD2EBD6A75288ABBB9E4D3973332E9332C93F5886ABE65603216B0F92B07662E72724FC0AF89582BA1106F79B7EAA9596638AA5FF0B9162EFD5BC6626AF45C459661A3AF444927B40A7368E5CB069A3D136713479524A4A9CB4BB6D9D4A3B0A64654A7D105C8F6C92ABC0BD31EB4A2AB8B07F0514450F69A42A79B043872DF17B00A5C61958E228857D331BDC06E4074E12E2BB028174946AECBC237A0B113123FF5784BDE37337A0B20AAD79967D0A99A37333EE0B0D09F717691265F6B66441E2B788C1E55405D4251BDABABE05220223D38AA034FBD9DD5CA8052BC0CD1CFC5671BC9D977C8B4BB90015CC07C34015C5C4DD2213982054855C260663C2684B0372289358F0891416713A70AF6843AAAE2F6F7BC5F124A5234BC278B81E345736D66EA50674AA341715469FBE4D24D7E15B9141143C95F57445036E55847B13F431DA5282C43520F992942FF19E702277A16B6624ADBE35319ECA74CB922BA892FF0FE53740AABA58FB37BF8F872892D831004073DF749B1B15E10F3518F3D55B0C024BB8DA18C304F6A8456811911DA16D45F5D6BB69EE3EA90BB0887289918046F3B09BFBA14C2C201932DE6C3D52A515005B7E8077C42BF77575315421711DF028577834161A699B3C8D8C6C200C70F3525A6D4D3DBCD0EA2F40272D2D8F1F894990848E4E66BF50D1404C4CA89FA27AB9FB3478D6A430D055E1B2E51173EE194DCCD90CC1E678A5CC6887479C9106C4A63524C354CCEBDF0AC405A4ACE8F0F26EBF2C821BF85C3762E84165F8410A14644FBB7CAAE15C67EF7FA273C6C7566341C0C48ACAEF88E043C76A77710D0ACB4FBC6EC21C0B4707461CBBCBD06CDD238380C7CA686BCF7E9BD28B942E7BE4A07494638506F873A184C5B8C25793F20AD846CCEF0D4F733BEA00A700EDAA0B4AA23F2D45E10308400BADC0F867E0917C7150D2E45A5C6C4688CE711C74B2DCB788CB48CD76317662F5F9E4782576B4368B525D7B0806C79FF31B0E577B52B3545A480E202E93F2F6174C378CD896C3FD8C2735D76A407CD07D99AE4C7F276436C69024A5914355386B42F94F386B8390179EA43D2AF965A69B1257805AEEBCE931789528E38EFDDE2944459E72208FE80BE4FE4E89586A50D983A24A0980C87034DAC00777C546B013F89589A3A10159249A190E0D0B043AA97FDE068EB92120BF139D4CAB62F5FD132C749D66D55A00A1267B05058DC9BE18B17D8276E00F491FE43D393D5A241F6D48C3C1A56F83C5465902E347C4DB7DC78D8A6F383A39F756B88D2447FB08430967710957D113F344A1C494CF6A9C6477B78578E80D10FD4350FCD94A0E6550BD48D014A26E587E4A128E369702EA8CD35AE7AA87E728FE9B82755F9D41BF2889690B4854FB0C9129D61072CF74B9ED3670B4EB309B51BFCFE813AADA619334EBFAE570E4A300B00FB52106F1EEA96F4CC6ED308264AB60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD
//     * sk = 17000000020000000B00FDFF0600FAFF05000D0007000200140010000700F6FF0A000300F6FF0800040009000500060002000600FAFF0C00F9FF0400FBFF0D000300F9FFF4FF01000900F6FF06000C00FDFF0300FCFFF4FF18001400FDFF0600FEFF0D00F9FF0900F8FFFFFFFFFF0300FCFFFEFF0A00F9FF0200FEFFF9FF02000100FAFF010001000A00010000000500FFFF0400F6FF04000600FFFF0000F7FFF3FFF9FFF8FFFFFF010011000900F1FFFDFF0600F7FFFCFF0900090005000300FDFFFEFF06000300FDFF04000100FAFF0400F9FFF5FF03000000080006000200F5FF1000FFFF01000500020008000C0001000500060009000800FCFF00000100FDFF01000000FEFF0D00F8FFFDFF0000F8FF0A00070017000B0001000900F3FFFAFF0E00FFFFFAFF02000500F7FFF9FF00000300FEFFFFFF0300FFFFFBFFF6FF0900F2FF050002000C000400F7FFF5FF0300FAFF1200F9FF0900020009000600FEFF0300020005000000F8FFF0FFEEFF0A00FCFF01000100FCFF06000700F8FF0C00F7FFFEFF0100FEFF0500F9FFFBFF090005000A00F3FFF7FFF8FF0C000000FDFF0B00FFFF0400F9FFFBFF0000FCFF0400FBFFFFFFF7FF0500170003001000FEFFF8FF0B000900FFFFFBFFF7FFFBFFF9FF03000C00000001000D00FBFF0100FEFF0200F6FF10000600FFFFF4FFFAFF0100F3FFF7FFFFFFFCFF08000B00020005000C00030009000A00F8FFF9FF0C00010004000300F8FFF3FF090009000000E7FF1100FFFFFFFFFFFFF9FFF9FF0B00F6FFFFFFF8FF00000700F2FF0000F7FF02000400F8FFF3FFF8FF090008000D00F7FFF6FF01000400110016000000F3FFFBFF0300FDFFEEFF0400040001000500FDFFFCFF0500F8FF0300F9FF0000FEFF0000F4FFF7FF1000FEFF050003000500FEFFFDFF01000900000007000D000000000005000D00FBFFFBFFF9FF0500010003000100FBFF0900FFFFF9FF0E000A00F4FFFBFF07000200F6FFFEFF010009000300040001000800FBFFFCFF05000400F9FFFFFF000005000600EAFFFDFF0100FCFF09000100FFFF010003000000F8FF0D0004000C00FCFFF9FFFFFF04000900F7FFF6FFF6FF0F000200FDFF0200F5FF03000E001100FFFFFAFFFEFF0A000A00F3FF0200FEFF0900FBFF0700030009000A000900FFFFF3FFF7FFFFFFF5FFF4FF1200FEFFF7FFF5FFFDFF0200F7FF02000800FCFF09000900F4FFFEFF050008000D0004000A00F7FF0900FFFFF6FF02000400090005000200F2FF0C00FDFF09000300EEFF0000F9FFF4FF01000E00FDFF0D000B000500FCFFFFFFF7FF0D00F9FFFEFFF0FF15000900FBFFFFFF090009000000F1FFF9FF0400FFFF0F000800FFFF0900FAFF00000C00F9FFF7FF04000600FDFF0A000200F6FF0600FCFFFDFFFBFF0C00030002000E000000F6FF0D001300FCFFFDFFFCFF040007000900F9FFFEFFFFFF0200F8FFF8FF060004000900040005000400F6FFFEFF0200F0FFFDFF0700FFFFF4FF06000D000900FDFFFDFFFCFFF6FF0100E8FFFCFFFFFFF9FFF5FF0000FEFFFDFFFCFF010002000B0008000C000800FEFFFAFFF8FF0600F4FFF7FFF6FF0300F9FFF8FF11000600FDFFFDFFFCFFFCFFFBFF11000800F9FF0300020000000800FDFF1700F7FF0B00FCFF0000F3FFFFFFFFFF0600F8FF00000600FEFFFBFFFCFFFCFFFAFFF7FFFEFF0B000400F3FFFEFF0D000800090003000A000700080003000D00F8FFFCFFFFFFF4FF0A000700F7FFF9FF0400FDFFFDFF0500FFFFFFFFFDFF0600FCFF0600030004000700060000000B000400F5FF1000F8FF0000FCFFFDFFFEFF03000000FFFFF6FF0500FEFF0A000000FBFFFCFFF8FFFCFF0600FBFF0500F7FFF7FFF5FFFCFFF9FF020003000800FCFF0F00FBFF09000200F4FF0B0009000600F3FF09000600F8FF02000600F8FF0300FFFFF9FFFDFFF5FFFCFF0100F0FFF7FF080002000B0005000700ECFFFCFF0400F9FF0500FCFF0500FBFF0300F5FF0A00F4FF070002000700FBFF0200FBFFEBFF0900FDFF0700F5FF0100F6FFF7FF0000F5FF0900FBFFFDFF0600FFFF0200060005000D00F6FF090005000500FFFFFFFFFFFF0700F6FF030009000B00F4FF0E00F9FFF8FFFBFF0500F9FF0200FEFF02000700FCFFFAFF0800F9FFFDFF02000300FFFF0700F6FF06000200F7FFF8FF070006000B00FAFF0500F0FF0C000000FAFF0400F6FF0000FBFFFBFF0C000500F7FFF7FFFFFF0000F1FFF9FFF7FFFBFF0100F6FF11000000FCFFF9FFF9FFF7FF0100F4FF0400F7FF0D00F9FFFFFF01000400FFFFFAFF09000100F9FFF6FF000005000100020004000100F7FF0C000400F7FFFDFFFCFF0F000D000C00040001000600F9FFFBFF12000400F8FFF9FF06000B000700FFFF0B00FDFFFFFFF3FF02000100FEFF0000010007000000FEFF00000000F7FF0400FCFFFEFF0D000F00FDFFF2FF00000300FDFF070005000300FDFF10000900060005000000F3FFF4FFFAFFFBFFFFFFFAFFFDFFFBFFFBFF0300FCFFF9FF0600F7FF0300FAFF010002000C000400F7FFF8FF07000600FFFFF8FF0A00F7FFFEFFF8FFF8FF0400F9FF0200020002000900FEFF0200FEFF07000A000500FCFFFCFFFFFF0300FCFFFDFF0900FDFFF6FFFFFFFCFF03000300100006000B00FBFFEBFFEDFF060003000800FFFF0F000100FDFFFEFFFDFFFBFF0D000400F5FF090000000D00F3FF0300F6FFFBFFEBFF030008000100F7FF0600F6FF0400FBFF05000C00F0FF0200F7FFFBFF0100FCFFFCFF0D00F9FFF6FFF8FFF8FF050003000200FDFF08000C000F0007000000FDFF0300F8FF0A00FEFF09000800F7FF0500FCFF08000300F7FF060004000D00F9FF1600EAFF07000B00F5FF0B001000FEFF0000F7FF03000A00F6FF0A00FDFF0F00F6FFFAFF0E000100000008000B000F00FDFF06000000FBFFF4FF090009000B00F5FFFFFF0100F3FF09000D000C000B00F5FF140000000000FCFF0000FCFF0000FFFF0D000700FCFFFAFFF9FF0B00FDFFFDFFFCFFFDFFFCFFFEFFFCFFFEFFEFFF09000300FCFF0700F8FF02000500F9FF0200F7FF090002000800F4FFF7FFFEFFF9FF02000200FDFF0000030000000400F3FFFAFFF9FF0300FBFFF8FF0100030006000E00FFFFF9FFF0FFFFFF0100F5FF1100EDFF090001000500F9FF0100FFFF0D0009000300080002000200F7FFFFFF0900FBFFF3FF0900FAFF0C00E9FF0500F5FFFBFFF6FF0600060001000F00FCFF000005000E00F6FF07000400020000001000FFFF0200F4FF0500120002000A00040001000D00020010000300FFFF0A00F0FF0900EBFFFDFFFBFF0600FDFFF9FFFAFF08000B00FFFF1000F9FF0900FCFFFAFFFFFFFEFF03000100030000000100EFFF0D00F4FFFFFF00000000F5FF0E00FEFFFBFF0800EBFF000000000E000800FBFFFDFF0F00F4FF0700F2FFF6FFF3FF0000050001000500F9FFFBFF0900FDFF030012000200F5FFFFFFEFFFFEFF0000F7FF090008000A00F7FFFDFF0600FEFF0D00F6FFECFF01000C00FDFF06000700F7FF0700FAFF0800EFFF0800FBFF00000700FFFF0800010001000200FAFF0C0006000100FCFF0400F2FF030002000200F4FF0E00FEFFFCFFF6FF0A00F7FF09000100F4FF0600FEFF06000500F9FFF8FFF6FF02000200090004000600FAFFF8FF02000800FDFFF8FFF9FFFCFFFFFFFDFF0D00F4FF0A000400FFFFF6FFFDFF040000000100F8FF040001000500010001000000FEFF0D000000FDFFFBFF06000600FAFF0400F6FF0500F9FFF8FF1000040006000700FDFF080005000000FAFF0700F4FF0000FFFFFBFFFEFFF1FFF6FFFDFF02000900F8FF0200FFFF0400FFFFF9FFFCFFF9FFFFFF0900FBFFF8FF0000F8FF0900F9FFFCFF0900F9FFF7FFF3FF0F00F0FF0000FFFF05001200F7FF020008000E00F6FF0900060002000300FDFF05000500FDFF0A00F7FFF9FF050002000E00FFFF0700FFFF0C000600FAFFFDFFFFFF0300FFFFFCFF0100F3FF02000400FEFFF7FF010000000900FFFF0A00FDFFFCFF0B00110004000200FFFF06000200FCFF01000600F5FF06000100FDFFF7FF01000A0006001000FFFFFFFFFFFFFFFFF8FFF6FFF7FFFEFFFCFFF6FFFBFF0200F8FF0500F6FF01000500FEFFFFFF02000200FFFF0900EDFF04000800FCFF0300EEFFFAFF0000F4FF0600FCFFF8FFFDFF03000100FBFFFAFF0800F8FFFDFF00000700FCFFFFFFF7FF06000F0010000A00FCFFF3FF0100FEFFF9FF0A00FAFF0C00EFFF0100E8FFEEFFF8FFF6FF040001000900FAFF0300FEFF06000100F4FF0C000200F9FF0400FEFFF8FF0400FEFF070007000000FBFF1100FAFFFDFFF9FFFAFF1200030009000200FAFFEFFF03000700FAFF0200FCFFFEFFF4FF01000D000400FCFF0400FAFFFCFFF5FFF7FFF8FF020009000300070007000E000300F8FF0800F9FF1000F5FFFBFFF1FF0400FCFFF7FF0400FBFF0A001200F8FF03000A000100F4FF0700FBFFF5FF0500FFFFF4FF01000500FAFFFCFF0700040006000500FBFF00000600F7FF03000F000100FEFF110006000000FBFF0200FDFF0800FFFFF7FF0B000700090005000A00F9FFFCFFFDFF0700FCFF080007000900FEFF0600F5FFFDFFF6FFFDFFFBFFFFFF0100FAFF0E0006000700FCFF0200080006000100FFFF05000600F7FF010008000800030000000600FCFFF8FF08000E0002000000F3FFF0FF0900FFFF0300EEFFFBFF0300EFFFFAFF0200F1FF0900FFFFF8FF0C00FAFF1000FDFFFAFF0E00F8FF010001000A00EFFF01000300FAFF0200F6FFFEFF0300010007000400FCFFF7FFFEFFFFFF0700FCFF09000100FEFFFFFFFDFFFAFFFDFFFCFFF1FF0200F0FF0200080005000600090011000800FAFF0A000900FBFF01001500FDFF0000FEFF0400F7FFF6FFFDFFF5FFFDFF09000400F7FF0200FBFF0D00F7FFFEFFFEFF0100F8FFFAFFFBFF00000300FBFFFBFF0100F9FF1400F5FF0700FDFFFDFFFAFF0100F9FFFCFF0900000008000700F6FFF8FFF5FFFDFFF0FFFEFF090005000A000A00FCFFF9FFFAFF030001000300F3FFFDFFF9FF0700FEFFFAFFF7FF0500020000000E00F6FF06000500FCFFFDFFFEFF09000500FDFFF6FF000002000100FEFF0D00FAFFF7FF1200F9FFFBFF000004000400F0FFF5FF090004000C000400F9FF0100FBFFF7FF0B00F7FFFFFFFDFF02000300F8FFFDFFF7FF03000100F3FFECFFEFFFF7FF00000500FCFF04000900FEFF00000700FFFFFAFF0F000000FEFF0800FDFF03000A000100040003000C0001000600F8FFF9FFF5FFFAFF09000100F8FFF1FFF1FF0300000000000C000E00ECFF0800FFFF02000A000600050001000A0001000D00FDFFF6FF0000F7FFFBFF0200F7FFF8FF07000000000003000900F7FFFCFF07000200FAFFF9FF0C00FDFFF8FF00000900F9FF010006000A000700FEFFFDFFF1FF0200F3FF0600F2FF090000000C00FDFFF2FFFCFFFCFFFBFFF0FF0700F7FFF4FF0700F7FF0800FDFF0000F8FF0300F8FF0900F9FF010004000800FCFFFFFFF8FF0700FDFF0000FCFF0C00FDFFEEFFF9FF07000600FFFFF7FFFFFF0300F5FF0700F6FF03000800FEFFFFFF04000300F9FF02000400F6FF0900F2FFFDFFFDFF05000300FBFF050009000800020007000C000700F9FFF8FFEFFF05000D0001000700FBFF0000FBFF0300FAFF0700FBFFEFFF00001100F4FF0F00E5FFFFFF0400FEFF00000B000100FDFFFFFF02000600FBFFFDFFFEFFFDFF08000200F7FFFCFF030007000200FBFFB60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD394D1695059DFF40AE256C5D5EDABFB69F5F40F37A588F50532CA408A8168AB1
//     * smlen = 2753
//     * sm = 13743CD9D613B998A4763D9A4F2618BF7B13543FD344B69EFD0C5AE439B3E5B8DFED144FE06F0983452AE52019BF2EC1F7264361E82591FDB0C05E5C0B32A22420B421805810F89DBF962E3887597DD2FEA01C4596033822A99BACA1343A008053FFFA5DB979E493E71C8B9F2BD2E46D237F0D92769FAA0A3B23B938488D2B40BBFFB3C8CD35AA1C79ACF28303F357A9AB367330A1CEA217701A0BCE89E015C64D34CD22F11A42A8D36B3F45FD74E0055B2B162E2C2DF505F609BC599CFCB2BA3921AAC37E155035140126FB3DDFD88A9D77F6B33D370B653813ABA5857C1E3646A6EB8C81C094EB59CD86F92F9E27B9C53010D52755F268BE672AC153E8538967F620A95DC2B3B6A084753A2A95800CEF18115BA816008C9469B88F16E8ECF9EE85C37B7F7C63EF98C8464B35518A0F4317C39AA101FC85943E14A196051BAFF5214BC1ECEED3F520B95A38DE945CB2FCD358CBCEE6A7F848112863BF0AFDD699E84AB8AD62057A354B0EC395851B4352B99D466503DF795C8D0ACCE3462719779F9C5AFC330A8735B9B4E18D6A2CEF6C640170028D4DCA4F3B0DF09B210FCDC469282B5593F9D40ECD9D52D13352811EBEE1B46C277A73089262827E5CEE82408B744A8257A44F5F7B16C69FD172EA62F3D55D3BF30B96C9B4DC5B86CC6CB1F3F296E78523923C1D7599E459636703CF8030B60513059A5AFD8B033736EFDEC506DC8F40EC20A4213F50067528AAABDE320BDA6E313D224ED1BBF868115759773DD5F107A3D3479823AFDF2E289AB20585E3BDD93FBDE1694C82567EBC65373A688178BB8D540AAD977EC64ECB7277B720760E571D0B837CE33B0E629832CD84707A7E4CB6111280DC16FCD98287DD5B089048520206B865EF1F9095528E6C7ED11DFBBC582946D3C50B529A4A0FE8E389FCCB09CFA04849E034C254F3116F05F7C75910017E6E01112BB6A02D288A8893AE506421E9F02F374A75015416956A3C7ACE5616A162AABFEF5F1B00D4C82858F7A2E48BBFE131AF4A327C09EE19402FDFEDA5BCDE266EB3EAA375A514899907D0DDFBD7FD4A2EA4CBCACD887311DA98653CBFE461BE9A491120A39384FF4376D0152A29696B690ADED65A698E0546B32B1494B3B7470FFBA1E052702ADB1B9ADBACB594DFB5106C5567E3FAE84C131FCEC5395E9C527304ECE8C83BAAE38DEBCC9E1732A2B79D2693481D14803BEC157D714EDDC6FC5F0697073084D36D6110E793C8C846531B14CCCBFEB7D3080E83D70941537606227E2F860084C8722EFED4E829A57B2629C53ACE8C1C77603B15532090E75FEEF57020CC0E6F1FABC426088C0C683062EBF6E588B2F44D0E37C623F12128FB940CA239F8CCD771D3DC4A4BEE056A8BCBB9E412BDC8CAE201DD8E18D74B598771367202D42D93C167E554A04E25B882EB79F6DC0B91826700ACFC4803EBCC105B40DA41875A2174F9FAEC30D64E3BAF0D3C4C60E33470968264D49900F334DCDD0D1B9F85822A063A68F027D9E6BFAE2E68C19D73EADAF48EC457C1D857E05F9200A296E4915C292EFBEBC4A9754B291DE2A7A7411A0FE3692FEF691ED703247002CAA7550730357A031ACA61688911DC6A546AED3F63B4BAA4DFD31E6DB3894F73029174F87495255FDD5A708FB213FD855FCDB523881DF45B2754C329367D3741226100F57A5F1E23A2DECBFF6BD1B79B9E1C0C7BA11157D9CF9173A13D9DB71D539432B39F78183F267E851A6CE314212BB2F448527DF68B822FFE6ECE7377070750EE0E8F7C7A84553B293C1B1073E6573085569DCACF3D82167B58D12915E75400F3A2D72A399C1354926BE462DAB3CF892502F4DF62628A58E77272E2F888555946B2DF445E54EE15C7703F7F632DB235C9D443F3C16012881824435FD5ECC602665912FFA65D65ED92D202567852A1D0490159235A93556D39C99805B6D4C4CB779183E08D0A5FC9E8CF007AE36134135162941CE3E582098C605F070048C0AC627E54555740B00C724FFB68839F60C692A48E349CB25AE564E98AD920B71C19D5729AA759F4FBE1E2639C84D71034740C1AEDCAF84BEAD4CB2F75CCB22DBDC9E4D7100B1F8F35E1D9CEBBF8006AFE2E86BBE9AB84A691378699FC79AC749EC9B629A10CD1B14E2008F08038984A270FDEB4E9C003BD006ED89FF1256ACC6D0DE7AFB2029604321D317B89BAE3A28416CBE28CCC6A944F6D3A6504BC5E552BD7784CFE293576BA30D9A8983D84D5ADCA28F1BC852ECFAD6C66B727373B2345321A18B6E2A0F3C08BCE8FCC61A205C0E5F0E9C221B128D0E3C04845EFFB7428178E0C7EAD35A526D38286451D4919C3D411F79B0DA7306D1FD98941C9D92CB4CA227C4FCCE088D76666C76AA29A15D4F6F38B212733C5AC9A91C8C36F869A59A99610FE2FF6293432ED64466029C55C11AEE67365394718180D87DBFAF85F8A045A04D5DDB70EDC54D116E265DFD70E40DF97AE9A4C833183BD66089BCB8AC9471BB774A704ED070EF17D4321E39FD9356867485AE8653C7C9BAA77B43D4355A82896CD710C0F4018A0668BB8F013633BD93A668180CDF0C95F130E42E4D6B04225DD8963464E62EB80D092D717BA9F837B357FF662598A6673DA0267107FD669EF03E01234962435DBE523C9F3E789813DE5AF59BF79994F234DA54C56A65EE9ED5D04B0625CEB29ACEF98BB483F3D8BF5074CAFFAD4635C9D412089C77EC81375F0FC30717C166B386FAC0C81ED285D38AEF2CAD959E39649F31449D65185AF84EC23B34D193EDBB9C572B9818D285109FB8334574CAF14381CF005A07BADE9B2C9C3B69FDD4C57D396FEB7130B092FE98407D3D038F7E51D7FDCF55213F363234306E9FDC4D711B590C684708C5AD86D900E4C7B9951029D6FDE5CE088C8F9D5D9A098C08FB904C07D9AF8F3307AB00370A685296F5F08CAB69947274089FA8D70BD6E0FFF1BDECDC96E1E5094D0B904F71B8814FE4C1FCE6C11D8883045E4FA4F970A892BC130153F846983440121617A5C6DEB390D4DD4FDF6AB786F2A2B9C44658889A515442D085BD012C7F4D5CB6FD17FFDC406F2B523958156190F47EFBE3CBA8D1EA7618CA86DEE0D114AC55EC55F640A05F4CC9DF350238CE031678BB98F155D4418DCAC97D8C5F4352D21D4D347A0A67120953A473040F317E0CA2F8E8B74CD263580EFE8F5BBA540CC402D624C8CB1F46A5458F20EC38A7E36BDCC812651C29851D692B7339F73D563B7BA708DCBF2F8D20970760823E3EE0D87658607CD911E08D818821AE6980868C0B3DCFAD9506903F80F04EAAC193741B61713388668B7165F8B9EB751E583EE78D0BB99E574A2E60A5A8C3C07417F8C28DF1613F09EDDAA3728481BE0C042F54DED6F4B825F8416FA7FF9D088F92939DB9BE5908057B10C5B3610D51CABEED0B22E7EB54D929CD42A2FC006E02B9CBEF3538911B984D9D7FF19D3709F47BEDAAE8B8614BFF07A00B48484DC61A08DCD2112644E9B64D02FAC284E2680215554C66DB3670F98BC86F31CBD89916E8192C18D3D6A25987E3FC5B4CDAE929907C7D449B01F7BE45EB9EBB0B7AB4CB69A9D99BD6E082CF6683403B8413B6885C9E8D2E9DB18B5A9B47CCDACDEBA8A03D4D0C4517DE93C8527898F7F89BDB20BC8929E7057E40CD61AF0623D64384F6CE5E8DD30F0F56F8C4855526B5FE1B88CC6F96EDC897E71638D93FACA00DC6FE30F8B3AC0EC48AE46889E75870A01BE62CDFC6A087208A17D8E3A5F55BC336233ED43DCE46111F7B98BE16DB5DAF2A79D1388387EA3201B9FC6F1A808BD5BB545E9075E1144DE5DD516AA3C086148DF7A5A9D2C2D40DFBED1D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8
//     */
//    public void testCat2Vector0()
//    {
//        byte[] seed = Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1");
//        int mlen = 33;
//        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
//        byte[] pk = Hex.decode("CBD291D6599F23872E227742166E71AD533DE6B8306805A539274B9A5CAC75298152C19732AB6F8AD5EED79EB918563A2533F89D782E80B1A8C784FEB08745F8AC1D0C1D6DFE80A8329D00AE7B8B956FB668A138480A5D151EA2324B5586B5769F997385EE2DA811D083190D397482EF72244B8E4D0FC41492DBA7C11DD344BC18F21860759E88484A37FBBC9EC4855B07F6EA4EDA62BB318A966479A20007A93C7DDF3E70CD08CEF7A6630F9071C7094FC4287CD754FC695B52152AA7C54D690693A2979C120312A689310B02355136F89656AACD54EC49E62A000F263092A1A0AA535E2C256A9B85657385E4E6055E91A3BA20300D87DDD1805E7C3A6EF094C826C12846E805D201848CEB0E11FC10D0BEDA60E6E2A78D105C8A084B5C38C7B3382A2E150C2FC0CE891E6DD09406978AEC134C7FD8E22CAE881A6DBD0930A8B46B211A2A24C6054639E546B2323BE14112C2F9D9D0AAA91CB1391884738452BDAE052354FBC96ABB54D58F9802BB7EFA6CA9B5CD4F8A3C82B472839DC7E2986FC5280972040C3E68942B9B936A1C855C94C45AB77BBAFBD9E60702477104CE25E665493B9B2A3BD5D7425BBA24F391BC449C6C307B57BAD0DA42D60FED3B0D80BB5A13B100F83AB7F00644A0A0AF339685E139AA8E9F72AAB439EB10386C212C3A6F620E9561EF5E3F596BB165B419B7F9F780A5BB5C44C156215B9CDD80C142124C2C60F33899F11820C82E39142E6AE9B8869D404C54BD6E7406B27E9020EB9B80B93FEA6750DF8709417D93BEC543725CF148C51A76B66D5FCD7C7240911A3E479401D35BCC1512F541E7620178752EAE40C211663907067F4202D7601D41D0FA09CADDAE38B9FF30457FD1D68C50DB8388FE69372955A638C0932A4CD3A65EB77642F2A100DE437A50E3DD40B7597A8B433501C9E0766335D4CA3ADF5618C481A0ED2D2551C0E164B520513766E24956778363170351C0C1A67C11CDF279C76E357639B06F0E3ED38F6EF2905D02EEC228E4B61AE017D974C05966B85FC21D2D7A978279820C94856011A149CC3B34C09E8A9A04FAE7B18A7806E74328EA44C7392339A56AD14BA188002FE6C081F221949294636B04D10F6D58E9AD74735CAA1F4315E899DBFC0384A2A0538E3160BE7954168C2D7F188342655ABE81ED5D3651660E4634F78063DF4B7D7E5EF628476ADA3478E1D9C0FDEBF73593FD79A17E845C2210B8DF2713D38ED3E156F2A72B9157C3CCE089A91C700B7D7C3B62118894159B096AEC01C551C78AD31B467F84CAB7D0AE0A83EAB3452A028C4127CECF3737088A6985FCF1CC4AE22F83BE00610804C8B8C7562645CC5B0A66F56C4C18EC47552BBD3996D787681E0043F451DD2DDA512EC0FE3A10D75D5D893AF17FCC49FDEEF0B120A9F5300908E49FC2FCCE4D88EE2627C6D5AC33EE6BF471F80E72D3B729AC4E4E5E405D86B467B48F6BD2EA45457293BDFB0DC0085D38E265589DB8AFECF259D098873F047144B288EEC338899B0ED949466F335004080AF0E3E6D744A49F6237244CB94F0A0837C135AFC0424E9FDC87C6CF372905CBF3E3A1CE7922FE1B53E5B5CE8A95E47FE72439A1ABAFE9250EC5B89E54C672C8BBB82F4D46AAAC88AF1BD1D14F48D3753D23CAE2485554C9373706DEADE5E70F8195392069BC4FE1D3B6D471693E7A0D49EBD2E65260B6DA26C95158C4ABB8EB7DB2BB1347810376BCDB1DF92E8B30C28BDF7AE7E28498F55AA61DDEE32A726F03045A81410865C87AB82AEF71F03324E63B2C0598FD40463006E3D407272C4631C9B019F211D69214CCAABD4B08D93A7B68A1884577D413D0A61CEDE21E0B5923211413CC599B3D0FC9B055D495139B0061E36D6A665CADD0BAC630D4B6C64C6F4B12BE8F8B986FB84B413C173C2A3C0B07691E8A9EAA993600E5BF2382B314E20F147A63AFB88437378AD627A4DB7F45C97D6966361469905A0039FF2400B094171DD5ABDBBA80CC976BD13C78F50D048145C4A330B5C8DFD7CB6B34D9446B35709A32D9372F2EAB05745C191DE6CB51FF02E222F7FAC560CF384566E42414674D7C91A2DF47F2DFA3DCAAB1668593CAF41893B7D81C5F5CD12BABD744C4BD061675A59238283CFDF0B94BFA44214265227527447577042901F5E11108529044D108AC9100EAD8349FAB49F53DA7CAEAF166D66176D175DB7416FA1BE7632DF72E54C04829424F01CB3733E6D3F5556200FE4D3A252C744EDC3706A5072E57CE2B8BA28E25EC7DCEEB7A9A26B06BEF4F76FDE56B24F2D5E858229924E0D2CE1F1D6AD912C14EC018AA4552B164BC98736E5280204E5E13789CD5229AA5D69D95A4930B4484E40AF229518346682C73BE1D2DDDFE9FFE53A31FC9C65067008F3AC155705E32338AED22FBB2425C462AAB3D43C70BE2E996CC680B8059222BB782836BC4B94A2CE68D42676D522AC2D44804C6C334672F3A49F6D257E608EBA187B230FBBE6014A2D4704007FC731E993295012303A3BA755FBA7872DB349E0C0E4B1FABD0007B90933CE48A71D647B3EC93A53FC5EBA17C994B21E7B2D2B8C60A6324B81361482B3223A031DEF2C0B0286052902F6317F19FCFE5C6377498323624290DF2F21A0C333E37963A4ECDD68BB1B4A0DCE55014E9B52B60A8C14FBC780C6625DEEF87A428A2149C286BFCBBCD2EBD6A75288ABBB9E4D3973332E9332C93F5886ABE65603216B0F92B07662E72724FC0AF89582BA1106F79B7EAA9596638AA5FF0B9162EFD5BC6626AF45C459661A3AF444927B40A7368E5CB069A3D136713479524A4A9CB4BB6D9D4A3B0A64654A7D105C8F6C92ABC0BD31EB4A2AB8B07F0514450F69A42A79B043872DF17B00A5C61958E228857D331BDC06E4074E12E2BB028174946AECBC237A0B113123FF5784BDE37337A0B20AAD79967D0A99A37333EE0B0D09F717691265F6B66441E2B788C1E55405D4251BDABABE05220223D38AA034FBD9DD5CA8052BC0CD1CFC5671BC9D977C8B4BB90015CC07C34015C5C4DD2213982054855C260663C2684B0372289358F0891416713A70AF6843AAAE2F6F7BC5F124A5234BC278B81E345736D66EA50674AA341715469FBE4D24D7E15B9141143C95F57445036E55847B13F431DA5282C43520F992942FF19E702277A16B6624ADBE35319ECA74CB922BA892FF0FE53740AABA58FB37BF8F872892D831004073DF749B1B15E10F3518F3D55B0C024BB8DA18C304F6A8456811911DA16D45F5D6BB69EE3EA90BB0887289918046F3B09BFBA14C2C201932DE6C3D52A515005B7E8077C42BF77575315421711DF028577834161A699B3C8D8C6C200C70F3525A6D4D3DBCD0EA2F40272D2D8F1F894990848E4E66BF50D1404C4CA89FA27AB9FB3478D6A430D055E1B2E51173EE194DCCD90CC1E678A5CC6887479C9106C4A63524C354CCEBDF0AC405A4ACE8F0F26EBF2C821BF85C3762E84165F8410A14644FBB7CAAE15C67EF7FA273C6C7566341C0C48ACAEF88E043C76A77710D0ACB4FBC6EC21C0B4707461CBBCBD06CDD238380C7CA686BCF7E9BD28B942E7BE4A07494638506F873A184C5B8C25793F20AD846CCEF0D4F733BEA00A700EDAA0B4AA23F2D45E10308400BADC0F867E0917C7150D2E45A5C6C4688CE711C74B2DCB788CB48CD76317662F5F9E4782576B4368B525D7B0806C79FF31B0E577B52B3545A480E202E93F2F6174C378CD896C3FD8C2735D76A407CD07D99AE4C7F276436C69024A5914355386B42F94F386B8390179EA43D2AF965A69B1257805AEEBCE931789528E38EFDDE2944459E72208FE80BE4FE4E89586A50D983A24A0980C87034DAC00777C546B013F89589A3A10159249A190E0D0B043AA97FDE068EB92120BF139D4CAB62F5FD132C749D66D55A00A1267B05058DC9BE18B17D8276E00F491FE43D393D5A241F6D48C3C1A56F83C5465902E347C4DB7DC78D8A6F383A39F756B88D2447FB08430967710957D113F344A1C494CF6A9C6477B78578E80D10FD4350FCD94A0E6550BD48D014A26E587E4A128E369702EA8CD35AE7AA87E728FE9B82755F9D41BF2889690B4854FB0C9129D61072CF74B9ED3670B4EB309B51BFCFE813AADA619334EBFAE570E4A300B00FB52106F1EEA96F4CC6ED308264AB60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD");
//        byte[] sk = Hex.decode("17000000020000000B00FDFF0600FAFF05000D0007000200140010000700F6FF0A000300F6FF0800040009000500060002000600FAFF0C00F9FF0400FBFF0D000300F9FFF4FF01000900F6FF06000C00FDFF0300FCFFF4FF18001400FDFF0600FEFF0D00F9FF0900F8FFFFFFFFFF0300FCFFFEFF0A00F9FF0200FEFFF9FF02000100FAFF010001000A00010000000500FFFF0400F6FF04000600FFFF0000F7FFF3FFF9FFF8FFFFFF010011000900F1FFFDFF0600F7FFFCFF0900090005000300FDFFFEFF06000300FDFF04000100FAFF0400F9FFF5FF03000000080006000200F5FF1000FFFF01000500020008000C0001000500060009000800FCFF00000100FDFF01000000FEFF0D00F8FFFDFF0000F8FF0A00070017000B0001000900F3FFFAFF0E00FFFFFAFF02000500F7FFF9FF00000300FEFFFFFF0300FFFFFBFFF6FF0900F2FF050002000C000400F7FFF5FF0300FAFF1200F9FF0900020009000600FEFF0300020005000000F8FFF0FFEEFF0A00FCFF01000100FCFF06000700F8FF0C00F7FFFEFF0100FEFF0500F9FFFBFF090005000A00F3FFF7FFF8FF0C000000FDFF0B00FFFF0400F9FFFBFF0000FCFF0400FBFFFFFFF7FF0500170003001000FEFFF8FF0B000900FFFFFBFFF7FFFBFFF9FF03000C00000001000D00FBFF0100FEFF0200F6FF10000600FFFFF4FFFAFF0100F3FFF7FFFFFFFCFF08000B00020005000C00030009000A00F8FFF9FF0C00010004000300F8FFF3FF090009000000E7FF1100FFFFFFFFFFFFF9FFF9FF0B00F6FFFFFFF8FF00000700F2FF0000F7FF02000400F8FFF3FFF8FF090008000D00F7FFF6FF01000400110016000000F3FFFBFF0300FDFFEEFF0400040001000500FDFFFCFF0500F8FF0300F9FF0000FEFF0000F4FFF7FF1000FEFF050003000500FEFFFDFF01000900000007000D000000000005000D00FBFFFBFFF9FF0500010003000100FBFF0900FFFFF9FF0E000A00F4FFFBFF07000200F6FFFEFF010009000300040001000800FBFFFCFF05000400F9FFFFFF000005000600EAFFFDFF0100FCFF09000100FFFF010003000000F8FF0D0004000C00FCFFF9FFFFFF04000900F7FFF6FFF6FF0F000200FDFF0200F5FF03000E001100FFFFFAFFFEFF0A000A00F3FF0200FEFF0900FBFF0700030009000A000900FFFFF3FFF7FFFFFFF5FFF4FF1200FEFFF7FFF5FFFDFF0200F7FF02000800FCFF09000900F4FFFEFF050008000D0004000A00F7FF0900FFFFF6FF02000400090005000200F2FF0C00FDFF09000300EEFF0000F9FFF4FF01000E00FDFF0D000B000500FCFFFFFFF7FF0D00F9FFFEFFF0FF15000900FBFFFFFF090009000000F1FFF9FF0400FFFF0F000800FFFF0900FAFF00000C00F9FFF7FF04000600FDFF0A000200F6FF0600FCFFFDFFFBFF0C00030002000E000000F6FF0D001300FCFFFDFFFCFF040007000900F9FFFEFFFFFF0200F8FFF8FF060004000900040005000400F6FFFEFF0200F0FFFDFF0700FFFFF4FF06000D000900FDFFFDFFFCFFF6FF0100E8FFFCFFFFFFF9FFF5FF0000FEFFFDFFFCFF010002000B0008000C000800FEFFFAFFF8FF0600F4FFF7FFF6FF0300F9FFF8FF11000600FDFFFDFFFCFFFCFFFBFF11000800F9FF0300020000000800FDFF1700F7FF0B00FCFF0000F3FFFFFFFFFF0600F8FF00000600FEFFFBFFFCFFFCFFFAFFF7FFFEFF0B000400F3FFFEFF0D000800090003000A000700080003000D00F8FFFCFFFFFFF4FF0A000700F7FFF9FF0400FDFFFDFF0500FFFFFFFFFDFF0600FCFF0600030004000700060000000B000400F5FF1000F8FF0000FCFFFDFFFEFF03000000FFFFF6FF0500FEFF0A000000FBFFFCFFF8FFFCFF0600FBFF0500F7FFF7FFF5FFFCFFF9FF020003000800FCFF0F00FBFF09000200F4FF0B0009000600F3FF09000600F8FF02000600F8FF0300FFFFF9FFFDFFF5FFFCFF0100F0FFF7FF080002000B0005000700ECFFFCFF0400F9FF0500FCFF0500FBFF0300F5FF0A00F4FF070002000700FBFF0200FBFFEBFF0900FDFF0700F5FF0100F6FFF7FF0000F5FF0900FBFFFDFF0600FFFF0200060005000D00F6FF090005000500FFFFFFFFFFFF0700F6FF030009000B00F4FF0E00F9FFF8FFFBFF0500F9FF0200FEFF02000700FCFFFAFF0800F9FFFDFF02000300FFFF0700F6FF06000200F7FFF8FF070006000B00FAFF0500F0FF0C000000FAFF0400F6FF0000FBFFFBFF0C000500F7FFF7FFFFFF0000F1FFF9FFF7FFFBFF0100F6FF11000000FCFFF9FFF9FFF7FF0100F4FF0400F7FF0D00F9FFFFFF01000400FFFFFAFF09000100F9FFF6FF000005000100020004000100F7FF0C000400F7FFFDFFFCFF0F000D000C00040001000600F9FFFBFF12000400F8FFF9FF06000B000700FFFF0B00FDFFFFFFF3FF02000100FEFF0000010007000000FEFF00000000F7FF0400FCFFFEFF0D000F00FDFFF2FF00000300FDFF070005000300FDFF10000900060005000000F3FFF4FFFAFFFBFFFFFFFAFFFDFFFBFFFBFF0300FCFFF9FF0600F7FF0300FAFF010002000C000400F7FFF8FF07000600FFFFF8FF0A00F7FFFEFFF8FFF8FF0400F9FF0200020002000900FEFF0200FEFF07000A000500FCFFFCFFFFFF0300FCFFFDFF0900FDFFF6FFFFFFFCFF03000300100006000B00FBFFEBFFEDFF060003000800FFFF0F000100FDFFFEFFFDFFFBFF0D000400F5FF090000000D00F3FF0300F6FFFBFFEBFF030008000100F7FF0600F6FF0400FBFF05000C00F0FF0200F7FFFBFF0100FCFFFCFF0D00F9FFF6FFF8FFF8FF050003000200FDFF08000C000F0007000000FDFF0300F8FF0A00FEFF09000800F7FF0500FCFF08000300F7FF060004000D00F9FF1600EAFF07000B00F5FF0B001000FEFF0000F7FF03000A00F6FF0A00FDFF0F00F6FFFAFF0E000100000008000B000F00FDFF06000000FBFFF4FF090009000B00F5FFFFFF0100F3FF09000D000C000B00F5FF140000000000FCFF0000FCFF0000FFFF0D000700FCFFFAFFF9FF0B00FDFFFDFFFCFFFDFFFCFFFEFFFCFFFEFFEFFF09000300FCFF0700F8FF02000500F9FF0200F7FF090002000800F4FFF7FFFEFFF9FF02000200FDFF0000030000000400F3FFFAFFF9FF0300FBFFF8FF0100030006000E00FFFFF9FFF0FFFFFF0100F5FF1100EDFF090001000500F9FF0100FFFF0D0009000300080002000200F7FFFFFF0900FBFFF3FF0900FAFF0C00E9FF0500F5FFFBFFF6FF0600060001000F00FCFF000005000E00F6FF07000400020000001000FFFF0200F4FF0500120002000A00040001000D00020010000300FFFF0A00F0FF0900EBFFFDFFFBFF0600FDFFF9FFFAFF08000B00FFFF1000F9FF0900FCFFFAFFFFFFFEFF03000100030000000100EFFF0D00F4FFFFFF00000000F5FF0E00FEFFFBFF0800EBFF000000000E000800FBFFFDFF0F00F4FF0700F2FFF6FFF3FF0000050001000500F9FFFBFF0900FDFF030012000200F5FFFFFFEFFFFEFF0000F7FF090008000A00F7FFFDFF0600FEFF0D00F6FFECFF01000C00FDFF06000700F7FF0700FAFF0800EFFF0800FBFF00000700FFFF0800010001000200FAFF0C0006000100FCFF0400F2FF030002000200F4FF0E00FEFFFCFFF6FF0A00F7FF09000100F4FF0600FEFF06000500F9FFF8FFF6FF02000200090004000600FAFFF8FF02000800FDFFF8FFF9FFFCFFFFFFFDFF0D00F4FF0A000400FFFFF6FFFDFF040000000100F8FF040001000500010001000000FEFF0D000000FDFFFBFF06000600FAFF0400F6FF0500F9FFF8FF1000040006000700FDFF080005000000FAFF0700F4FF0000FFFFFBFFFEFFF1FFF6FFFDFF02000900F8FF0200FFFF0400FFFFF9FFFCFFF9FFFFFF0900FBFFF8FF0000F8FF0900F9FFFCFF0900F9FFF7FFF3FF0F00F0FF0000FFFF05001200F7FF020008000E00F6FF0900060002000300FDFF05000500FDFF0A00F7FFF9FF050002000E00FFFF0700FFFF0C000600FAFFFDFFFFFF0300FFFFFCFF0100F3FF02000400FEFFF7FF010000000900FFFF0A00FDFFFCFF0B00110004000200FFFF06000200FCFF01000600F5FF06000100FDFFF7FF01000A0006001000FFFFFFFFFFFFFFFFF8FFF6FFF7FFFEFFFCFFF6FFFBFF0200F8FF0500F6FF01000500FEFFFFFF02000200FFFF0900EDFF04000800FCFF0300EEFFFAFF0000F4FF0600FCFFF8FFFDFF03000100FBFFFAFF0800F8FFFDFF00000700FCFFFFFFF7FF06000F0010000A00FCFFF3FF0100FEFFF9FF0A00FAFF0C00EFFF0100E8FFEEFFF8FFF6FF040001000900FAFF0300FEFF06000100F4FF0C000200F9FF0400FEFFF8FF0400FEFF070007000000FBFF1100FAFFFDFFF9FFFAFF1200030009000200FAFFEFFF03000700FAFF0200FCFFFEFFF4FF01000D000400FCFF0400FAFFFCFFF5FFF7FFF8FF020009000300070007000E000300F8FF0800F9FF1000F5FFFBFFF1FF0400FCFFF7FF0400FBFF0A001200F8FF03000A000100F4FF0700FBFFF5FF0500FFFFF4FF01000500FAFFFCFF0700040006000500FBFF00000600F7FF03000F000100FEFF110006000000FBFF0200FDFF0800FFFFF7FF0B000700090005000A00F9FFFCFFFDFF0700FCFF080007000900FEFF0600F5FFFDFFF6FFFDFFFBFFFFFF0100FAFF0E0006000700FCFF0200080006000100FFFF05000600F7FF010008000800030000000600FCFFF8FF08000E0002000000F3FFF0FF0900FFFF0300EEFFFBFF0300EFFFFAFF0200F1FF0900FFFFF8FF0C00FAFF1000FDFFFAFF0E00F8FF010001000A00EFFF01000300FAFF0200F6FFFEFF0300010007000400FCFFF7FFFEFFFFFF0700FCFF09000100FEFFFFFFFDFFFAFFFDFFFCFFF1FF0200F0FF0200080005000600090011000800FAFF0A000900FBFF01001500FDFF0000FEFF0400F7FFF6FFFDFFF5FFFDFF09000400F7FF0200FBFF0D00F7FFFEFFFEFF0100F8FFFAFFFBFF00000300FBFFFBFF0100F9FF1400F5FF0700FDFFFDFFFAFF0100F9FFFCFF0900000008000700F6FFF8FFF5FFFDFFF0FFFEFF090005000A000A00FCFFF9FFFAFF030001000300F3FFFDFFF9FF0700FEFFFAFFF7FF0500020000000E00F6FF06000500FCFFFDFFFEFF09000500FDFFF6FF000002000100FEFF0D00FAFFF7FF1200F9FFFBFF000004000400F0FFF5FF090004000C000400F9FF0100FBFFF7FF0B00F7FFFFFFFDFF02000300F8FFFDFFF7FF03000100F3FFECFFEFFFF7FF00000500FCFF04000900FEFF00000700FFFFFAFF0F000000FEFF0800FDFF03000A000100040003000C0001000600F8FFF9FFF5FFFAFF09000100F8FFF1FFF1FF0300000000000C000E00ECFF0800FFFF02000A000600050001000A0001000D00FDFFF6FF0000F7FFFBFF0200F7FFF8FF07000000000003000900F7FFFCFF07000200FAFFF9FF0C00FDFFF8FF00000900F9FF010006000A000700FEFFFDFFF1FF0200F3FF0600F2FF090000000C00FDFFF2FFFCFFFCFFFBFFF0FF0700F7FFF4FF0700F7FF0800FDFF0000F8FF0300F8FF0900F9FF010004000800FCFFFFFFF8FF0700FDFF0000FCFF0C00FDFFEEFFF9FF07000600FFFFF7FFFFFF0300F5FF0700F6FF03000800FEFFFFFF04000300F9FF02000400F6FF0900F2FFFDFFFDFF05000300FBFF050009000800020007000C000700F9FFF8FFEFFF05000D0001000700FBFF0000FBFF0300FAFF0700FBFFEFFF00001100F4FF0F00E5FFFFFF0400FEFF00000B000100FDFFFFFF02000600FBFFFDFFFEFFFDFF08000200F7FFFCFF030007000200FBFFB60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD394D1695059DFF40AE256C5D5EDABFB69F5F40F37A588F50532CA408A8168AB1");
//        int smlen = 2753;
//        byte[] sm = Hex.decode("13743CD9D613B998A4763D9A4F2618BF7B13543FD344B69EFD0C5AE439B3E5B8DFED144FE06F0983452AE52019BF2EC1F7264361E82591FDB0C05E5C0B32A22420B421805810F89DBF962E3887597DD2FEA01C4596033822A99BACA1343A008053FFFA5DB979E493E71C8B9F2BD2E46D237F0D92769FAA0A3B23B938488D2B40BBFFB3C8CD35AA1C79ACF28303F357A9AB367330A1CEA217701A0BCE89E015C64D34CD22F11A42A8D36B3F45FD74E0055B2B162E2C2DF505F609BC599CFCB2BA3921AAC37E155035140126FB3DDFD88A9D77F6B33D370B653813ABA5857C1E3646A6EB8C81C094EB59CD86F92F9E27B9C53010D52755F268BE672AC153E8538967F620A95DC2B3B6A084753A2A95800CEF18115BA816008C9469B88F16E8ECF9EE85C37B7F7C63EF98C8464B35518A0F4317C39AA101FC85943E14A196051BAFF5214BC1ECEED3F520B95A38DE945CB2FCD358CBCEE6A7F848112863BF0AFDD699E84AB8AD62057A354B0EC395851B4352B99D466503DF795C8D0ACCE3462719779F9C5AFC330A8735B9B4E18D6A2CEF6C640170028D4DCA4F3B0DF09B210FCDC469282B5593F9D40ECD9D52D13352811EBEE1B46C277A73089262827E5CEE82408B744A8257A44F5F7B16C69FD172EA62F3D55D3BF30B96C9B4DC5B86CC6CB1F3F296E78523923C1D7599E459636703CF8030B60513059A5AFD8B033736EFDEC506DC8F40EC20A4213F50067528AAABDE320BDA6E313D224ED1BBF868115759773DD5F107A3D3479823AFDF2E289AB20585E3BDD93FBDE1694C82567EBC65373A688178BB8D540AAD977EC64ECB7277B720760E571D0B837CE33B0E629832CD84707A7E4CB6111280DC16FCD98287DD5B089048520206B865EF1F9095528E6C7ED11DFBBC582946D3C50B529A4A0FE8E389FCCB09CFA04849E034C254F3116F05F7C75910017E6E01112BB6A02D288A8893AE506421E9F02F374A75015416956A3C7ACE5616A162AABFEF5F1B00D4C82858F7A2E48BBFE131AF4A327C09EE19402FDFEDA5BCDE266EB3EAA375A514899907D0DDFBD7FD4A2EA4CBCACD887311DA98653CBFE461BE9A491120A39384FF4376D0152A29696B690ADED65A698E0546B32B1494B3B7470FFBA1E052702ADB1B9ADBACB594DFB5106C5567E3FAE84C131FCEC5395E9C527304ECE8C83BAAE38DEBCC9E1732A2B79D2693481D14803BEC157D714EDDC6FC5F0697073084D36D6110E793C8C846531B14CCCBFEB7D3080E83D70941537606227E2F860084C8722EFED4E829A57B2629C53ACE8C1C77603B15532090E75FEEF57020CC0E6F1FABC426088C0C683062EBF6E588B2F44D0E37C623F12128FB940CA239F8CCD771D3DC4A4BEE056A8BCBB9E412BDC8CAE201DD8E18D74B598771367202D42D93C167E554A04E25B882EB79F6DC0B91826700ACFC4803EBCC105B40DA41875A2174F9FAEC30D64E3BAF0D3C4C60E33470968264D49900F334DCDD0D1B9F85822A063A68F027D9E6BFAE2E68C19D73EADAF48EC457C1D857E05F9200A296E4915C292EFBEBC4A9754B291DE2A7A7411A0FE3692FEF691ED703247002CAA7550730357A031ACA61688911DC6A546AED3F63B4BAA4DFD31E6DB3894F73029174F87495255FDD5A708FB213FD855FCDB523881DF45B2754C329367D3741226100F57A5F1E23A2DECBFF6BD1B79B9E1C0C7BA11157D9CF9173A13D9DB71D539432B39F78183F267E851A6CE314212BB2F448527DF68B822FFE6ECE7377070750EE0E8F7C7A84553B293C1B1073E6573085569DCACF3D82167B58D12915E75400F3A2D72A399C1354926BE462DAB3CF892502F4DF62628A58E77272E2F888555946B2DF445E54EE15C7703F7F632DB235C9D443F3C16012881824435FD5ECC602665912FFA65D65ED92D202567852A1D0490159235A93556D39C99805B6D4C4CB779183E08D0A5FC9E8CF007AE36134135162941CE3E582098C605F070048C0AC627E54555740B00C724FFB68839F60C692A48E349CB25AE564E98AD920B71C19D5729AA759F4FBE1E2639C84D71034740C1AEDCAF84BEAD4CB2F75CCB22DBDC9E4D7100B1F8F35E1D9CEBBF8006AFE2E86BBE9AB84A691378699FC79AC749EC9B629A10CD1B14E2008F08038984A270FDEB4E9C003BD006ED89FF1256ACC6D0DE7AFB2029604321D317B89BAE3A28416CBE28CCC6A944F6D3A6504BC5E552BD7784CFE293576BA30D9A8983D84D5ADCA28F1BC852ECFAD6C66B727373B2345321A18B6E2A0F3C08BCE8FCC61A205C0E5F0E9C221B128D0E3C04845EFFB7428178E0C7EAD35A526D38286451D4919C3D411F79B0DA7306D1FD98941C9D92CB4CA227C4FCCE088D76666C76AA29A15D4F6F38B212733C5AC9A91C8C36F869A59A99610FE2FF6293432ED64466029C55C11AEE67365394718180D87DBFAF85F8A045A04D5DDB70EDC54D116E265DFD70E40DF97AE9A4C833183BD66089BCB8AC9471BB774A704ED070EF17D4321E39FD9356867485AE8653C7C9BAA77B43D4355A82896CD710C0F4018A0668BB8F013633BD93A668180CDF0C95F130E42E4D6B04225DD8963464E62EB80D092D717BA9F837B357FF662598A6673DA0267107FD669EF03E01234962435DBE523C9F3E789813DE5AF59BF79994F234DA54C56A65EE9ED5D04B0625CEB29ACEF98BB483F3D8BF5074CAFFAD4635C9D412089C77EC81375F0FC30717C166B386FAC0C81ED285D38AEF2CAD959E39649F31449D65185AF84EC23B34D193EDBB9C572B9818D285109FB8334574CAF14381CF005A07BADE9B2C9C3B69FDD4C57D396FEB7130B092FE98407D3D038F7E51D7FDCF55213F363234306E9FDC4D711B590C684708C5AD86D900E4C7B9951029D6FDE5CE088C8F9D5D9A098C08FB904C07D9AF8F3307AB00370A685296F5F08CAB69947274089FA8D70BD6E0FFF1BDECDC96E1E5094D0B904F71B8814FE4C1FCE6C11D8883045E4FA4F970A892BC130153F846983440121617A5C6DEB390D4DD4FDF6AB786F2A2B9C44658889A515442D085BD012C7F4D5CB6FD17FFDC406F2B523958156190F47EFBE3CBA8D1EA7618CA86DEE0D114AC55EC55F640A05F4CC9DF350238CE031678BB98F155D4418DCAC97D8C5F4352D21D4D347A0A67120953A473040F317E0CA2F8E8B74CD263580EFE8F5BBA540CC402D624C8CB1F46A5458F20EC38A7E36BDCC812651C29851D692B7339F73D563B7BA708DCBF2F8D20970760823E3EE0D87658607CD911E08D818821AE6980868C0B3DCFAD9506903F80F04EAAC193741B61713388668B7165F8B9EB751E583EE78D0BB99E574A2E60A5A8C3C07417F8C28DF1613F09EDDAA3728481BE0C042F54DED6F4B825F8416FA7FF9D088F92939DB9BE5908057B10C5B3610D51CABEED0B22E7EB54D929CD42A2FC006E02B9CBEF3538911B984D9D7FF19D3709F47BEDAAE8B8614BFF07A00B48484DC61A08DCD2112644E9B64D02FAC284E2680215554C66DB3670F98BC86F31CBD89916E8192C18D3D6A25987E3FC5B4CDAE929907C7D449B01F7BE45EB9EBB0B7AB4CB69A9D99BD6E082CF6683403B8413B6885C9E8D2E9DB18B5A9B47CCDACDEBA8A03D4D0C4517DE93C8527898F7F89BDB20BC8929E7057E40CD61AF0623D64384F6CE5E8DD30F0F56F8C4855526B5FE1B88CC6F96EDC897E71638D93FACA00DC6FE30F8B3AC0EC48AE46889E75870A01BE62CDFC6A087208A17D8E3A5F55BC336233ED43DCE46111F7B98BE16DB5DAF2A79D1388387EA3201B9FC6F1A808BD5BB545E9075E1144DE5DD516AA3C086148DF7A5A9D2C2D40DFBED1D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
//
//        byte[] sig = new byte[4000];
//        int[] sigL = new int[1];
//        QTESLA.signingIIISize(sig, 0, sigL, msg, 0, msg.length, sk, QTESLASecureRandomFactory.getFixed(seed, 256));
//System.err.println(Hex.toHexString(Arrays.copyOfRange(sig, 0, sigL[0])));
//        assertTrue(Arrays.equals(sm, Arrays.copyOfRange(sig, 0, sigL[0])));
//        int status = QTESLA.verifyingI(msg, 0, new int[]{msg.length}, sig, 0, sigL[0], pk);
//        assertEquals(0, status);
//    }
}
