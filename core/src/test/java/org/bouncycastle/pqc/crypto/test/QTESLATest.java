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

        QTESLA.signingPIII(signature, 0, signatureLength, messageInput, 0, 59, privateKey, secureRandom);

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

        response = QTESLA.verifyingPIII(messageOutput, 0, messageLength, signature, 0, signatureLength[0], publicKey);

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
    public void testCatIVector0()
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
    public void testCatIVector1()
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

    /**
     * # qTesla-III-size
     *
     * count = 0
     * seed = 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1
     * mlen = 33
     * msg = D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8
     * pk = CBD291D6599F23872E227742166E71AD533DE6B8306805A539274B9A5CAC75298152C19732AB6F8AD5EED79EB918563A2533F89D782E80B1A8C784FEB08745F8AC1D0C1D6DFE80A8329D00AE7B8B956FB668A138480A5D151EA2324B5586B5769F997385EE2DA811D083190D397482EF72244B8E4D0FC41492DBA7C11DD344BC18F21860759E88484A37FBBC9EC4855B07F6EA4EDA62BB318A966479A20007A93C7DDF3E70CD08CEF7A6630F9071C7094FC4287CD754FC695B52152AA7C54D690693A2979C120312A689310B02355136F89656AACD54EC49E62A000F263092A1A0AA535E2C256A9B85657385E4E6055E91A3BA20300D87DDD1805E7C3A6EF094C826C12846E805D201848CEB0E11FC10D0BEDA60E6E2A78D105C8A084B5C38C7B3382A2E150C2FC0CE891E6DD09406978AEC134C7FD8E22CAE881A6DBD0930A8B46B211A2A24C6054639E546B2323BE14112C2F9D9D0AAA91CB1391884738452BDAE052354FBC96ABB54D58F9802BB7EFA6CA9B5CD4F8A3C82B472839DC7E2986FC5280972040C3E68942B9B936A1C855C94C45AB77BBAFBD9E60702477104CE25E665493B9B2A3BD5D7425BBA24F391BC449C6C307B57BAD0DA42D60FED3B0D80BB5A13B100F83AB7F00644A0A0AF339685E139AA8E9F72AAB439EB10386C212C3A6F620E9561EF5E3F596BB165B419B7F9F780A5BB5C44C156215B9CDD80C142124C2C60F33899F11820C82E39142E6AE9B8869D404C54BD6E7406B27E9020EB9B80B93FEA6750DF8709417D93BEC543725CF148C51A76B66D5FCD7C7240911A3E479401D35BCC1512F541E7620178752EAE40C211663907067F4202D7601D41D0FA09CADDAE38B9FF30457FD1D68C50DB8388FE69372955A638C0932A4CD3A65EB77642F2A100DE437A50E3DD40B7597A8B433501C9E0766335D4CA3ADF5618C481A0ED2D2551C0E164B520513766E24956778363170351C0C1A67C11CDF279C76E357639B06F0E3ED38F6EF2905D02EEC228E4B61AE017D974C05966B85FC21D2D7A978279820C94856011A149CC3B34C09E8A9A04FAE7B18A7806E74328EA44C7392339A56AD14BA188002FE6C081F221949294636B04D10F6D58E9AD74735CAA1F4315E899DBFC0384A2A0538E3160BE7954168C2D7F188342655ABE81ED5D3651660E4634F78063DF4B7D7E5EF628476ADA3478E1D9C0FDEBF73593FD79A17E845C2210B8DF2713D38ED3E156F2A72B9157C3CCE089A91C700B7D7C3B62118894159B096AEC01C551C78AD31B467F84CAB7D0AE0A83EAB3452A028C4127CECF3737088A6985FCF1CC4AE22F83BE00610804C8B8C7562645CC5B0A66F56C4C18EC47552BBD3996D787681E0043F451DD2DDA512EC0FE3A10D75D5D893AF17FCC49FDEEF0B120A9F5300908E49FC2FCCE4D88EE2627C6D5AC33EE6BF471F80E72D3B729AC4E4E5E405D86B467B48F6BD2EA45457293BDFB0DC0085D38E265589DB8AFECF259D098873F047144B288EEC338899B0ED949466F335004080AF0E3E6D744A49F6237244CB94F0A0837C135AFC0424E9FDC87C6CF372905CBF3E3A1CE7922FE1B53E5B5CE8A95E47FE72439A1ABAFE9250EC5B89E54C672C8BBB82F4D46AAAC88AF1BD1D14F48D3753D23CAE2485554C9373706DEADE5E70F8195392069BC4FE1D3B6D471693E7A0D49EBD2E65260B6DA26C95158C4ABB8EB7DB2BB1347810376BCDB1DF92E8B30C28BDF7AE7E28498F55AA61DDEE32A726F03045A81410865C87AB82AEF71F03324E63B2C0598FD40463006E3D407272C4631C9B019F211D69214CCAABD4B08D93A7B68A1884577D413D0A61CEDE21E0B5923211413CC599B3D0FC9B055D495139B0061E36D6A665CADD0BAC630D4B6C64C6F4B12BE8F8B986FB84B413C173C2A3C0B07691E8A9EAA993600E5BF2382B314E20F147A63AFB88437378AD627A4DB7F45C97D6966361469905A0039FF2400B094171DD5ABDBBA80CC976BD13C78F50D048145C4A330B5C8DFD7CB6B34D9446B35709A32D9372F2EAB05745C191DE6CB51FF02E222F7FAC560CF384566E42414674D7C91A2DF47F2DFA3DCAAB1668593CAF41893B7D81C5F5CD12BABD744C4BD061675A59238283CFDF0B94BFA44214265227527447577042901F5E11108529044D108AC9100EAD8349FAB49F53DA7CAEAF166D66176D175DB7416FA1BE7632DF72E54C04829424F01CB3733E6D3F5556200FE4D3A252C744EDC3706A5072E57CE2B8BA28E25EC7DCEEB7A9A26B06BEF4F76FDE56B24F2D5E858229924E0D2CE1F1D6AD912C14EC018AA4552B164BC98736E5280204E5E13789CD5229AA5D69D95A4930B4484E40AF229518346682C73BE1D2DDDFE9FFE53A31FC9C65067008F3AC155705E32338AED22FBB2425C462AAB3D43C70BE2E996CC680B8059222BB782836BC4B94A2CE68D42676D522AC2D44804C6C334672F3A49F6D257E608EBA187B230FBBE6014A2D4704007FC731E993295012303A3BA755FBA7872DB349E0C0E4B1FABD0007B90933CE48A71D647B3EC93A53FC5EBA17C994B21E7B2D2B8C60A6324B81361482B3223A031DEF2C0B0286052902F6317F19FCFE5C6377498323624290DF2F21A0C333E37963A4ECDD68BB1B4A0DCE55014E9B52B60A8C14FBC780C6625DEEF87A428A2149C286BFCBBCD2EBD6A75288ABBB9E4D3973332E9332C93F5886ABE65603216B0F92B07662E72724FC0AF89582BA1106F79B7EAA9596638AA5FF0B9162EFD5BC6626AF45C459661A3AF444927B40A7368E5CB069A3D136713479524A4A9CB4BB6D9D4A3B0A64654A7D105C8F6C92ABC0BD31EB4A2AB8B07F0514450F69A42A79B043872DF17B00A5C61958E228857D331BDC06E4074E12E2BB028174946AECBC237A0B113123FF5784BDE37337A0B20AAD79967D0A99A37333EE0B0D09F717691265F6B66441E2B788C1E55405D4251BDABABE05220223D38AA034FBD9DD5CA8052BC0CD1CFC5671BC9D977C8B4BB90015CC07C34015C5C4DD2213982054855C260663C2684B0372289358F0891416713A70AF6843AAAE2F6F7BC5F124A5234BC278B81E345736D66EA50674AA341715469FBE4D24D7E15B9141143C95F57445036E55847B13F431DA5282C43520F992942FF19E702277A16B6624ADBE35319ECA74CB922BA892FF0FE53740AABA58FB37BF8F872892D831004073DF749B1B15E10F3518F3D55B0C024BB8DA18C304F6A8456811911DA16D45F5D6BB69EE3EA90BB0887289918046F3B09BFBA14C2C201932DE6C3D52A515005B7E8077C42BF77575315421711DF028577834161A699B3C8D8C6C200C70F3525A6D4D3DBCD0EA2F40272D2D8F1F894990848E4E66BF50D1404C4CA89FA27AB9FB3478D6A430D055E1B2E51173EE194DCCD90CC1E678A5CC6887479C9106C4A63524C354CCEBDF0AC405A4ACE8F0F26EBF2C821BF85C3762E84165F8410A14644FBB7CAAE15C67EF7FA273C6C7566341C0C48ACAEF88E043C76A77710D0ACB4FBC6EC21C0B4707461CBBCBD06CDD238380C7CA686BCF7E9BD28B942E7BE4A07494638506F873A184C5B8C25793F20AD846CCEF0D4F733BEA00A700EDAA0B4AA23F2D45E10308400BADC0F867E0917C7150D2E45A5C6C4688CE711C74B2DCB788CB48CD76317662F5F9E4782576B4368B525D7B0806C79FF31B0E577B52B3545A480E202E93F2F6174C378CD896C3FD8C2735D76A407CD07D99AE4C7F276436C69024A5914355386B42F94F386B8390179EA43D2AF965A69B1257805AEEBCE931789528E38EFDDE2944459E72208FE80BE4FE4E89586A50D983A24A0980C87034DAC00777C546B013F89589A3A10159249A190E0D0B043AA97FDE068EB92120BF139D4CAB62F5FD132C749D66D55A00A1267B05058DC9BE18B17D8276E00F491FE43D393D5A241F6D48C3C1A56F83C5465902E347C4DB7DC78D8A6F383A39F756B88D2447FB08430967710957D113F344A1C494CF6A9C6477B78578E80D10FD4350FCD94A0E6550BD48D014A26E587E4A128E369702EA8CD35AE7AA87E728FE9B82755F9D41BF2889690B4854FB0C9129D61072CF74B9ED3670B4EB309B51BFCFE813AADA619334EBFAE570E4A300B00FB52106F1EEA96F4CC6ED308264AB60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD
     * sk = 17000000020000000B00FDFF0600FAFF05000D0007000200140010000700F6FF0A000300F6FF0800040009000500060002000600FAFF0C00F9FF0400FBFF0D000300F9FFF4FF01000900F6FF06000C00FDFF0300FCFFF4FF18001400FDFF0600FEFF0D00F9FF0900F8FFFFFFFFFF0300FCFFFEFF0A00F9FF0200FEFFF9FF02000100FAFF010001000A00010000000500FFFF0400F6FF04000600FFFF0000F7FFF3FFF9FFF8FFFFFF010011000900F1FFFDFF0600F7FFFCFF0900090005000300FDFFFEFF06000300FDFF04000100FAFF0400F9FFF5FF03000000080006000200F5FF1000FFFF01000500020008000C0001000500060009000800FCFF00000100FDFF01000000FEFF0D00F8FFFDFF0000F8FF0A00070017000B0001000900F3FFFAFF0E00FFFFFAFF02000500F7FFF9FF00000300FEFFFFFF0300FFFFFBFFF6FF0900F2FF050002000C000400F7FFF5FF0300FAFF1200F9FF0900020009000600FEFF0300020005000000F8FFF0FFEEFF0A00FCFF01000100FCFF06000700F8FF0C00F7FFFEFF0100FEFF0500F9FFFBFF090005000A00F3FFF7FFF8FF0C000000FDFF0B00FFFF0400F9FFFBFF0000FCFF0400FBFFFFFFF7FF0500170003001000FEFFF8FF0B000900FFFFFBFFF7FFFBFFF9FF03000C00000001000D00FBFF0100FEFF0200F6FF10000600FFFFF4FFFAFF0100F3FFF7FFFFFFFCFF08000B00020005000C00030009000A00F8FFF9FF0C00010004000300F8FFF3FF090009000000E7FF1100FFFFFFFFFFFFF9FFF9FF0B00F6FFFFFFF8FF00000700F2FF0000F7FF02000400F8FFF3FFF8FF090008000D00F7FFF6FF01000400110016000000F3FFFBFF0300FDFFEEFF0400040001000500FDFFFCFF0500F8FF0300F9FF0000FEFF0000F4FFF7FF1000FEFF050003000500FEFFFDFF01000900000007000D000000000005000D00FBFFFBFFF9FF0500010003000100FBFF0900FFFFF9FF0E000A00F4FFFBFF07000200F6FFFEFF010009000300040001000800FBFFFCFF05000400F9FFFFFF000005000600EAFFFDFF0100FCFF09000100FFFF010003000000F8FF0D0004000C00FCFFF9FFFFFF04000900F7FFF6FFF6FF0F000200FDFF0200F5FF03000E001100FFFFFAFFFEFF0A000A00F3FF0200FEFF0900FBFF0700030009000A000900FFFFF3FFF7FFFFFFF5FFF4FF1200FEFFF7FFF5FFFDFF0200F7FF02000800FCFF09000900F4FFFEFF050008000D0004000A00F7FF0900FFFFF6FF02000400090005000200F2FF0C00FDFF09000300EEFF0000F9FFF4FF01000E00FDFF0D000B000500FCFFFFFFF7FF0D00F9FFFEFFF0FF15000900FBFFFFFF090009000000F1FFF9FF0400FFFF0F000800FFFF0900FAFF00000C00F9FFF7FF04000600FDFF0A000200F6FF0600FCFFFDFFFBFF0C00030002000E000000F6FF0D001300FCFFFDFFFCFF040007000900F9FFFEFFFFFF0200F8FFF8FF060004000900040005000400F6FFFEFF0200F0FFFDFF0700FFFFF4FF06000D000900FDFFFDFFFCFFF6FF0100E8FFFCFFFFFFF9FFF5FF0000FEFFFDFFFCFF010002000B0008000C000800FEFFFAFFF8FF0600F4FFF7FFF6FF0300F9FFF8FF11000600FDFFFDFFFCFFFCFFFBFF11000800F9FF0300020000000800FDFF1700F7FF0B00FCFF0000F3FFFFFFFFFF0600F8FF00000600FEFFFBFFFCFFFCFFFAFFF7FFFEFF0B000400F3FFFEFF0D000800090003000A000700080003000D00F8FFFCFFFFFFF4FF0A000700F7FFF9FF0400FDFFFDFF0500FFFFFFFFFDFF0600FCFF0600030004000700060000000B000400F5FF1000F8FF0000FCFFFDFFFEFF03000000FFFFF6FF0500FEFF0A000000FBFFFCFFF8FFFCFF0600FBFF0500F7FFF7FFF5FFFCFFF9FF020003000800FCFF0F00FBFF09000200F4FF0B0009000600F3FF09000600F8FF02000600F8FF0300FFFFF9FFFDFFF5FFFCFF0100F0FFF7FF080002000B0005000700ECFFFCFF0400F9FF0500FCFF0500FBFF0300F5FF0A00F4FF070002000700FBFF0200FBFFEBFF0900FDFF0700F5FF0100F6FFF7FF0000F5FF0900FBFFFDFF0600FFFF0200060005000D00F6FF090005000500FFFFFFFFFFFF0700F6FF030009000B00F4FF0E00F9FFF8FFFBFF0500F9FF0200FEFF02000700FCFFFAFF0800F9FFFDFF02000300FFFF0700F6FF06000200F7FFF8FF070006000B00FAFF0500F0FF0C000000FAFF0400F6FF0000FBFFFBFF0C000500F7FFF7FFFFFF0000F1FFF9FFF7FFFBFF0100F6FF11000000FCFFF9FFF9FFF7FF0100F4FF0400F7FF0D00F9FFFFFF01000400FFFFFAFF09000100F9FFF6FF000005000100020004000100F7FF0C000400F7FFFDFFFCFF0F000D000C00040001000600F9FFFBFF12000400F8FFF9FF06000B000700FFFF0B00FDFFFFFFF3FF02000100FEFF0000010007000000FEFF00000000F7FF0400FCFFFEFF0D000F00FDFFF2FF00000300FDFF070005000300FDFF10000900060005000000F3FFF4FFFAFFFBFFFFFFFAFFFDFFFBFFFBFF0300FCFFF9FF0600F7FF0300FAFF010002000C000400F7FFF8FF07000600FFFFF8FF0A00F7FFFEFFF8FFF8FF0400F9FF0200020002000900FEFF0200FEFF07000A000500FCFFFCFFFFFF0300FCFFFDFF0900FDFFF6FFFFFFFCFF03000300100006000B00FBFFEBFFEDFF060003000800FFFF0F000100FDFFFEFFFDFFFBFF0D000400F5FF090000000D00F3FF0300F6FFFBFFEBFF030008000100F7FF0600F6FF0400FBFF05000C00F0FF0200F7FFFBFF0100FCFFFCFF0D00F9FFF6FFF8FFF8FF050003000200FDFF08000C000F0007000000FDFF0300F8FF0A00FEFF09000800F7FF0500FCFF08000300F7FF060004000D00F9FF1600EAFF07000B00F5FF0B001000FEFF0000F7FF03000A00F6FF0A00FDFF0F00F6FFFAFF0E000100000008000B000F00FDFF06000000FBFFF4FF090009000B00F5FFFFFF0100F3FF09000D000C000B00F5FF140000000000FCFF0000FCFF0000FFFF0D000700FCFFFAFFF9FF0B00FDFFFDFFFCFFFDFFFCFFFEFFFCFFFEFFEFFF09000300FCFF0700F8FF02000500F9FF0200F7FF090002000800F4FFF7FFFEFFF9FF02000200FDFF0000030000000400F3FFFAFFF9FF0300FBFFF8FF0100030006000E00FFFFF9FFF0FFFFFF0100F5FF1100EDFF090001000500F9FF0100FFFF0D0009000300080002000200F7FFFFFF0900FBFFF3FF0900FAFF0C00E9FF0500F5FFFBFFF6FF0600060001000F00FCFF000005000E00F6FF07000400020000001000FFFF0200F4FF0500120002000A00040001000D00020010000300FFFF0A00F0FF0900EBFFFDFFFBFF0600FDFFF9FFFAFF08000B00FFFF1000F9FF0900FCFFFAFFFFFFFEFF03000100030000000100EFFF0D00F4FFFFFF00000000F5FF0E00FEFFFBFF0800EBFF000000000E000800FBFFFDFF0F00F4FF0700F2FFF6FFF3FF0000050001000500F9FFFBFF0900FDFF030012000200F5FFFFFFEFFFFEFF0000F7FF090008000A00F7FFFDFF0600FEFF0D00F6FFECFF01000C00FDFF06000700F7FF0700FAFF0800EFFF0800FBFF00000700FFFF0800010001000200FAFF0C0006000100FCFF0400F2FF030002000200F4FF0E00FEFFFCFFF6FF0A00F7FF09000100F4FF0600FEFF06000500F9FFF8FFF6FF02000200090004000600FAFFF8FF02000800FDFFF8FFF9FFFCFFFFFFFDFF0D00F4FF0A000400FFFFF6FFFDFF040000000100F8FF040001000500010001000000FEFF0D000000FDFFFBFF06000600FAFF0400F6FF0500F9FFF8FF1000040006000700FDFF080005000000FAFF0700F4FF0000FFFFFBFFFEFFF1FFF6FFFDFF02000900F8FF0200FFFF0400FFFFF9FFFCFFF9FFFFFF0900FBFFF8FF0000F8FF0900F9FFFCFF0900F9FFF7FFF3FF0F00F0FF0000FFFF05001200F7FF020008000E00F6FF0900060002000300FDFF05000500FDFF0A00F7FFF9FF050002000E00FFFF0700FFFF0C000600FAFFFDFFFFFF0300FFFFFCFF0100F3FF02000400FEFFF7FF010000000900FFFF0A00FDFFFCFF0B00110004000200FFFF06000200FCFF01000600F5FF06000100FDFFF7FF01000A0006001000FFFFFFFFFFFFFFFFF8FFF6FFF7FFFEFFFCFFF6FFFBFF0200F8FF0500F6FF01000500FEFFFFFF02000200FFFF0900EDFF04000800FCFF0300EEFFFAFF0000F4FF0600FCFFF8FFFDFF03000100FBFFFAFF0800F8FFFDFF00000700FCFFFFFFF7FF06000F0010000A00FCFFF3FF0100FEFFF9FF0A00FAFF0C00EFFF0100E8FFEEFFF8FFF6FF040001000900FAFF0300FEFF06000100F4FF0C000200F9FF0400FEFFF8FF0400FEFF070007000000FBFF1100FAFFFDFFF9FFFAFF1200030009000200FAFFEFFF03000700FAFF0200FCFFFEFFF4FF01000D000400FCFF0400FAFFFCFFF5FFF7FFF8FF020009000300070007000E000300F8FF0800F9FF1000F5FFFBFFF1FF0400FCFFF7FF0400FBFF0A001200F8FF03000A000100F4FF0700FBFFF5FF0500FFFFF4FF01000500FAFFFCFF0700040006000500FBFF00000600F7FF03000F000100FEFF110006000000FBFF0200FDFF0800FFFFF7FF0B000700090005000A00F9FFFCFFFDFF0700FCFF080007000900FEFF0600F5FFFDFFF6FFFDFFFBFFFFFF0100FAFF0E0006000700FCFF0200080006000100FFFF05000600F7FF010008000800030000000600FCFFF8FF08000E0002000000F3FFF0FF0900FFFF0300EEFFFBFF0300EFFFFAFF0200F1FF0900FFFFF8FF0C00FAFF1000FDFFFAFF0E00F8FF010001000A00EFFF01000300FAFF0200F6FFFEFF0300010007000400FCFFF7FFFEFFFFFF0700FCFF09000100FEFFFFFFFDFFFAFFFDFFFCFFF1FF0200F0FF0200080005000600090011000800FAFF0A000900FBFF01001500FDFF0000FEFF0400F7FFF6FFFDFFF5FFFDFF09000400F7FF0200FBFF0D00F7FFFEFFFEFF0100F8FFFAFFFBFF00000300FBFFFBFF0100F9FF1400F5FF0700FDFFFDFFFAFF0100F9FFFCFF0900000008000700F6FFF8FFF5FFFDFFF0FFFEFF090005000A000A00FCFFF9FFFAFF030001000300F3FFFDFFF9FF0700FEFFFAFFF7FF0500020000000E00F6FF06000500FCFFFDFFFEFF09000500FDFFF6FF000002000100FEFF0D00FAFFF7FF1200F9FFFBFF000004000400F0FFF5FF090004000C000400F9FF0100FBFFF7FF0B00F7FFFFFFFDFF02000300F8FFFDFFF7FF03000100F3FFECFFEFFFF7FF00000500FCFF04000900FEFF00000700FFFFFAFF0F000000FEFF0800FDFF03000A000100040003000C0001000600F8FFF9FFF5FFFAFF09000100F8FFF1FFF1FF0300000000000C000E00ECFF0800FFFF02000A000600050001000A0001000D00FDFFF6FF0000F7FFFBFF0200F7FFF8FF07000000000003000900F7FFFCFF07000200FAFFF9FF0C00FDFFF8FF00000900F9FF010006000A000700FEFFFDFFF1FF0200F3FF0600F2FF090000000C00FDFFF2FFFCFFFCFFFBFFF0FF0700F7FFF4FF0700F7FF0800FDFF0000F8FF0300F8FF0900F9FF010004000800FCFFFFFFF8FF0700FDFF0000FCFF0C00FDFFEEFFF9FF07000600FFFFF7FFFFFF0300F5FF0700F6FF03000800FEFFFFFF04000300F9FF02000400F6FF0900F2FFFDFFFDFF05000300FBFF050009000800020007000C000700F9FFF8FFEFFF05000D0001000700FBFF0000FBFF0300FAFF0700FBFFEFFF00001100F4FF0F00E5FFFFFF0400FEFF00000B000100FDFFFFFF02000600FBFFFDFFFEFFFDFF08000200F7FFFCFF030007000200FBFFB60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD394D1695059DFF40AE256C5D5EDABFB69F5F40F37A588F50532CA408A8168AB1
     * smlen = 2753
     * sm = 13743CD9D613B998A4763D9A4F2618BF7B13543FD344B69EFD0C5AE439B3E5B8DFED144FE06F0983452AE52019BF2EC1F7264361E82591FDB0C05E5C0B32A22420B421805810F89DBF962E3887597DD2FEA01C4596033822A99BACA1343A008053FFFA5DB979E493E71C8B9F2BD2E46D237F0D92769FAA0A3B23B938488D2B40BBFFB3C8CD35AA1C79ACF28303F357A9AB367330A1CEA217701A0BCE89E015C64D34CD22F11A42A8D36B3F45FD74E0055B2B162E2C2DF505F609BC599CFCB2BA3921AAC37E155035140126FB3DDFD88A9D77F6B33D370B653813ABA5857C1E3646A6EB8C81C094EB59CD86F92F9E27B9C53010D52755F268BE672AC153E8538967F620A95DC2B3B6A084753A2A95800CEF18115BA816008C9469B88F16E8ECF9EE85C37B7F7C63EF98C8464B35518A0F4317C39AA101FC85943E14A196051BAFF5214BC1ECEED3F520B95A38DE945CB2FCD358CBCEE6A7F848112863BF0AFDD699E84AB8AD62057A354B0EC395851B4352B99D466503DF795C8D0ACCE3462719779F9C5AFC330A8735B9B4E18D6A2CEF6C640170028D4DCA4F3B0DF09B210FCDC469282B5593F9D40ECD9D52D13352811EBEE1B46C277A73089262827E5CEE82408B744A8257A44F5F7B16C69FD172EA62F3D55D3BF30B96C9B4DC5B86CC6CB1F3F296E78523923C1D7599E459636703CF8030B60513059A5AFD8B033736EFDEC506DC8F40EC20A4213F50067528AAABDE320BDA6E313D224ED1BBF868115759773DD5F107A3D3479823AFDF2E289AB20585E3BDD93FBDE1694C82567EBC65373A688178BB8D540AAD977EC64ECB7277B720760E571D0B837CE33B0E629832CD84707A7E4CB6111280DC16FCD98287DD5B089048520206B865EF1F9095528E6C7ED11DFBBC582946D3C50B529A4A0FE8E389FCCB09CFA04849E034C254F3116F05F7C75910017E6E01112BB6A02D288A8893AE506421E9F02F374A75015416956A3C7ACE5616A162AABFEF5F1B00D4C82858F7A2E48BBFE131AF4A327C09EE19402FDFEDA5BCDE266EB3EAA375A514899907D0DDFBD7FD4A2EA4CBCACD887311DA98653CBFE461BE9A491120A39384FF4376D0152A29696B690ADED65A698E0546B32B1494B3B7470FFBA1E052702ADB1B9ADBACB594DFB5106C5567E3FAE84C131FCEC5395E9C527304ECE8C83BAAE38DEBCC9E1732A2B79D2693481D14803BEC157D714EDDC6FC5F0697073084D36D6110E793C8C846531B14CCCBFEB7D3080E83D70941537606227E2F860084C8722EFED4E829A57B2629C53ACE8C1C77603B15532090E75FEEF57020CC0E6F1FABC426088C0C683062EBF6E588B2F44D0E37C623F12128FB940CA239F8CCD771D3DC4A4BEE056A8BCBB9E412BDC8CAE201DD8E18D74B598771367202D42D93C167E554A04E25B882EB79F6DC0B91826700ACFC4803EBCC105B40DA41875A2174F9FAEC30D64E3BAF0D3C4C60E33470968264D49900F334DCDD0D1B9F85822A063A68F027D9E6BFAE2E68C19D73EADAF48EC457C1D857E05F9200A296E4915C292EFBEBC4A9754B291DE2A7A7411A0FE3692FEF691ED703247002CAA7550730357A031ACA61688911DC6A546AED3F63B4BAA4DFD31E6DB3894F73029174F87495255FDD5A708FB213FD855FCDB523881DF45B2754C329367D3741226100F57A5F1E23A2DECBFF6BD1B79B9E1C0C7BA11157D9CF9173A13D9DB71D539432B39F78183F267E851A6CE314212BB2F448527DF68B822FFE6ECE7377070750EE0E8F7C7A84553B293C1B1073E6573085569DCACF3D82167B58D12915E75400F3A2D72A399C1354926BE462DAB3CF892502F4DF62628A58E77272E2F888555946B2DF445E54EE15C7703F7F632DB235C9D443F3C16012881824435FD5ECC602665912FFA65D65ED92D202567852A1D0490159235A93556D39C99805B6D4C4CB779183E08D0A5FC9E8CF007AE36134135162941CE3E582098C605F070048C0AC627E54555740B00C724FFB68839F60C692A48E349CB25AE564E98AD920B71C19D5729AA759F4FBE1E2639C84D71034740C1AEDCAF84BEAD4CB2F75CCB22DBDC9E4D7100B1F8F35E1D9CEBBF8006AFE2E86BBE9AB84A691378699FC79AC749EC9B629A10CD1B14E2008F08038984A270FDEB4E9C003BD006ED89FF1256ACC6D0DE7AFB2029604321D317B89BAE3A28416CBE28CCC6A944F6D3A6504BC5E552BD7784CFE293576BA30D9A8983D84D5ADCA28F1BC852ECFAD6C66B727373B2345321A18B6E2A0F3C08BCE8FCC61A205C0E5F0E9C221B128D0E3C04845EFFB7428178E0C7EAD35A526D38286451D4919C3D411F79B0DA7306D1FD98941C9D92CB4CA227C4FCCE088D76666C76AA29A15D4F6F38B212733C5AC9A91C8C36F869A59A99610FE2FF6293432ED64466029C55C11AEE67365394718180D87DBFAF85F8A045A04D5DDB70EDC54D116E265DFD70E40DF97AE9A4C833183BD66089BCB8AC9471BB774A704ED070EF17D4321E39FD9356867485AE8653C7C9BAA77B43D4355A82896CD710C0F4018A0668BB8F013633BD93A668180CDF0C95F130E42E4D6B04225DD8963464E62EB80D092D717BA9F837B357FF662598A6673DA0267107FD669EF03E01234962435DBE523C9F3E789813DE5AF59BF79994F234DA54C56A65EE9ED5D04B0625CEB29ACEF98BB483F3D8BF5074CAFFAD4635C9D412089C77EC81375F0FC30717C166B386FAC0C81ED285D38AEF2CAD959E39649F31449D65185AF84EC23B34D193EDBB9C572B9818D285109FB8334574CAF14381CF005A07BADE9B2C9C3B69FDD4C57D396FEB7130B092FE98407D3D038F7E51D7FDCF55213F363234306E9FDC4D711B590C684708C5AD86D900E4C7B9951029D6FDE5CE088C8F9D5D9A098C08FB904C07D9AF8F3307AB00370A685296F5F08CAB69947274089FA8D70BD6E0FFF1BDECDC96E1E5094D0B904F71B8814FE4C1FCE6C11D8883045E4FA4F970A892BC130153F846983440121617A5C6DEB390D4DD4FDF6AB786F2A2B9C44658889A515442D085BD012C7F4D5CB6FD17FFDC406F2B523958156190F47EFBE3CBA8D1EA7618CA86DEE0D114AC55EC55F640A05F4CC9DF350238CE031678BB98F155D4418DCAC97D8C5F4352D21D4D347A0A67120953A473040F317E0CA2F8E8B74CD263580EFE8F5BBA540CC402D624C8CB1F46A5458F20EC38A7E36BDCC812651C29851D692B7339F73D563B7BA708DCBF2F8D20970760823E3EE0D87658607CD911E08D818821AE6980868C0B3DCFAD9506903F80F04EAAC193741B61713388668B7165F8B9EB751E583EE78D0BB99E574A2E60A5A8C3C07417F8C28DF1613F09EDDAA3728481BE0C042F54DED6F4B825F8416FA7FF9D088F92939DB9BE5908057B10C5B3610D51CABEED0B22E7EB54D929CD42A2FC006E02B9CBEF3538911B984D9D7FF19D3709F47BEDAAE8B8614BFF07A00B48484DC61A08DCD2112644E9B64D02FAC284E2680215554C66DB3670F98BC86F31CBD89916E8192C18D3D6A25987E3FC5B4CDAE929907C7D449B01F7BE45EB9EBB0B7AB4CB69A9D99BD6E082CF6683403B8413B6885C9E8D2E9DB18B5A9B47CCDACDEBA8A03D4D0C4517DE93C8527898F7F89BDB20BC8929E7057E40CD61AF0623D64384F6CE5E8DD30F0F56F8C4855526B5FE1B88CC6F96EDC897E71638D93FACA00DC6FE30F8B3AC0EC48AE46889E75870A01BE62CDFC6A087208A17D8E3A5F55BC336233ED43DCE46111F7B98BE16DB5DAF2A79D1388387EA3201B9FC6F1A808BD5BB545E9075E1144DE5DD516AA3C086148DF7A5A9D2C2D40DFBED1D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8
     */
    public void testCatIIISizeVector0()
    {
        byte[] seed = Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1");
        int mlen = 33;
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] pk = Hex.decode("CBD291D6599F23872E227742166E71AD533DE6B8306805A539274B9A5CAC75298152C19732AB6F8AD5EED79EB918563A2533F89D782E80B1A8C784FEB08745F8AC1D0C1D6DFE80A8329D00AE7B8B956FB668A138480A5D151EA2324B5586B5769F997385EE2DA811D083190D397482EF72244B8E4D0FC41492DBA7C11DD344BC18F21860759E88484A37FBBC9EC4855B07F6EA4EDA62BB318A966479A20007A93C7DDF3E70CD08CEF7A6630F9071C7094FC4287CD754FC695B52152AA7C54D690693A2979C120312A689310B02355136F89656AACD54EC49E62A000F263092A1A0AA535E2C256A9B85657385E4E6055E91A3BA20300D87DDD1805E7C3A6EF094C826C12846E805D201848CEB0E11FC10D0BEDA60E6E2A78D105C8A084B5C38C7B3382A2E150C2FC0CE891E6DD09406978AEC134C7FD8E22CAE881A6DBD0930A8B46B211A2A24C6054639E546B2323BE14112C2F9D9D0AAA91CB1391884738452BDAE052354FBC96ABB54D58F9802BB7EFA6CA9B5CD4F8A3C82B472839DC7E2986FC5280972040C3E68942B9B936A1C855C94C45AB77BBAFBD9E60702477104CE25E665493B9B2A3BD5D7425BBA24F391BC449C6C307B57BAD0DA42D60FED3B0D80BB5A13B100F83AB7F00644A0A0AF339685E139AA8E9F72AAB439EB10386C212C3A6F620E9561EF5E3F596BB165B419B7F9F780A5BB5C44C156215B9CDD80C142124C2C60F33899F11820C82E39142E6AE9B8869D404C54BD6E7406B27E9020EB9B80B93FEA6750DF8709417D93BEC543725CF148C51A76B66D5FCD7C7240911A3E479401D35BCC1512F541E7620178752EAE40C211663907067F4202D7601D41D0FA09CADDAE38B9FF30457FD1D68C50DB8388FE69372955A638C0932A4CD3A65EB77642F2A100DE437A50E3DD40B7597A8B433501C9E0766335D4CA3ADF5618C481A0ED2D2551C0E164B520513766E24956778363170351C0C1A67C11CDF279C76E357639B06F0E3ED38F6EF2905D02EEC228E4B61AE017D974C05966B85FC21D2D7A978279820C94856011A149CC3B34C09E8A9A04FAE7B18A7806E74328EA44C7392339A56AD14BA188002FE6C081F221949294636B04D10F6D58E9AD74735CAA1F4315E899DBFC0384A2A0538E3160BE7954168C2D7F188342655ABE81ED5D3651660E4634F78063DF4B7D7E5EF628476ADA3478E1D9C0FDEBF73593FD79A17E845C2210B8DF2713D38ED3E156F2A72B9157C3CCE089A91C700B7D7C3B62118894159B096AEC01C551C78AD31B467F84CAB7D0AE0A83EAB3452A028C4127CECF3737088A6985FCF1CC4AE22F83BE00610804C8B8C7562645CC5B0A66F56C4C18EC47552BBD3996D787681E0043F451DD2DDA512EC0FE3A10D75D5D893AF17FCC49FDEEF0B120A9F5300908E49FC2FCCE4D88EE2627C6D5AC33EE6BF471F80E72D3B729AC4E4E5E405D86B467B48F6BD2EA45457293BDFB0DC0085D38E265589DB8AFECF259D098873F047144B288EEC338899B0ED949466F335004080AF0E3E6D744A49F6237244CB94F0A0837C135AFC0424E9FDC87C6CF372905CBF3E3A1CE7922FE1B53E5B5CE8A95E47FE72439A1ABAFE9250EC5B89E54C672C8BBB82F4D46AAAC88AF1BD1D14F48D3753D23CAE2485554C9373706DEADE5E70F8195392069BC4FE1D3B6D471693E7A0D49EBD2E65260B6DA26C95158C4ABB8EB7DB2BB1347810376BCDB1DF92E8B30C28BDF7AE7E28498F55AA61DDEE32A726F03045A81410865C87AB82AEF71F03324E63B2C0598FD40463006E3D407272C4631C9B019F211D69214CCAABD4B08D93A7B68A1884577D413D0A61CEDE21E0B5923211413CC599B3D0FC9B055D495139B0061E36D6A665CADD0BAC630D4B6C64C6F4B12BE8F8B986FB84B413C173C2A3C0B07691E8A9EAA993600E5BF2382B314E20F147A63AFB88437378AD627A4DB7F45C97D6966361469905A0039FF2400B094171DD5ABDBBA80CC976BD13C78F50D048145C4A330B5C8DFD7CB6B34D9446B35709A32D9372F2EAB05745C191DE6CB51FF02E222F7FAC560CF384566E42414674D7C91A2DF47F2DFA3DCAAB1668593CAF41893B7D81C5F5CD12BABD744C4BD061675A59238283CFDF0B94BFA44214265227527447577042901F5E11108529044D108AC9100EAD8349FAB49F53DA7CAEAF166D66176D175DB7416FA1BE7632DF72E54C04829424F01CB3733E6D3F5556200FE4D3A252C744EDC3706A5072E57CE2B8BA28E25EC7DCEEB7A9A26B06BEF4F76FDE56B24F2D5E858229924E0D2CE1F1D6AD912C14EC018AA4552B164BC98736E5280204E5E13789CD5229AA5D69D95A4930B4484E40AF229518346682C73BE1D2DDDFE9FFE53A31FC9C65067008F3AC155705E32338AED22FBB2425C462AAB3D43C70BE2E996CC680B8059222BB782836BC4B94A2CE68D42676D522AC2D44804C6C334672F3A49F6D257E608EBA187B230FBBE6014A2D4704007FC731E993295012303A3BA755FBA7872DB349E0C0E4B1FABD0007B90933CE48A71D647B3EC93A53FC5EBA17C994B21E7B2D2B8C60A6324B81361482B3223A031DEF2C0B0286052902F6317F19FCFE5C6377498323624290DF2F21A0C333E37963A4ECDD68BB1B4A0DCE55014E9B52B60A8C14FBC780C6625DEEF87A428A2149C286BFCBBCD2EBD6A75288ABBB9E4D3973332E9332C93F5886ABE65603216B0F92B07662E72724FC0AF89582BA1106F79B7EAA9596638AA5FF0B9162EFD5BC6626AF45C459661A3AF444927B40A7368E5CB069A3D136713479524A4A9CB4BB6D9D4A3B0A64654A7D105C8F6C92ABC0BD31EB4A2AB8B07F0514450F69A42A79B043872DF17B00A5C61958E228857D331BDC06E4074E12E2BB028174946AECBC237A0B113123FF5784BDE37337A0B20AAD79967D0A99A37333EE0B0D09F717691265F6B66441E2B788C1E55405D4251BDABABE05220223D38AA034FBD9DD5CA8052BC0CD1CFC5671BC9D977C8B4BB90015CC07C34015C5C4DD2213982054855C260663C2684B0372289358F0891416713A70AF6843AAAE2F6F7BC5F124A5234BC278B81E345736D66EA50674AA341715469FBE4D24D7E15B9141143C95F57445036E55847B13F431DA5282C43520F992942FF19E702277A16B6624ADBE35319ECA74CB922BA892FF0FE53740AABA58FB37BF8F872892D831004073DF749B1B15E10F3518F3D55B0C024BB8DA18C304F6A8456811911DA16D45F5D6BB69EE3EA90BB0887289918046F3B09BFBA14C2C201932DE6C3D52A515005B7E8077C42BF77575315421711DF028577834161A699B3C8D8C6C200C70F3525A6D4D3DBCD0EA2F40272D2D8F1F894990848E4E66BF50D1404C4CA89FA27AB9FB3478D6A430D055E1B2E51173EE194DCCD90CC1E678A5CC6887479C9106C4A63524C354CCEBDF0AC405A4ACE8F0F26EBF2C821BF85C3762E84165F8410A14644FBB7CAAE15C67EF7FA273C6C7566341C0C48ACAEF88E043C76A77710D0ACB4FBC6EC21C0B4707461CBBCBD06CDD238380C7CA686BCF7E9BD28B942E7BE4A07494638506F873A184C5B8C25793F20AD846CCEF0D4F733BEA00A700EDAA0B4AA23F2D45E10308400BADC0F867E0917C7150D2E45A5C6C4688CE711C74B2DCB788CB48CD76317662F5F9E4782576B4368B525D7B0806C79FF31B0E577B52B3545A480E202E93F2F6174C378CD896C3FD8C2735D76A407CD07D99AE4C7F276436C69024A5914355386B42F94F386B8390179EA43D2AF965A69B1257805AEEBCE931789528E38EFDDE2944459E72208FE80BE4FE4E89586A50D983A24A0980C87034DAC00777C546B013F89589A3A10159249A190E0D0B043AA97FDE068EB92120BF139D4CAB62F5FD132C749D66D55A00A1267B05058DC9BE18B17D8276E00F491FE43D393D5A241F6D48C3C1A56F83C5465902E347C4DB7DC78D8A6F383A39F756B88D2447FB08430967710957D113F344A1C494CF6A9C6477B78578E80D10FD4350FCD94A0E6550BD48D014A26E587E4A128E369702EA8CD35AE7AA87E728FE9B82755F9D41BF2889690B4854FB0C9129D61072CF74B9ED3670B4EB309B51BFCFE813AADA619334EBFAE570E4A300B00FB52106F1EEA96F4CC6ED308264AB60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD");
        byte[] sk = Hex.decode("17000000020000000B00FDFF0600FAFF05000D0007000200140010000700F6FF0A000300F6FF0800040009000500060002000600FAFF0C00F9FF0400FBFF0D000300F9FFF4FF01000900F6FF06000C00FDFF0300FCFFF4FF18001400FDFF0600FEFF0D00F9FF0900F8FFFFFFFFFF0300FCFFFEFF0A00F9FF0200FEFFF9FF02000100FAFF010001000A00010000000500FFFF0400F6FF04000600FFFF0000F7FFF3FFF9FFF8FFFFFF010011000900F1FFFDFF0600F7FFFCFF0900090005000300FDFFFEFF06000300FDFF04000100FAFF0400F9FFF5FF03000000080006000200F5FF1000FFFF01000500020008000C0001000500060009000800FCFF00000100FDFF01000000FEFF0D00F8FFFDFF0000F8FF0A00070017000B0001000900F3FFFAFF0E00FFFFFAFF02000500F7FFF9FF00000300FEFFFFFF0300FFFFFBFFF6FF0900F2FF050002000C000400F7FFF5FF0300FAFF1200F9FF0900020009000600FEFF0300020005000000F8FFF0FFEEFF0A00FCFF01000100FCFF06000700F8FF0C00F7FFFEFF0100FEFF0500F9FFFBFF090005000A00F3FFF7FFF8FF0C000000FDFF0B00FFFF0400F9FFFBFF0000FCFF0400FBFFFFFFF7FF0500170003001000FEFFF8FF0B000900FFFFFBFFF7FFFBFFF9FF03000C00000001000D00FBFF0100FEFF0200F6FF10000600FFFFF4FFFAFF0100F3FFF7FFFFFFFCFF08000B00020005000C00030009000A00F8FFF9FF0C00010004000300F8FFF3FF090009000000E7FF1100FFFFFFFFFFFFF9FFF9FF0B00F6FFFFFFF8FF00000700F2FF0000F7FF02000400F8FFF3FFF8FF090008000D00F7FFF6FF01000400110016000000F3FFFBFF0300FDFFEEFF0400040001000500FDFFFCFF0500F8FF0300F9FF0000FEFF0000F4FFF7FF1000FEFF050003000500FEFFFDFF01000900000007000D000000000005000D00FBFFFBFFF9FF0500010003000100FBFF0900FFFFF9FF0E000A00F4FFFBFF07000200F6FFFEFF010009000300040001000800FBFFFCFF05000400F9FFFFFF000005000600EAFFFDFF0100FCFF09000100FFFF010003000000F8FF0D0004000C00FCFFF9FFFFFF04000900F7FFF6FFF6FF0F000200FDFF0200F5FF03000E001100FFFFFAFFFEFF0A000A00F3FF0200FEFF0900FBFF0700030009000A000900FFFFF3FFF7FFFFFFF5FFF4FF1200FEFFF7FFF5FFFDFF0200F7FF02000800FCFF09000900F4FFFEFF050008000D0004000A00F7FF0900FFFFF6FF02000400090005000200F2FF0C00FDFF09000300EEFF0000F9FFF4FF01000E00FDFF0D000B000500FCFFFFFFF7FF0D00F9FFFEFFF0FF15000900FBFFFFFF090009000000F1FFF9FF0400FFFF0F000800FFFF0900FAFF00000C00F9FFF7FF04000600FDFF0A000200F6FF0600FCFFFDFFFBFF0C00030002000E000000F6FF0D001300FCFFFDFFFCFF040007000900F9FFFEFFFFFF0200F8FFF8FF060004000900040005000400F6FFFEFF0200F0FFFDFF0700FFFFF4FF06000D000900FDFFFDFFFCFFF6FF0100E8FFFCFFFFFFF9FFF5FF0000FEFFFDFFFCFF010002000B0008000C000800FEFFFAFFF8FF0600F4FFF7FFF6FF0300F9FFF8FF11000600FDFFFDFFFCFFFCFFFBFF11000800F9FF0300020000000800FDFF1700F7FF0B00FCFF0000F3FFFFFFFFFF0600F8FF00000600FEFFFBFFFCFFFCFFFAFFF7FFFEFF0B000400F3FFFEFF0D000800090003000A000700080003000D00F8FFFCFFFFFFF4FF0A000700F7FFF9FF0400FDFFFDFF0500FFFFFFFFFDFF0600FCFF0600030004000700060000000B000400F5FF1000F8FF0000FCFFFDFFFEFF03000000FFFFF6FF0500FEFF0A000000FBFFFCFFF8FFFCFF0600FBFF0500F7FFF7FFF5FFFCFFF9FF020003000800FCFF0F00FBFF09000200F4FF0B0009000600F3FF09000600F8FF02000600F8FF0300FFFFF9FFFDFFF5FFFCFF0100F0FFF7FF080002000B0005000700ECFFFCFF0400F9FF0500FCFF0500FBFF0300F5FF0A00F4FF070002000700FBFF0200FBFFEBFF0900FDFF0700F5FF0100F6FFF7FF0000F5FF0900FBFFFDFF0600FFFF0200060005000D00F6FF090005000500FFFFFFFFFFFF0700F6FF030009000B00F4FF0E00F9FFF8FFFBFF0500F9FF0200FEFF02000700FCFFFAFF0800F9FFFDFF02000300FFFF0700F6FF06000200F7FFF8FF070006000B00FAFF0500F0FF0C000000FAFF0400F6FF0000FBFFFBFF0C000500F7FFF7FFFFFF0000F1FFF9FFF7FFFBFF0100F6FF11000000FCFFF9FFF9FFF7FF0100F4FF0400F7FF0D00F9FFFFFF01000400FFFFFAFF09000100F9FFF6FF000005000100020004000100F7FF0C000400F7FFFDFFFCFF0F000D000C00040001000600F9FFFBFF12000400F8FFF9FF06000B000700FFFF0B00FDFFFFFFF3FF02000100FEFF0000010007000000FEFF00000000F7FF0400FCFFFEFF0D000F00FDFFF2FF00000300FDFF070005000300FDFF10000900060005000000F3FFF4FFFAFFFBFFFFFFFAFFFDFFFBFFFBFF0300FCFFF9FF0600F7FF0300FAFF010002000C000400F7FFF8FF07000600FFFFF8FF0A00F7FFFEFFF8FFF8FF0400F9FF0200020002000900FEFF0200FEFF07000A000500FCFFFCFFFFFF0300FCFFFDFF0900FDFFF6FFFFFFFCFF03000300100006000B00FBFFEBFFEDFF060003000800FFFF0F000100FDFFFEFFFDFFFBFF0D000400F5FF090000000D00F3FF0300F6FFFBFFEBFF030008000100F7FF0600F6FF0400FBFF05000C00F0FF0200F7FFFBFF0100FCFFFCFF0D00F9FFF6FFF8FFF8FF050003000200FDFF08000C000F0007000000FDFF0300F8FF0A00FEFF09000800F7FF0500FCFF08000300F7FF060004000D00F9FF1600EAFF07000B00F5FF0B001000FEFF0000F7FF03000A00F6FF0A00FDFF0F00F6FFFAFF0E000100000008000B000F00FDFF06000000FBFFF4FF090009000B00F5FFFFFF0100F3FF09000D000C000B00F5FF140000000000FCFF0000FCFF0000FFFF0D000700FCFFFAFFF9FF0B00FDFFFDFFFCFFFDFFFCFFFEFFFCFFFEFFEFFF09000300FCFF0700F8FF02000500F9FF0200F7FF090002000800F4FFF7FFFEFFF9FF02000200FDFF0000030000000400F3FFFAFFF9FF0300FBFFF8FF0100030006000E00FFFFF9FFF0FFFFFF0100F5FF1100EDFF090001000500F9FF0100FFFF0D0009000300080002000200F7FFFFFF0900FBFFF3FF0900FAFF0C00E9FF0500F5FFFBFFF6FF0600060001000F00FCFF000005000E00F6FF07000400020000001000FFFF0200F4FF0500120002000A00040001000D00020010000300FFFF0A00F0FF0900EBFFFDFFFBFF0600FDFFF9FFFAFF08000B00FFFF1000F9FF0900FCFFFAFFFFFFFEFF03000100030000000100EFFF0D00F4FFFFFF00000000F5FF0E00FEFFFBFF0800EBFF000000000E000800FBFFFDFF0F00F4FF0700F2FFF6FFF3FF0000050001000500F9FFFBFF0900FDFF030012000200F5FFFFFFEFFFFEFF0000F7FF090008000A00F7FFFDFF0600FEFF0D00F6FFECFF01000C00FDFF06000700F7FF0700FAFF0800EFFF0800FBFF00000700FFFF0800010001000200FAFF0C0006000100FCFF0400F2FF030002000200F4FF0E00FEFFFCFFF6FF0A00F7FF09000100F4FF0600FEFF06000500F9FFF8FFF6FF02000200090004000600FAFFF8FF02000800FDFFF8FFF9FFFCFFFFFFFDFF0D00F4FF0A000400FFFFF6FFFDFF040000000100F8FF040001000500010001000000FEFF0D000000FDFFFBFF06000600FAFF0400F6FF0500F9FFF8FF1000040006000700FDFF080005000000FAFF0700F4FF0000FFFFFBFFFEFFF1FFF6FFFDFF02000900F8FF0200FFFF0400FFFFF9FFFCFFF9FFFFFF0900FBFFF8FF0000F8FF0900F9FFFCFF0900F9FFF7FFF3FF0F00F0FF0000FFFF05001200F7FF020008000E00F6FF0900060002000300FDFF05000500FDFF0A00F7FFF9FF050002000E00FFFF0700FFFF0C000600FAFFFDFFFFFF0300FFFFFCFF0100F3FF02000400FEFFF7FF010000000900FFFF0A00FDFFFCFF0B00110004000200FFFF06000200FCFF01000600F5FF06000100FDFFF7FF01000A0006001000FFFFFFFFFFFFFFFFF8FFF6FFF7FFFEFFFCFFF6FFFBFF0200F8FF0500F6FF01000500FEFFFFFF02000200FFFF0900EDFF04000800FCFF0300EEFFFAFF0000F4FF0600FCFFF8FFFDFF03000100FBFFFAFF0800F8FFFDFF00000700FCFFFFFFF7FF06000F0010000A00FCFFF3FF0100FEFFF9FF0A00FAFF0C00EFFF0100E8FFEEFFF8FFF6FF040001000900FAFF0300FEFF06000100F4FF0C000200F9FF0400FEFFF8FF0400FEFF070007000000FBFF1100FAFFFDFFF9FFFAFF1200030009000200FAFFEFFF03000700FAFF0200FCFFFEFFF4FF01000D000400FCFF0400FAFFFCFFF5FFF7FFF8FF020009000300070007000E000300F8FF0800F9FF1000F5FFFBFFF1FF0400FCFFF7FF0400FBFF0A001200F8FF03000A000100F4FF0700FBFFF5FF0500FFFFF4FF01000500FAFFFCFF0700040006000500FBFF00000600F7FF03000F000100FEFF110006000000FBFF0200FDFF0800FFFFF7FF0B000700090005000A00F9FFFCFFFDFF0700FCFF080007000900FEFF0600F5FFFDFFF6FFFDFFFBFFFFFF0100FAFF0E0006000700FCFF0200080006000100FFFF05000600F7FF010008000800030000000600FCFFF8FF08000E0002000000F3FFF0FF0900FFFF0300EEFFFBFF0300EFFFFAFF0200F1FF0900FFFFF8FF0C00FAFF1000FDFFFAFF0E00F8FF010001000A00EFFF01000300FAFF0200F6FFFEFF0300010007000400FCFFF7FFFEFFFFFF0700FCFF09000100FEFFFFFFFDFFFAFFFDFFFCFFF1FF0200F0FF0200080005000600090011000800FAFF0A000900FBFF01001500FDFF0000FEFF0400F7FFF6FFFDFFF5FFFDFF09000400F7FF0200FBFF0D00F7FFFEFFFEFF0100F8FFFAFFFBFF00000300FBFFFBFF0100F9FF1400F5FF0700FDFFFDFFFAFF0100F9FFFCFF0900000008000700F6FFF8FFF5FFFDFFF0FFFEFF090005000A000A00FCFFF9FFFAFF030001000300F3FFFDFFF9FF0700FEFFFAFFF7FF0500020000000E00F6FF06000500FCFFFDFFFEFF09000500FDFFF6FF000002000100FEFF0D00FAFFF7FF1200F9FFFBFF000004000400F0FFF5FF090004000C000400F9FF0100FBFFF7FF0B00F7FFFFFFFDFF02000300F8FFFDFFF7FF03000100F3FFECFFEFFFF7FF00000500FCFF04000900FEFF00000700FFFFFAFF0F000000FEFF0800FDFF03000A000100040003000C0001000600F8FFF9FFF5FFFAFF09000100F8FFF1FFF1FF0300000000000C000E00ECFF0800FFFF02000A000600050001000A0001000D00FDFFF6FF0000F7FFFBFF0200F7FFF8FF07000000000003000900F7FFFCFF07000200FAFFF9FF0C00FDFFF8FF00000900F9FF010006000A000700FEFFFDFFF1FF0200F3FF0600F2FF090000000C00FDFFF2FFFCFFFCFFFBFFF0FF0700F7FFF4FF0700F7FF0800FDFF0000F8FF0300F8FF0900F9FF010004000800FCFFFFFFF8FF0700FDFF0000FCFF0C00FDFFEEFFF9FF07000600FFFFF7FFFFFF0300F5FF0700F6FF03000800FEFFFFFF04000300F9FF02000400F6FF0900F2FFFDFFFDFF05000300FBFF050009000800020007000C000700F9FFF8FFEFFF05000D0001000700FBFF0000FBFF0300FAFF0700FBFFEFFF00001100F4FF0F00E5FFFFFF0400FEFF00000B000100FDFFFFFF02000600FBFFFDFFFEFFFDFF08000200F7FFFCFF030007000200FBFFB60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD394D1695059DFF40AE256C5D5EDABFB69F5F40F37A588F50532CA408A8168AB1");
        int smlen = 2753;
        byte[] sm = Hex.decode("13743CD9D613B998A4763D9A4F2618BF7B13543FD344B69EFD0C5AE439B3E5B8DFED144FE06F0983452AE52019BF2EC1F7264361E82591FDB0C05E5C0B32A22420B421805810F89DBF962E3887597DD2FEA01C4596033822A99BACA1343A008053FFFA5DB979E493E71C8B9F2BD2E46D237F0D92769FAA0A3B23B938488D2B40BBFFB3C8CD35AA1C79ACF28303F357A9AB367330A1CEA217701A0BCE89E015C64D34CD22F11A42A8D36B3F45FD74E0055B2B162E2C2DF505F609BC599CFCB2BA3921AAC37E155035140126FB3DDFD88A9D77F6B33D370B653813ABA5857C1E3646A6EB8C81C094EB59CD86F92F9E27B9C53010D52755F268BE672AC153E8538967F620A95DC2B3B6A084753A2A95800CEF18115BA816008C9469B88F16E8ECF9EE85C37B7F7C63EF98C8464B35518A0F4317C39AA101FC85943E14A196051BAFF5214BC1ECEED3F520B95A38DE945CB2FCD358CBCEE6A7F848112863BF0AFDD699E84AB8AD62057A354B0EC395851B4352B99D466503DF795C8D0ACCE3462719779F9C5AFC330A8735B9B4E18D6A2CEF6C640170028D4DCA4F3B0DF09B210FCDC469282B5593F9D40ECD9D52D13352811EBEE1B46C277A73089262827E5CEE82408B744A8257A44F5F7B16C69FD172EA62F3D55D3BF30B96C9B4DC5B86CC6CB1F3F296E78523923C1D7599E459636703CF8030B60513059A5AFD8B033736EFDEC506DC8F40EC20A4213F50067528AAABDE320BDA6E313D224ED1BBF868115759773DD5F107A3D3479823AFDF2E289AB20585E3BDD93FBDE1694C82567EBC65373A688178BB8D540AAD977EC64ECB7277B720760E571D0B837CE33B0E629832CD84707A7E4CB6111280DC16FCD98287DD5B089048520206B865EF1F9095528E6C7ED11DFBBC582946D3C50B529A4A0FE8E389FCCB09CFA04849E034C254F3116F05F7C75910017E6E01112BB6A02D288A8893AE506421E9F02F374A75015416956A3C7ACE5616A162AABFEF5F1B00D4C82858F7A2E48BBFE131AF4A327C09EE19402FDFEDA5BCDE266EB3EAA375A514899907D0DDFBD7FD4A2EA4CBCACD887311DA98653CBFE461BE9A491120A39384FF4376D0152A29696B690ADED65A698E0546B32B1494B3B7470FFBA1E052702ADB1B9ADBACB594DFB5106C5567E3FAE84C131FCEC5395E9C527304ECE8C83BAAE38DEBCC9E1732A2B79D2693481D14803BEC157D714EDDC6FC5F0697073084D36D6110E793C8C846531B14CCCBFEB7D3080E83D70941537606227E2F860084C8722EFED4E829A57B2629C53ACE8C1C77603B15532090E75FEEF57020CC0E6F1FABC426088C0C683062EBF6E588B2F44D0E37C623F12128FB940CA239F8CCD771D3DC4A4BEE056A8BCBB9E412BDC8CAE201DD8E18D74B598771367202D42D93C167E554A04E25B882EB79F6DC0B91826700ACFC4803EBCC105B40DA41875A2174F9FAEC30D64E3BAF0D3C4C60E33470968264D49900F334DCDD0D1B9F85822A063A68F027D9E6BFAE2E68C19D73EADAF48EC457C1D857E05F9200A296E4915C292EFBEBC4A9754B291DE2A7A7411A0FE3692FEF691ED703247002CAA7550730357A031ACA61688911DC6A546AED3F63B4BAA4DFD31E6DB3894F73029174F87495255FDD5A708FB213FD855FCDB523881DF45B2754C329367D3741226100F57A5F1E23A2DECBFF6BD1B79B9E1C0C7BA11157D9CF9173A13D9DB71D539432B39F78183F267E851A6CE314212BB2F448527DF68B822FFE6ECE7377070750EE0E8F7C7A84553B293C1B1073E6573085569DCACF3D82167B58D12915E75400F3A2D72A399C1354926BE462DAB3CF892502F4DF62628A58E77272E2F888555946B2DF445E54EE15C7703F7F632DB235C9D443F3C16012881824435FD5ECC602665912FFA65D65ED92D202567852A1D0490159235A93556D39C99805B6D4C4CB779183E08D0A5FC9E8CF007AE36134135162941CE3E582098C605F070048C0AC627E54555740B00C724FFB68839F60C692A48E349CB25AE564E98AD920B71C19D5729AA759F4FBE1E2639C84D71034740C1AEDCAF84BEAD4CB2F75CCB22DBDC9E4D7100B1F8F35E1D9CEBBF8006AFE2E86BBE9AB84A691378699FC79AC749EC9B629A10CD1B14E2008F08038984A270FDEB4E9C003BD006ED89FF1256ACC6D0DE7AFB2029604321D317B89BAE3A28416CBE28CCC6A944F6D3A6504BC5E552BD7784CFE293576BA30D9A8983D84D5ADCA28F1BC852ECFAD6C66B727373B2345321A18B6E2A0F3C08BCE8FCC61A205C0E5F0E9C221B128D0E3C04845EFFB7428178E0C7EAD35A526D38286451D4919C3D411F79B0DA7306D1FD98941C9D92CB4CA227C4FCCE088D76666C76AA29A15D4F6F38B212733C5AC9A91C8C36F869A59A99610FE2FF6293432ED64466029C55C11AEE67365394718180D87DBFAF85F8A045A04D5DDB70EDC54D116E265DFD70E40DF97AE9A4C833183BD66089BCB8AC9471BB774A704ED070EF17D4321E39FD9356867485AE8653C7C9BAA77B43D4355A82896CD710C0F4018A0668BB8F013633BD93A668180CDF0C95F130E42E4D6B04225DD8963464E62EB80D092D717BA9F837B357FF662598A6673DA0267107FD669EF03E01234962435DBE523C9F3E789813DE5AF59BF79994F234DA54C56A65EE9ED5D04B0625CEB29ACEF98BB483F3D8BF5074CAFFAD4635C9D412089C77EC81375F0FC30717C166B386FAC0C81ED285D38AEF2CAD959E39649F31449D65185AF84EC23B34D193EDBB9C572B9818D285109FB8334574CAF14381CF005A07BADE9B2C9C3B69FDD4C57D396FEB7130B092FE98407D3D038F7E51D7FDCF55213F363234306E9FDC4D711B590C684708C5AD86D900E4C7B9951029D6FDE5CE088C8F9D5D9A098C08FB904C07D9AF8F3307AB00370A685296F5F08CAB69947274089FA8D70BD6E0FFF1BDECDC96E1E5094D0B904F71B8814FE4C1FCE6C11D8883045E4FA4F970A892BC130153F846983440121617A5C6DEB390D4DD4FDF6AB786F2A2B9C44658889A515442D085BD012C7F4D5CB6FD17FFDC406F2B523958156190F47EFBE3CBA8D1EA7618CA86DEE0D114AC55EC55F640A05F4CC9DF350238CE031678BB98F155D4418DCAC97D8C5F4352D21D4D347A0A67120953A473040F317E0CA2F8E8B74CD263580EFE8F5BBA540CC402D624C8CB1F46A5458F20EC38A7E36BDCC812651C29851D692B7339F73D563B7BA708DCBF2F8D20970760823E3EE0D87658607CD911E08D818821AE6980868C0B3DCFAD9506903F80F04EAAC193741B61713388668B7165F8B9EB751E583EE78D0BB99E574A2E60A5A8C3C07417F8C28DF1613F09EDDAA3728481BE0C042F54DED6F4B825F8416FA7FF9D088F92939DB9BE5908057B10C5B3610D51CABEED0B22E7EB54D929CD42A2FC006E02B9CBEF3538911B984D9D7FF19D3709F47BEDAAE8B8614BFF07A00B48484DC61A08DCD2112644E9B64D02FAC284E2680215554C66DB3670F98BC86F31CBD89916E8192C18D3D6A25987E3FC5B4CDAE929907C7D449B01F7BE45EB9EBB0B7AB4CB69A9D99BD6E082CF6683403B8413B6885C9E8D2E9DB18B5A9B47CCDACDEBA8A03D4D0C4517DE93C8527898F7F89BDB20BC8929E7057E40CD61AF0623D64384F6CE5E8DD30F0F56F8C4855526B5FE1B88CC6F96EDC897E71638D93FACA00DC6FE30F8B3AC0EC48AE46889E75870A01BE62CDFC6A087208A17D8E3A5F55BC336233ED43DCE46111F7B98BE16DB5DAF2A79D1388387EA3201B9FC6F1A808BD5BB545E9075E1144DE5DD516AA3C086148DF7A5A9D2C2D40DFBED1D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");

        byte[] sig = new byte[4000];
        int[] sigL = new int[1];
        QTESLA.signingIIISize(sig, 0, sigL, msg, 0, msg.length, sk, QTESLASecureRandomFactory.getFixed(seed, 256));

        assertTrue(Arrays.equals(sm, Arrays.copyOfRange(sig, 0, sigL[0])));
        int status = QTESLA.verifyingIIISize(msg, 0, new int[]{msg.length}, sig, 0, sigL[0], pk);
        assertEquals(0, status);
    }

    /*
    # qTesla-III-speed

    count = 0
    seed = 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1
    mlen = 33
    msg = D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8
    pk = 624563CB6E4499327172AF7F15FE1893614871835EA6F3330DD94337204F88D911FFB91B06CF2F07240203F75353906FB7EA7BCD0A4362546D94E60D32833623CD73B1D055DD1C2533CE5B81DE05C02966275D289D25134EF8577C7A489B383D3FA769DD3C1C033325034B731F7F678E5E58426F372F0F24DCEE455A8C6B0E6A68796E7B8D36317B23641E7D4EDDFA1E4F4A5012F50E70222E36527A14A559F4132F025F2C20BD3C2C023AE2E249E94D23460C80B94006CB1E38769A510911672D2E48AA5E5DD54F38746C195CA954D6A909CE33759A222399F209FBCF26641029D08D4C0C3D51D2FD7DAB2A6A3779365B06720B686F052A1FC5A54C5B4A26962F224C194096FA7048372F037D5E9772315B956881615C72EB57A0B661E9851F5BB61A17755BBFB571CDD90FFE562C4F147846407266A43AD9D063CD7710256D69FF6F07164E7A41D13E66C60614EB7F69B621F83237633E36E7F16605DC0A89A774E425323BCA551F211D4AC6110C314F39B873E48062C00255EE6E7E5BCF75A94F6DAC0E182C44532468658A2A6A9A9B72BAD7715E0765A10B520CED236A4D3343FE2A347D726D6107046877FE583F09FC50F4804CAD603810A15C7BB655400533721E4D38E020EFA64E3DA8277DAA437465033C486FCAFB5235B44C76AB27ED5E5D7BFA6CB2EF6EC7AE008AB5320CF861DB605321406ECDB56837572048175831343A1A192E7844225B6A72E66B42C98C7A3C513D2B5A71BCCC329BCF20246C241C4B5EBD5F37ED144C1CFD173F6330F78D40C9A952192201126F79EB1E444BE27E3FF500FDFA0BC27706FF2A4381454634540D3BF44CF418613C087776C940F5EC1928E1190F710909EB43EA715FBAFA3E3C140396EB516C9664A87277AAFC139D343D512C65776056A1C31104645033E03EBEC24D99837D1A427CFB7B72DDF86054744ABBD62B57A8355C8D3994F84B2A4B2CC1B731529E495F811A73414C03FC1B66BB0C58105283F42AF9B2521A5B717D8A3E8DF411A85C68F706006E8B7D1114769E2103FB2B7601DB1BC28B0355D909AAAB3702904F96BA6FCA3152C4F042596A7854B13827222DE0925A47CE40F2AF3FAE9F19395D70DBAD28DA8E7AC34F5BD36E174CA352807F2C49645B05015B389B3666A679AF7A033C8C0659600F6761263ABB6B4BC2360F29267AC82D80905502B7557A295406D605D75828565046DAAE09B12080EEAE67179D53B05A54444B4CC77C1E2DAB2D298D785B841047B5665D3C36E3181CD7AB2DD49F78633661949F585E0A18530D7940046E140D684C033915EE5DBC3A07C34A4178516F43964F0E2E04647324D26107980F68FF990C7B8C0C47F12FC1AC384520485EF061DF373B78A12D80810834AE36E5BA37397D35AA5C4625B708C51066F5C54CB1C52E0A9D3CBB772819D44A875B78AC4A65D3EA7621BE271914770B8D363CA911B8874CA1C16FDE314725B409391933DBD96B5BB013C2723E307D7D9C1C41654049204837D4074FA12B46E25D39E1EB3F74194C08CA47453E2092AF3142D06950FE14087E1A80970ADE4E7C6F6D70294F3710743854AF2D0A1776DDE166895950DDF06B2ACD11E5A248D8CE52EFF276AF9414B0DE264B315D61413EB731154CEC10F0FC230801229311566E781A57F65EBDCA4EB0CA71C62F281AD139D105108FFD5345016734F37C039377F71B36B649661F425A2CF3132CD40FF6DD5668C25808441EB86415136A55F57A1DC5991463A00BB3C67CED334979BE64A192471EC95F9F591014D607BD23585E5F0E03B33AA6E11E70F3314E7305336F5BF5E25E25D33C985B2D86BA0C41980199C506CE420F12523269D62949904174B86B383E41255F64940029094C0E9BAF76636E6E37B6711DA70ED1510E6BE35DE7C34FF8613BF3AD2358161E0E7F58696A669FD50ABEA278872C58BC3B1387F93DA26245E1DF1A35D32BB51F372F1133975E5DA27B5E112B43508D5588EE21D7A2704A9F7B1E7C62454D6D4321171C3647841D4A7BBB3B25DF019F856B7DE1652F26132C55049BF85AAEF21FDDFA03BB873761A72B389B3217C238B1EF315D4778EF4643431E1327350F240040CCF90C324370843554E9C23F6075089FB94677E85377B74FDD6A174F3B628B3F30778A629F6A5D9D8274943110095C3B763E4BC9862DD3F1441DE30256F20FE5DF629DBA55AF182C373D03D1E707253360E69455388554FC8140E97377B38024DB1C1CFAD014949552BDE132F8BC1D066166B48566C4A672B9F07A3C32399CF351AC073665FE4D52D11077CC6E823516920843FDF62FAD5D7D081B17470F16122317C3C84A7BA54B988E77952D1ECD012F90BC3C1E4152FD577E927847A8F943F5B87170A933C7DD5C8DEB4D0D02615E7B66D5CD399D0613CD111784C27A27A71516174B0D9534CFB51B6EE67D77767B818D79444F4FF519397E4C7B87EF06B0826DAE7031CFA63B835D4E2FC5035F3118463977458C6F5EB97F9CC87D77F107C28402F9D616681C108FF14C432315A368071A6F19C18108833137A4DF25764754FCF509EB6B1B118029CD7425566F4569020F5EEA7C3F5A6B0F3B62E8B615333F5FA43E15484C4F71496420D331D7FD74445816273113BBDA6DD5434DA9537EAD8479F20C2B4AE7648B9B04EAFA3A36143F0AB364552A482B766ABCB33274C832F5B3687B4802E3E369804275A0F443C5B76113E7380ADF03BF7057BAA575521D75F1EB5F774A7353A94D9BEB1BE70D174E602435FE55B8863CF5F71782B83F1AB62C222D5DDC8E04B20D5EDE755CB89E61855A160CBA7F60D708238267FE727DBDF67B8F160280A363F04B5EA62F79ECA260A0DA31B0C016DCF509A32E80A2B91176534A36B345FB2018C17540D14D569CAD14644F1135E779D360078F1D3DD4790757E035A4466B1C097751C01FC0E32D6A0C24ECD16D027441A38D26A9125F0D13039F9B2650E64C31322DE2743FB5306D057C1AE9B2051D916C0E076439070328344C970E47651B2D9E826DF12C6724347FCB3E13C61E0B79AD1E67D747C1BD3A9FF274B5EF0143126EEE3F6A72E10F75A70A77EF46B40B1A2D5A39BC2A2933DC3222787C60AC73ABBD110E73698E6A00C8BD031B626583832490B67647A3499A9431F3446DB4710E24F32F3F321E6C87427ADE28DEE2287D6120C6D633E1036A1B72067B955C3F873026E01957491B5F8D60888C13A91136FAAC24DF284668B31602C24EA4EC4BB0AF4A444C3AD22620E0B046E0CE3B28186265BD34C2EF34A74A56CFF15F230F308C6547D7252D340412F37F279B033C068961CA220A6855624EB860BEE53E8D0C492EA668A81164A87F042D9749DF8B493E4F2564D437ED53183ECB06961A09A3E30C4CDF37013A7435316DD6877CF3E2556689320CBF6B504205CDCF0B5F600EEF300669F65123B60972CA14785E4B54514143193B889D17415769413927235A24BA7D3828A844798179A44914C9F94B47701E07233E5B4050B6044270930583E5381AAD35E1C906952C1CAB143777C26208F90AAFBB6586295F168758400655DFB852BD314E5F5935735D66090521395B56CC60029B752D5D0E2B69F70043DA3A620D6A089661060B04E7402D33B77E726A49AC7C4D8EF52819E704B8B41745811774611BA3F108CD3143BE976A4A310D13320FB3C92B41C353C3725DB54B091B1E2CD9BB474360159BB615AD614399D7635465761748078FFB19828B72A1B57001CE20289E0F02BD15BB5E109FDE3E92BA495C660332337B94EC05568E4AE9065D1B0664CD4D11CA9A0BECDC7AD4041E2C044456B77E4E3C2066A33AAC412D53E66E2AFB12B946079B330BF0852D033342F2914337AE04425A02F80E1CC55C60530C08692008AFC758749726B5340B29F74A3F8F4045436293870A91746FAC025EF07C7D1D065B9D120962F87255E21E6EC73277D66B353D741F2D3ED099670C560D929D5E352D7CB5BB2A529F35FE8E514E4D72779256CBAF0B382A2E082E08294E6CC83955B2FD0ED1C65AC2355674823854F807EE707F83F42120375D4AEA21D076503CEC7DD539645B527856973BC0F06597081B7DCC48D428130A9F3230065632201FFA404FEFBB7EAAD60FA6AE57CE312CF7A51703610B6B9D0BDAD64A09D402C8D670DBEC4146816D80723CDF8E4BC6DA4CD5AA540FF510626F12FCA9485DEF65045257B5B24E896C647FD61C5D12013B3277DAD75B21243AFDA11109826B7B7F5873503323EC665D8C11E5CB441C4065FE1763BF302B21DF7FFBD021763F6031AA36369B198D761FD1FF1925583733EB325F845D754426B60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD
    sk = 1C0000000A0000000F00050005001C000A00F3FF000010000A00020004000000040003000400030005000A00020004000F00FDFF0300F3FFFAFFF4FF01000E000100F9FF0B0001000C00F3FF0600F3FFFFFFFFFFF6FF0200030001000A00FEFFF6FF070000000E00E9FF090000000D00F9FF0B00FEFFF6FF02000B00FDFFF2FFF1FFF3FFEEFF0700FCFF0F0002000C0000000000F3FFF9FFF8FFFFFFF5FF010014000900EEFFFDFF0600F7FFFCFF0900090005000300F6FFFEFF06000C00FEFF06001D000400F9FFF2FF03000A00080006000200F2FF1300FFFF01000A00F9FFE9FFF5FFFFFF0100050006000C000800FCFF00000100FDFF0100F6FFF6FF0F00F8FFFDFF0000F8FF040007000B00F8FFF6FF0800F7FFFFFFF6FF02000500F7FFF9FF00000A00FEFFFFFF010004000C000900EAFF050002000F000400130006000A00FEFFFCFF1200F1FF020009000600FBFF0100FFFF0700F8FFEDFFEBFF0D00FCFF01000B00FCFF0A000B00F5FF0F00F4FFFEFF0F00E8FFFEFF0A00FAFFF6FFF8FFFBFF0C00FAFFF0FFF8FFFFFFF4FFF8FF0F000000FDFF0E00F7FF1400E9FF0A000300FDFF0000FCFF0B00FBFFF6FFF7FF0500E8FFFCFF11000D0006000600FCFFFCFF0300FAFF05000300F8FF0700F8FFFBFF0100FEFF0200F3FF13000600FFFFF1FFFAFF0A00F0FFF7FFF5FFFCFF08000E00020005001200040003001100F9FF16000B0004000300F5FF07000700FEFFF2FF08000C000000FEFFF9FFF9FF0E00F3FF0300F8FF00000700F6FFEFFF1200FEFF010010000900F5FFF0FFF8FF0C000B001000F4FFF1FF0A00EEFF1B000000F0FF0600F0FFF9FFF5FFFDFFFAFF05000400FCFFF6FF08000900F9FF0000FEFF0000F1FFF4FF1300FEFF06000100F9FF0000FCFFFEFFF4FF00000A001000000000000500F0FFF3FF1000EDFFF4FF10000D000B0002000D000300FAFFF9FF11000D00F1FFFBFF07000200F3FFFEFF0100090003000B0001000900F7FFF9FF0700FFFF000005000600FBFFF7FFF7FFFEFF0B000C000700F8FF10000A000500FAFF0300FDFF0200F3FFF3FFF4FF0A00FCFF0D001400FDFFFAFFFEFF0F000D00F0FF0200F7FF02000200020002000900ECFFF2FFF8FF07000B000C000D000900FFFFFFFF0900F1FFF9FF0E000C00F8FFF5FFFDFFFDFF07001000F9FF0F000100FDFF0A0008000400FBFF0F00F6FF0800FDFF06000F001200FEFFFFFF220000000800F0FF0F00FDFF0C000300EBFF0000F9FFF1FF01001100FDFF10000200F7FF1000F9FF0A00EDFF06000600E9FF0000FDFFFFFF12000800FFFF0C00FAFF00000F000B00F6FFF7FF04000A00FDFF0D000200F0FFF5FF0100FDFFFBFF0F000300020001000100F6FF030011000A000700F7FF1000EFFF0800F8FFF8FF0500FEFFFEFFF3FFFEFFFAFFFFFF0000F3FFF5FF0B00EDFFFDFF0B00F3FF060010000C00FDFFFDFFFCFFFBFFFDFFE3FFFCFFF8FFF3FF0F00E2FFEDFFF5FF0D000600F3FF040002000E0008000F000A00FEFFFAFFF8FF0600E9FFF4FFF6FF0600080014000600F8FF0A00FCFFFBFF14000800F6FF0300020000000B00FDFF1C00F8FF02000000F0FFFFFFFFFF0B00FCFFF8FF00000600FDFFF0FFF7FF11001500F6FFF5FF0E000B00F0FFFDFF100008000900EBFF07000A001000F6FFFEFF0C000D00FDFFF9FF0400F5FFFDFF0500FFFFFFFFFDFF0600FCFF06000300040007000A00F6FF0E0004000500020003000000FCFFF6FF1300FAFF0000FFFFFDFFFEFF0000FEFFEDFF0900FAFFF3FFFAFF0600FBFF03000D00F2FF0D001100050003000800FCFF1200FBFF0C000B00F1FF0E0009000600F5FFFCFFF2FFFAFFF8FF03000000FFFF0000F0FF0800FCFF0E000700120004000600EDFFF4FF0800F1FFEDFF040004000400F6FFF9FFFBFFFCFF0400F6FF0500FCFF0B000100F2FF0D00F1FF070002000700F6FF0200FBFFE6FF0C00FDFF0600F2FF130010000700F2FFF0FFF9FFFEFF05000600FDFFECFF0100060007000100FEFF05000500FFFFFFFFFFFF0B00F3FF00000C000E00F1FF1100F9FFF8FFFBFF0500F2FFFCFF00000700FBFFFAFF0800F9FFFDFFFAFFFDFFF0FF1000F6FFFCFFFBFF0500F6FFF8FF07000600F7FFECFF0000FAFF0B00F3FF0000FBFFFBFFF9FF0000F9FF1500FCFF1200F9FFF7FFFBFF0100F3FF1400FEFFFCFF0500FEFFF7FFF7FF0100FAFF0D00FFFFF8FF0600F5FF0400FEFFFFFFFAFF09000100F9FFF3FF000005000100020004001300F1FF0D000600FAFFF6FFECFFFBFF120010000F000A0001000600F9FFFBFF15000400F8FFF9FF06000E000700FEFF0E00FDFFFFFFF2FFF2FFFEFFF5FFFBFF0000010007000000FEFF00001000FDFF0F000700030010001200FDFFEFFF0000030004000300020009000300FDFF16000C00060005000000F0FFF1FFFAFFFBFFFFFFFAFFFDFFF8FFF8FFFCFFF9FF0600F7FF0300FAFF01000B000D00FFFF07000A00FFFFF8FF0D00F7FFFEFFF8FFF3FFFFFF180014000100000002000300FCFF01000D000500FCFFFCFF03000C00F2FFFCFFFDFF0C00FDFFF3FFFFFFFCFF03000300170006000E00FBFFE6FFE8FF060003000800FFFF12000100FDFFFEFFFDFFFBFF10000400F2FF160000001000F0FF0300F3FFFBFFE6FF03000A000100120000000600FAFF05000F00EDFFF6FF060001000100FCFFFCFF1000F9FFF3FFF8FFF8FF05000A00EEFF0700FEFF0500F7FF0D0012000A000000FDFF0F00F6FF0000FBFFFBFF03000B00F0FF0400FEFFF4FFFDFFF5FF04001000F9FF1B00E5FF07000E00F2FF0E0013000100FAFF03000200FBFF0C0002001900E5FFFEFF090001000300F7FFF3FFFCFFFBFF0500FEFF00000D00FEFFFBFFF6FF0000F7FF03000D00F3FF0D00FDFF1200F3FFFAFF01001D00F7FF0800FDFF00000200060008000E00F2FFFFFF0100F0FF0C000100E2FF0D00F9FFE8FFF7FFF6FFFCFF0000FCFF0000FFFF10000700FCFFFAFF0B00F8FF0000FFFFFEFF0400FCFFFEFFFCFFF3FF04001A000700F5FF02000500F9FF0200F4FF0C0002000800F1FFF7FFFEFFF9FFFFFF0300FBFFF6FF070000000400F0FF09000500F1FFF8FF010003000900F4FF1100FFFF0300FAFF0800F6FF0200FDFF0100F8FF100007000F00010002000600F4FFFFFFF6FFFEFFF8FF0D000300FAFF04000B00FEFF0C000300060001001200FCFF000005001100FCFF07000400F5FFFBFFF9FFE8FF080012000000FFFF020000000D00EAFF0700FAFF1000F5FF06000300F7FFFEFFFAFFFAFF0500FDFF0800FBFFFDFFF9FFF6FFF5FF08000E00FFFF1300F9FFEAFF0F000600FFFF0700F5FF03000A00030000000100EAFF0C00FDFF00000700F3FF0A000200F9FF01000000020006000C00F6FFFBFFEDFFF7FFF6FF0D00F3FF0B00F9FF01000500F9FFFBFF0C00F6FF030015000200F2FFEEFF0700FEFFEEFF11000000F4FFFDFF0300080002000000E8FF0600FEFF1000F3FFE7FF01000F00FDFF0600E8FFF6FF0B00180007000B000C0008000200EBFF0A000700FFFF0800000002000D00060006000500FBFF060013000300FFFF03000F00FEFF01000A000900F6FFF4FF070004000400FAFFF1FF0600FFFF00000000FFFFF0FF0C0004000A00FAFFF8FFF5FF00000800FAFF0200FDFF1000F1FF0D000400FFFFF3FFFDFF040000000100F8FF040001000400F9FF030003000100FEFF10000000E7FF0200FAFF0200EAFFFAFF0400ECFFFFFFF9FFF8FF13000A0006000A00FAFF030005000000FAFF0700FBFF0500FFFFFBFFFEFFE9FFF3FFFDFF020004000500EBFF0400FFFF0200F7FFF8FF07000500E0FF0D00E8FF1300F2FF01000D00F8FFFFFF0900F8FF0C00F9FFFCFF0B00F5FFF4FFF0FF1200EDFF0000FFFF0A00FBFFF7FF02000B001100F7FF1600090006000A000300F5FF0500F5FFF8FF02000400EAFFFFFFF5FFF2FF0600FAFFFDFFF6FF0300FFFFF5FF0100F0FF02000400FEFFF4FF0100F8FF090007000100EFFF1400F6FF0D00F1FFFFFF00000200FCFF01000600F2FF06000100FDFFF4FF01000D0006000800FFFFFFFFF8FFEBFFFFFF020006000100F7FF01000000F8FF0500F3FF01000500FEFFFFFF02000200FFFF0900E8FF0A000800F6FF0300EBFFFAFF0000F1FF0600FCFFF8FFFDFF03000100FBFFFAFF0800F8FFFDFF0A00F5FFFDFF0700FCFFFFFF0000F7FF0D0008000300FDFFFBFF00001000FAFF07000A00F0FF010004000500050000000200F9FFFAFF0300FEFFF5FF06000100F1FF0F000200F9FF0400FEFFF8FF0400F5FF070007000A00FBFF1600FAFFFDFFF9FFFAFF150003000C000200EFFFF0FFFFFFF4FF0200FAFFF4FF0B00FDFF02001400FEFF00000F00FFFF0600EAFF0500EFFFF4FF0700F4FFF7FFF4FFF0FFF8FF0B00F9FF1300F2FFF6FFEEFF0400FCFFF7FF0400FBFF16001500F8FF03000D000100E9FFF5FFFFFFF9FF0100FEFF130001000500FAFFF5FF07000400070003000F00F5FF00000A000F000600F8FFF0FFFDFFFBFF0200F5FFF6FF06000400F4FF0E000B00090005000D00F5FFFCFFFDFF0700FDFF06000500FEFF0600F2FF0A000A0004000A000900FFFF0100F5FFF8FFFCFFF4FFFCFF06000600F6FFFFFF0100FFFF05000600F7FF010008000800FAFF0500FFFF1400F9FFFDFF0200ECFF0000FDFF0C000700F6FF13000000FEFFEAFFFBFF0300ECFFFAFF0200EAFF0C00FFFFF8FF0300EAFFFAFF0D00ECFF01000300FAFF05000400F1FFF9FF0D00F3FFF5FF0800F8FFFFFF0500FCFFF4FFFEFFFFFF0700FCFFF5FF0900FDFFEEFF0C00E6FF0000F2FFF4FF0600FBFF1100FEFF1400F4FF080001001A00FDFF0000FEFF0400F4FFF3FFFDFFFAFFFEFFFFFFF5FFFFFF1200FDFF0E00FEFFFEFF0B00FAFFFBFF00000300FBFFF5FF0A00F9FF1900F2FF0700FCFF0B00FDFFFAFF0600FBFFFCFF06000900FEFF0700F3FFF8FFF2FF020001001200FEFF090005000D0008000900F9FFF7FF030001000200F0FFFDFFF9FF0700F7FF0A00F8FF07000500020000000500FDFF0E00FCFFFCFFFDFFFEFF0E000500FDFFF3FF00000A000700F3FFFAFFF4FFECFF0E00F9FFFBFFF6FF04000400EDFFF2FF09000B000F0004000A00FFFF0C000600FDFF17000D00F4FF08000800F7FFFFFFFDFF02000300F8FFF6FFF5FF13000B000D00EEFFECFF0F00EAFFF7FF0400EDFF06000E00FEFFF8FF01000700140004000C00FBFFFAFF0800FDFF060002001600F9FFF9FF0900FBFF0600F8FFF9FFF2FFFAFF09000100F8FFEAFF10000B00EEFF0300F9FFFFFF00000F001700F7FFF3FFF8FFFCFF0D0001001000FDFFF3FF0000F4FFFBFF020010000A000300F2FF03000A0003000C00F4FFFCFF07000000FAFFF5FF0F00FDFFF6FF00000B0003000300F9FF010006000D000700FEFFFDFFEEFF0200F0FF0900EBFFECFF090000000F00F8FFF5FFFFFFEEFF0700F7FFF1FF08000300FCFF0C00F5FFFDFF0000F8FF0300F8FF0900F9FF010004000800FCFF0B00F8FF0700F5FF0000FCFF1600FDFFEBFFF9FF07000600F6FFF7FFFFFF0300F2FF0700F3FF07000600FEFFF6FF04000A00F9FF02000400F6FFFDFFFDFF05000B00FBFF05000900080007000E000300F3FFFAFFECFF050010000800FCFF0000F6FFF0FF0300EDFF0800FBFFECFF00001400F1FF1200E0FFFFFF0400FEFF00000E0001001200F9FFF8FFF2FF0000F4FF03000000FBFFF6FFFEFFF6FFF4FFF8FF01001800FAFFF4FFFCFF03000700B60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD394D1695059DFF40AE256C5D5EDABFB69F5F40F37A588F50532CA408A8168AB1
    smlen = 2881
    sm = 14CA42B0BCFF0A0DB3E20897E1A6DF1DF2A9BDF34F73D8E42B60706EE8F0C60D8430CA12F0E11E7B79CBD89743DF155A2CF70DB62BF45C1F2D16B37341DF548E93F5776C9D955E3A58AB6711339BC4DF1006B1A8FC60F2B804719C5CFD04499D3524ECE1C008AC586A7833852D3DCF9FEBA864C2A477E755FDE7271B16AB2313397142DA6EB6B8CDB65267BB3FF3E383611A4C54FDA66A8D60C7613BB9130E87E5A105F5055ABECD33B5CD4D26CFC222F7C8BCD667ED167074F620D940F12CD11D76131F76B6CA32750819246EC386788DB1FE466C855FE4AECA477AD18C2DE1FA871A572042864F7873EE11B69CC2FD244F2C9103E6D71CA34139A429F6F052CC1990A9ECC0DAF1F11FF0DB092F166194A291A278E73275AD809D20E3CD7D74A3F37A61CFD4CBAF58AFB36C11D658CF2619E2BF773D9379ABFB89E608DCC7F94E2A8E664734F8D89A3BECD865E76C05E236B1F6365F8063314835D38240DEEE166D9413D037912B0918314CAB4490021BD939BF291C992A67EE087FCEA6F1CD012FBD933B56E0B307168115DE30010B802799BF3333F58D9E19505C2B041F546FD8DA5488AE1F149D7205D32DBA7043B28059A2C3C927724DE0D7ABC407E7280E7CA32BB441D4759A0BC1D30C20042DC0807208FAE857A7ABE6D2AF45B5241423BCB45E2F17D6BAA08A1DDC123144B02A0D5BC28CA266E4B615846BA23D540ABB951A3C5E5C1FD55D05CAEB2E0EC7483D8B2865474ADB37AC484543DEB10B3BD62490D0DC5AEE4216FE0A9F06BD8E89A216576399BD18AD4D63D7BB5DA8DDAD27BDEDB4DCAA5BD7B49434BCA3ED398BF9FD5D16FF07479E49A2778E58AA0D7687D15A9D4CC4089DA0A8269140A28099BD8AE802FEC2E38DE976971F9037AB8BB8C9C3E27D8EAB169F5D8F4B1BECCBF937CA0D926E83BC14CB49762877E667751F29ACAAB622A9FA56646854592B548074385F61103DE9B4589CFF79233C77EAF55362C083256F7FFFBCC82148C2EE226108DF2AEA520ADC4DCCAFE059F735DFAD95CE1F1B91C2CBD878B7526A15B3A934325733C8B45D79EFFB9746FD2E0318B3371C5316B9D946EAA2CA4975C78B183B6A75CC48DF776A714999EBDCCACA5C2C7BC1CE12290B084728356ABCFACA40D4830F6354CD9545FF120F99AC686F6211D8A4DE0AC426BABFBDE2398F272EA688920D682B9A31500854752A9C44A3AF2A65BD52215F8552B4AA9705A2FD043CE5C89311587F400B618F93C04280543AF730A0E16FC4DF0AB47A0F9C320FEB48A1849BE46D588FB677CF87BA62BB51CD21E627D28083452B9CCA286AFA5D0CF67FAEDCA84819A1DD5A6DAE249C95E2B6ED0F903588F0C20DF9E90E990E25975DCEF53BDCCEF15780952B508504C52CBF9099165D9AFFBC94F33CC72C63454AD8E4BF1BA8DB701DDBA7F893DD3D05300D028789F3C3D062DFE0830A07340E5C3EA9DCC5D3798F28647EE7003B6C65C5E71722E9C12BCA140E266060A862F8AA12C7F43C8A30CC10BA9E1B118D8A6C6F647D94D34E3E163C1BC7EBA6EC97E52E7EED3E082EFD9B60E3BAA045905C4A1068EA8797D9C19FC3F121DB2A1714020B4AE6526423BD8AF705D342629E8DE7A77CEDACB61222105B80BAF59D285455831B183897CA81F93E08703D2F086C593FA6C583A383A7A9DFC5A890FDD7739C9B3797709CED9FA93AD4B0572FB5192FFAFBADB6725A13FA2C7C0F62E6AE1B89C094B14165AD00554C472BEFF44FD5AB60763F02A0A930C360B7F220A0039684A41AB45A18262C9BEA2BA7B5AFB7462F4EB2882572374F8B5C3FE34802A21F3EC37996593B707D7189C75547B5BD9A4D120B3FB27E7D505378FAF91E2F62333C06A2411CD70FA5D269A8509CE0A11E12D69B04D9B242116D1256E0F863081A3AC0C4FBF2525CB2D985FA88E7F270662C97BE3AA27FD19FF4F7973C107FED99693135D2C9536A90FC0BE1C3CD2BBAF34F7655F4167D41FA71E3331C0C898003746AFA42D5C9027868338E42819C18F6702D7E24B9F418E69737FD28F3F6E261EB7F72DF5E1DF899790CDCE2C965BABC93419AED0C83458C43806819FA1311EE317D2C49BD341F6442284989C4E71C577305489DF1D30936493700948C1F7590719948263BAD1812077391323AE1B8B01BE3D68E7F41C1CF1D2556252E99400430ACDDA6901674B63C2265A843B71A85C2E33A40ACA4C40CB0F4EF3E9FC83FAFF3010BD6C97F17B26519F588F35AE75F5A5E4651D8CC56262685F4230B392993CA0765A2CC5D986A945C82C251554B421DBF546D4D7505C2E2FBB5F9721B5ADAA8F389BEF5624F49CDE0E317A11433CD49F9FD0A0BD1BAC539CDF2579FD5A248BCC36231031C101431E09F5AF0E763E6437E5D8068789E10014F42BC3011472D9530E0D5BAA97D03F03A69FF197C448C3081A5F2B778025ECF944D67DE0565618FD89B935F397D620239BD4AF85528AD4753F4E1E7EF8BFBB357D9876E29DE758653E2CA9D083896921D29BE64890142869BFE62CF364465434DC0691408635E3D1991277401C8569AF2F781AEAF0776E4C737FFDD78C41C95957EB756517F3136A9855E6829909953C8C76D5C2983F4862BE27EAA83E0D64F135BCCC553157A5961003DB4BB694AA020F39A947BEE927F0752BD185716A80A976231646E1EAA7B581D8C42531E0442F73FE65ADBA383E57A7995B1FD520643DAF9587FF2600C30FDAD6E2F652D71C7FF7EF41BDF7E4BA9034E0BD6F7F239CFC4485ADA2D84979503F8A91C0ADD6DF19A0B6B00790306F534DED80C8CAFC02160B9C9EA4A93F50FCE66CB2CA041EFD4B469641A7AED232C9593930AB05D4A67C46224E40806EF1DDC951BF1D7D8FF7A0A689EB88887F42D891010D4FF4A7839C3CD9D62B6B27EAADE4A54094BCAA1D114172B4036C1CDE268F43764126FE3E20EF9881BBDEDDF51BE346131DF432AC1E177A5F0CC52B03688FA40D6E033D5ACCC64EBF201519713117329A50C86B9F971AC58C001FF28A51B3FC06F3796986C30D01EEE4D5A607E0246657FD3CA4560AECC4D40AF2FDC07150CB0AB8E40C02FB7A762D3D7976F9E13FA1B953E17A85BDB74FC81F3BB8B2B01541F44C3ED8C3A1630DF1549DA0EEE4F40C49C7314ED728513F6903B8F2AAD159EC30DD988A53523B48626DC7DFF40178B916DD28A895F2F415218DD81D9AB7BBF740DA8371D6312706134955FE39C4028BF8515584683C8622060D8C1552F71AE04E2452B2921F8492332A4580A7B6EB5E464BD916BEF741945319ED0E1EFEB10CE52363D529DB1D1E1D81C0AE43DF2C701149B87E8B7AE191055CB430F0AFB2B9CFE788F0F9214EF777B76C3845F0C8F4BC4D5B32EE029627FBF6F8E00B1B5F7D0A9C16AE368E232E0A5D734433AC8658B04FDBCDA3BB73F62CED23CA21C675D02217EBE7D7203098221251671CB67F2F9E34CE8F7D34DBCDF67ADC9D0BEC46DD33CF5E331EA22BB3809165114E9DF844F20397B514072A9CC6FCE3D48EF97BC61476E46579422C411203FC1FD7EF837BA4B146ED2666F8ACC557E4CEBE80C19EF7D798114E38BF752C4782E964EFEAE069D65D4CECAB9CC966DCCB7BFF75CACF705B0BAD981A91C4DD216612A53EABA8ED09EFED760553A88D6FAE8E9D8BA9CDB3D9AD4432C3CD6467361658E8941EA0B2E373BF00F664A5C5154193904731AFEE48237C91FB15A73347C08F5A867B96BC75EC73CA3813A0A2550E5984AEFF016F898CFB9217F5C258D54DB02C2DCCEEC13EDE30B3AADCBE6803F89CABED28D6B9EA99D43EDE04CA6AE1DFDA670EDCECB55F384CFB65BDD0B6AFDD5645A70FE3ED7E2C21D9C9E401101CE544DC042DD3498107A8E79AB22D566F39390C2AE02C2047DB2C994C4D96301D15B38F7160661BC5233483F4F0AC000D38A25C57BB72505B6CD0D5DCA085B2D48437B8658D7DFAB0C95971282307D1AE68AEDCF89F9F9863DACF17516C74CBF4FA33D681A60561DFCC2ECA2B576BDDD8809BA9856FFD81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8
    */
    public void testCatIIISpeedVector0()
    {
        byte[] seed = Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1");
        int mlen = 33;
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] pk = Hex.decode("624563CB6E4499327172AF7F15FE1893614871835EA6F3330DD94337204F88D911FFB91B06CF2F07240203F75353906FB7EA7BCD0A4362546D94E60D32833623CD73B1D055DD1C2533CE5B81DE05C02966275D289D25134EF8577C7A489B383D3FA769DD3C1C033325034B731F7F678E5E58426F372F0F24DCEE455A8C6B0E6A68796E7B8D36317B23641E7D4EDDFA1E4F4A5012F50E70222E36527A14A559F4132F025F2C20BD3C2C023AE2E249E94D23460C80B94006CB1E38769A510911672D2E48AA5E5DD54F38746C195CA954D6A909CE33759A222399F209FBCF26641029D08D4C0C3D51D2FD7DAB2A6A3779365B06720B686F052A1FC5A54C5B4A26962F224C194096FA7048372F037D5E9772315B956881615C72EB57A0B661E9851F5BB61A17755BBFB571CDD90FFE562C4F147846407266A43AD9D063CD7710256D69FF6F07164E7A41D13E66C60614EB7F69B621F83237633E36E7F16605DC0A89A774E425323BCA551F211D4AC6110C314F39B873E48062C00255EE6E7E5BCF75A94F6DAC0E182C44532468658A2A6A9A9B72BAD7715E0765A10B520CED236A4D3343FE2A347D726D6107046877FE583F09FC50F4804CAD603810A15C7BB655400533721E4D38E020EFA64E3DA8277DAA437465033C486FCAFB5235B44C76AB27ED5E5D7BFA6CB2EF6EC7AE008AB5320CF861DB605321406ECDB56837572048175831343A1A192E7844225B6A72E66B42C98C7A3C513D2B5A71BCCC329BCF20246C241C4B5EBD5F37ED144C1CFD173F6330F78D40C9A952192201126F79EB1E444BE27E3FF500FDFA0BC27706FF2A4381454634540D3BF44CF418613C087776C940F5EC1928E1190F710909EB43EA715FBAFA3E3C140396EB516C9664A87277AAFC139D343D512C65776056A1C31104645033E03EBEC24D99837D1A427CFB7B72DDF86054744ABBD62B57A8355C8D3994F84B2A4B2CC1B731529E495F811A73414C03FC1B66BB0C58105283F42AF9B2521A5B717D8A3E8DF411A85C68F706006E8B7D1114769E2103FB2B7601DB1BC28B0355D909AAAB3702904F96BA6FCA3152C4F042596A7854B13827222DE0925A47CE40F2AF3FAE9F19395D70DBAD28DA8E7AC34F5BD36E174CA352807F2C49645B05015B389B3666A679AF7A033C8C0659600F6761263ABB6B4BC2360F29267AC82D80905502B7557A295406D605D75828565046DAAE09B12080EEAE67179D53B05A54444B4CC77C1E2DAB2D298D785B841047B5665D3C36E3181CD7AB2DD49F78633661949F585E0A18530D7940046E140D684C033915EE5DBC3A07C34A4178516F43964F0E2E04647324D26107980F68FF990C7B8C0C47F12FC1AC384520485EF061DF373B78A12D80810834AE36E5BA37397D35AA5C4625B708C51066F5C54CB1C52E0A9D3CBB772819D44A875B78AC4A65D3EA7621BE271914770B8D363CA911B8874CA1C16FDE314725B409391933DBD96B5BB013C2723E307D7D9C1C41654049204837D4074FA12B46E25D39E1EB3F74194C08CA47453E2092AF3142D06950FE14087E1A80970ADE4E7C6F6D70294F3710743854AF2D0A1776DDE166895950DDF06B2ACD11E5A248D8CE52EFF276AF9414B0DE264B315D61413EB731154CEC10F0FC230801229311566E781A57F65EBDCA4EB0CA71C62F281AD139D105108FFD5345016734F37C039377F71B36B649661F425A2CF3132CD40FF6DD5668C25808441EB86415136A55F57A1DC5991463A00BB3C67CED334979BE64A192471EC95F9F591014D607BD23585E5F0E03B33AA6E11E70F3314E7305336F5BF5E25E25D33C985B2D86BA0C41980199C506CE420F12523269D62949904174B86B383E41255F64940029094C0E9BAF76636E6E37B6711DA70ED1510E6BE35DE7C34FF8613BF3AD2358161E0E7F58696A669FD50ABEA278872C58BC3B1387F93DA26245E1DF1A35D32BB51F372F1133975E5DA27B5E112B43508D5588EE21D7A2704A9F7B1E7C62454D6D4321171C3647841D4A7BBB3B25DF019F856B7DE1652F26132C55049BF85AAEF21FDDFA03BB873761A72B389B3217C238B1EF315D4778EF4643431E1327350F240040CCF90C324370843554E9C23F6075089FB94677E85377B74FDD6A174F3B628B3F30778A629F6A5D9D8274943110095C3B763E4BC9862DD3F1441DE30256F20FE5DF629DBA55AF182C373D03D1E707253360E69455388554FC8140E97377B38024DB1C1CFAD014949552BDE132F8BC1D066166B48566C4A672B9F07A3C32399CF351AC073665FE4D52D11077CC6E823516920843FDF62FAD5D7D081B17470F16122317C3C84A7BA54B988E77952D1ECD012F90BC3C1E4152FD577E927847A8F943F5B87170A933C7DD5C8DEB4D0D02615E7B66D5CD399D0613CD111784C27A27A71516174B0D9534CFB51B6EE67D77767B818D79444F4FF519397E4C7B87EF06B0826DAE7031CFA63B835D4E2FC5035F3118463977458C6F5EB97F9CC87D77F107C28402F9D616681C108FF14C432315A368071A6F19C18108833137A4DF25764754FCF509EB6B1B118029CD7425566F4569020F5EEA7C3F5A6B0F3B62E8B615333F5FA43E15484C4F71496420D331D7FD74445816273113BBDA6DD5434DA9537EAD8479F20C2B4AE7648B9B04EAFA3A36143F0AB364552A482B766ABCB33274C832F5B3687B4802E3E369804275A0F443C5B76113E7380ADF03BF7057BAA575521D75F1EB5F774A7353A94D9BEB1BE70D174E602435FE55B8863CF5F71782B83F1AB62C222D5DDC8E04B20D5EDE755CB89E61855A160CBA7F60D708238267FE727DBDF67B8F160280A363F04B5EA62F79ECA260A0DA31B0C016DCF509A32E80A2B91176534A36B345FB2018C17540D14D569CAD14644F1135E779D360078F1D3DD4790757E035A4466B1C097751C01FC0E32D6A0C24ECD16D027441A38D26A9125F0D13039F9B2650E64C31322DE2743FB5306D057C1AE9B2051D916C0E076439070328344C970E47651B2D9E826DF12C6724347FCB3E13C61E0B79AD1E67D747C1BD3A9FF274B5EF0143126EEE3F6A72E10F75A70A77EF46B40B1A2D5A39BC2A2933DC3222787C60AC73ABBD110E73698E6A00C8BD031B626583832490B67647A3499A9431F3446DB4710E24F32F3F321E6C87427ADE28DEE2287D6120C6D633E1036A1B72067B955C3F873026E01957491B5F8D60888C13A91136FAAC24DF284668B31602C24EA4EC4BB0AF4A444C3AD22620E0B046E0CE3B28186265BD34C2EF34A74A56CFF15F230F308C6547D7252D340412F37F279B033C068961CA220A6855624EB860BEE53E8D0C492EA668A81164A87F042D9749DF8B493E4F2564D437ED53183ECB06961A09A3E30C4CDF37013A7435316DD6877CF3E2556689320CBF6B504205CDCF0B5F600EEF300669F65123B60972CA14785E4B54514143193B889D17415769413927235A24BA7D3828A844798179A44914C9F94B47701E07233E5B4050B6044270930583E5381AAD35E1C906952C1CAB143777C26208F90AAFBB6586295F168758400655DFB852BD314E5F5935735D66090521395B56CC60029B752D5D0E2B69F70043DA3A620D6A089661060B04E7402D33B77E726A49AC7C4D8EF52819E704B8B41745811774611BA3F108CD3143BE976A4A310D13320FB3C92B41C353C3725DB54B091B1E2CD9BB474360159BB615AD614399D7635465761748078FFB19828B72A1B57001CE20289E0F02BD15BB5E109FDE3E92BA495C660332337B94EC05568E4AE9065D1B0664CD4D11CA9A0BECDC7AD4041E2C044456B77E4E3C2066A33AAC412D53E66E2AFB12B946079B330BF0852D033342F2914337AE04425A02F80E1CC55C60530C08692008AFC758749726B5340B29F74A3F8F4045436293870A91746FAC025EF07C7D1D065B9D120962F87255E21E6EC73277D66B353D741F2D3ED099670C560D929D5E352D7CB5BB2A529F35FE8E514E4D72779256CBAF0B382A2E082E08294E6CC83955B2FD0ED1C65AC2355674823854F807EE707F83F42120375D4AEA21D076503CEC7DD539645B527856973BC0F06597081B7DCC48D428130A9F3230065632201FFA404FEFBB7EAAD60FA6AE57CE312CF7A51703610B6B9D0BDAD64A09D402C8D670DBEC4146816D80723CDF8E4BC6DA4CD5AA540FF510626F12FCA9485DEF65045257B5B24E896C647FD61C5D12013B3277DAD75B21243AFDA11109826B7B7F5873503323EC665D8C11E5CB441C4065FE1763BF302B21DF7FFBD021763F6031AA36369B198D761FD1FF1925583733EB325F845D754426B60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD");
        byte[] sk = Hex.decode("1C0000000A0000000F00050005001C000A00F3FF000010000A00020004000000040003000400030005000A00020004000F00FDFF0300F3FFFAFFF4FF01000E000100F9FF0B0001000C00F3FF0600F3FFFFFFFFFFF6FF0200030001000A00FEFFF6FF070000000E00E9FF090000000D00F9FF0B00FEFFF6FF02000B00FDFFF2FFF1FFF3FFEEFF0700FCFF0F0002000C0000000000F3FFF9FFF8FFFFFFF5FF010014000900EEFFFDFF0600F7FFFCFF0900090005000300F6FFFEFF06000C00FEFF06001D000400F9FFF2FF03000A00080006000200F2FF1300FFFF01000A00F9FFE9FFF5FFFFFF0100050006000C000800FCFF00000100FDFF0100F6FFF6FF0F00F8FFFDFF0000F8FF040007000B00F8FFF6FF0800F7FFFFFFF6FF02000500F7FFF9FF00000A00FEFFFFFF010004000C000900EAFF050002000F000400130006000A00FEFFFCFF1200F1FF020009000600FBFF0100FFFF0700F8FFEDFFEBFF0D00FCFF01000B00FCFF0A000B00F5FF0F00F4FFFEFF0F00E8FFFEFF0A00FAFFF6FFF8FFFBFF0C00FAFFF0FFF8FFFFFFF4FFF8FF0F000000FDFF0E00F7FF1400E9FF0A000300FDFF0000FCFF0B00FBFFF6FFF7FF0500E8FFFCFF11000D0006000600FCFFFCFF0300FAFF05000300F8FF0700F8FFFBFF0100FEFF0200F3FF13000600FFFFF1FFFAFF0A00F0FFF7FFF5FFFCFF08000E00020005001200040003001100F9FF16000B0004000300F5FF07000700FEFFF2FF08000C000000FEFFF9FFF9FF0E00F3FF0300F8FF00000700F6FFEFFF1200FEFF010010000900F5FFF0FFF8FF0C000B001000F4FFF1FF0A00EEFF1B000000F0FF0600F0FFF9FFF5FFFDFFFAFF05000400FCFFF6FF08000900F9FF0000FEFF0000F1FFF4FF1300FEFF06000100F9FF0000FCFFFEFFF4FF00000A001000000000000500F0FFF3FF1000EDFFF4FF10000D000B0002000D000300FAFFF9FF11000D00F1FFFBFF07000200F3FFFEFF0100090003000B0001000900F7FFF9FF0700FFFF000005000600FBFFF7FFF7FFFEFF0B000C000700F8FF10000A000500FAFF0300FDFF0200F3FFF3FFF4FF0A00FCFF0D001400FDFFFAFFFEFF0F000D00F0FF0200F7FF02000200020002000900ECFFF2FFF8FF07000B000C000D000900FFFFFFFF0900F1FFF9FF0E000C00F8FFF5FFFDFFFDFF07001000F9FF0F000100FDFF0A0008000400FBFF0F00F6FF0800FDFF06000F001200FEFFFFFF220000000800F0FF0F00FDFF0C000300EBFF0000F9FFF1FF01001100FDFF10000200F7FF1000F9FF0A00EDFF06000600E9FF0000FDFFFFFF12000800FFFF0C00FAFF00000F000B00F6FFF7FF04000A00FDFF0D000200F0FFF5FF0100FDFFFBFF0F000300020001000100F6FF030011000A000700F7FF1000EFFF0800F8FFF8FF0500FEFFFEFFF3FFFEFFFAFFFFFF0000F3FFF5FF0B00EDFFFDFF0B00F3FF060010000C00FDFFFDFFFCFFFBFFFDFFE3FFFCFFF8FFF3FF0F00E2FFEDFFF5FF0D000600F3FF040002000E0008000F000A00FEFFFAFFF8FF0600E9FFF4FFF6FF0600080014000600F8FF0A00FCFFFBFF14000800F6FF0300020000000B00FDFF1C00F8FF02000000F0FFFFFFFFFF0B00FCFFF8FF00000600FDFFF0FFF7FF11001500F6FFF5FF0E000B00F0FFFDFF100008000900EBFF07000A001000F6FFFEFF0C000D00FDFFF9FF0400F5FFFDFF0500FFFFFFFFFDFF0600FCFF06000300040007000A00F6FF0E0004000500020003000000FCFFF6FF1300FAFF0000FFFFFDFFFEFF0000FEFFEDFF0900FAFFF3FFFAFF0600FBFF03000D00F2FF0D001100050003000800FCFF1200FBFF0C000B00F1FF0E0009000600F5FFFCFFF2FFFAFFF8FF03000000FFFF0000F0FF0800FCFF0E000700120004000600EDFFF4FF0800F1FFEDFF040004000400F6FFF9FFFBFFFCFF0400F6FF0500FCFF0B000100F2FF0D00F1FF070002000700F6FF0200FBFFE6FF0C00FDFF0600F2FF130010000700F2FFF0FFF9FFFEFF05000600FDFFECFF0100060007000100FEFF05000500FFFFFFFFFFFF0B00F3FF00000C000E00F1FF1100F9FFF8FFFBFF0500F2FFFCFF00000700FBFFFAFF0800F9FFFDFFFAFFFDFFF0FF1000F6FFFCFFFBFF0500F6FFF8FF07000600F7FFECFF0000FAFF0B00F3FF0000FBFFFBFFF9FF0000F9FF1500FCFF1200F9FFF7FFFBFF0100F3FF1400FEFFFCFF0500FEFFF7FFF7FF0100FAFF0D00FFFFF8FF0600F5FF0400FEFFFFFFFAFF09000100F9FFF3FF000005000100020004001300F1FF0D000600FAFFF6FFECFFFBFF120010000F000A0001000600F9FFFBFF15000400F8FFF9FF06000E000700FEFF0E00FDFFFFFFF2FFF2FFFEFFF5FFFBFF0000010007000000FEFF00001000FDFF0F000700030010001200FDFFEFFF0000030004000300020009000300FDFF16000C00060005000000F0FFF1FFFAFFFBFFFFFFFAFFFDFFF8FFF8FFFCFFF9FF0600F7FF0300FAFF01000B000D00FFFF07000A00FFFFF8FF0D00F7FFFEFFF8FFF3FFFFFF180014000100000002000300FCFF01000D000500FCFFFCFF03000C00F2FFFCFFFDFF0C00FDFFF3FFFFFFFCFF03000300170006000E00FBFFE6FFE8FF060003000800FFFF12000100FDFFFEFFFDFFFBFF10000400F2FF160000001000F0FF0300F3FFFBFFE6FF03000A000100120000000600FAFF05000F00EDFFF6FF060001000100FCFFFCFF1000F9FFF3FFF8FFF8FF05000A00EEFF0700FEFF0500F7FF0D0012000A000000FDFF0F00F6FF0000FBFFFBFF03000B00F0FF0400FEFFF4FFFDFFF5FF04001000F9FF1B00E5FF07000E00F2FF0E0013000100FAFF03000200FBFF0C0002001900E5FFFEFF090001000300F7FFF3FFFCFFFBFF0500FEFF00000D00FEFFFBFFF6FF0000F7FF03000D00F3FF0D00FDFF1200F3FFFAFF01001D00F7FF0800FDFF00000200060008000E00F2FFFFFF0100F0FF0C000100E2FF0D00F9FFE8FFF7FFF6FFFCFF0000FCFF0000FFFF10000700FCFFFAFF0B00F8FF0000FFFFFEFF0400FCFFFEFFFCFFF3FF04001A000700F5FF02000500F9FF0200F4FF0C0002000800F1FFF7FFFEFFF9FFFFFF0300FBFFF6FF070000000400F0FF09000500F1FFF8FF010003000900F4FF1100FFFF0300FAFF0800F6FF0200FDFF0100F8FF100007000F00010002000600F4FFFFFFF6FFFEFFF8FF0D000300FAFF04000B00FEFF0C000300060001001200FCFF000005001100FCFF07000400F5FFFBFFF9FFE8FF080012000000FFFF020000000D00EAFF0700FAFF1000F5FF06000300F7FFFEFFFAFFFAFF0500FDFF0800FBFFFDFFF9FFF6FFF5FF08000E00FFFF1300F9FFEAFF0F000600FFFF0700F5FF03000A00030000000100EAFF0C00FDFF00000700F3FF0A000200F9FF01000000020006000C00F6FFFBFFEDFFF7FFF6FF0D00F3FF0B00F9FF01000500F9FFFBFF0C00F6FF030015000200F2FFEEFF0700FEFFEEFF11000000F4FFFDFF0300080002000000E8FF0600FEFF1000F3FFE7FF01000F00FDFF0600E8FFF6FF0B00180007000B000C0008000200EBFF0A000700FFFF0800000002000D00060006000500FBFF060013000300FFFF03000F00FEFF01000A000900F6FFF4FF070004000400FAFFF1FF0600FFFF00000000FFFFF0FF0C0004000A00FAFFF8FFF5FF00000800FAFF0200FDFF1000F1FF0D000400FFFFF3FFFDFF040000000100F8FF040001000400F9FF030003000100FEFF10000000E7FF0200FAFF0200EAFFFAFF0400ECFFFFFFF9FFF8FF13000A0006000A00FAFF030005000000FAFF0700FBFF0500FFFFFBFFFEFFE9FFF3FFFDFF020004000500EBFF0400FFFF0200F7FFF8FF07000500E0FF0D00E8FF1300F2FF01000D00F8FFFFFF0900F8FF0C00F9FFFCFF0B00F5FFF4FFF0FF1200EDFF0000FFFF0A00FBFFF7FF02000B001100F7FF1600090006000A000300F5FF0500F5FFF8FF02000400EAFFFFFFF5FFF2FF0600FAFFFDFFF6FF0300FFFFF5FF0100F0FF02000400FEFFF4FF0100F8FF090007000100EFFF1400F6FF0D00F1FFFFFF00000200FCFF01000600F2FF06000100FDFFF4FF01000D0006000800FFFFFFFFF8FFEBFFFFFF020006000100F7FF01000000F8FF0500F3FF01000500FEFFFFFF02000200FFFF0900E8FF0A000800F6FF0300EBFFFAFF0000F1FF0600FCFFF8FFFDFF03000100FBFFFAFF0800F8FFFDFF0A00F5FFFDFF0700FCFFFFFF0000F7FF0D0008000300FDFFFBFF00001000FAFF07000A00F0FF010004000500050000000200F9FFFAFF0300FEFFF5FF06000100F1FF0F000200F9FF0400FEFFF8FF0400F5FF070007000A00FBFF1600FAFFFDFFF9FFFAFF150003000C000200EFFFF0FFFFFFF4FF0200FAFFF4FF0B00FDFF02001400FEFF00000F00FFFF0600EAFF0500EFFFF4FF0700F4FFF7FFF4FFF0FFF8FF0B00F9FF1300F2FFF6FFEEFF0400FCFFF7FF0400FBFF16001500F8FF03000D000100E9FFF5FFFFFFF9FF0100FEFF130001000500FAFFF5FF07000400070003000F00F5FF00000A000F000600F8FFF0FFFDFFFBFF0200F5FFF6FF06000400F4FF0E000B00090005000D00F5FFFCFFFDFF0700FDFF06000500FEFF0600F2FF0A000A0004000A000900FFFF0100F5FFF8FFFCFFF4FFFCFF06000600F6FFFFFF0100FFFF05000600F7FF010008000800FAFF0500FFFF1400F9FFFDFF0200ECFF0000FDFF0C000700F6FF13000000FEFFEAFFFBFF0300ECFFFAFF0200EAFF0C00FFFFF8FF0300EAFFFAFF0D00ECFF01000300FAFF05000400F1FFF9FF0D00F3FFF5FF0800F8FFFFFF0500FCFFF4FFFEFFFFFF0700FCFFF5FF0900FDFFEEFF0C00E6FF0000F2FFF4FF0600FBFF1100FEFF1400F4FF080001001A00FDFF0000FEFF0400F4FFF3FFFDFFFAFFFEFFFFFFF5FFFFFF1200FDFF0E00FEFFFEFF0B00FAFFFBFF00000300FBFFF5FF0A00F9FF1900F2FF0700FCFF0B00FDFFFAFF0600FBFFFCFF06000900FEFF0700F3FFF8FFF2FF020001001200FEFF090005000D0008000900F9FFF7FF030001000200F0FFFDFFF9FF0700F7FF0A00F8FF07000500020000000500FDFF0E00FCFFFCFFFDFFFEFF0E000500FDFFF3FF00000A000700F3FFFAFFF4FFECFF0E00F9FFFBFFF6FF04000400EDFFF2FF09000B000F0004000A00FFFF0C000600FDFF17000D00F4FF08000800F7FFFFFFFDFF02000300F8FFF6FFF5FF13000B000D00EEFFECFF0F00EAFFF7FF0400EDFF06000E00FEFFF8FF01000700140004000C00FBFFFAFF0800FDFF060002001600F9FFF9FF0900FBFF0600F8FFF9FFF2FFFAFF09000100F8FFEAFF10000B00EEFF0300F9FFFFFF00000F001700F7FFF3FFF8FFFCFF0D0001001000FDFFF3FF0000F4FFFBFF020010000A000300F2FF03000A0003000C00F4FFFCFF07000000FAFFF5FF0F00FDFFF6FF00000B0003000300F9FF010006000D000700FEFFFDFFEEFF0200F0FF0900EBFFECFF090000000F00F8FFF5FFFFFFEEFF0700F7FFF1FF08000300FCFF0C00F5FFFDFF0000F8FF0300F8FF0900F9FF010004000800FCFF0B00F8FF0700F5FF0000FCFF1600FDFFEBFFF9FF07000600F6FFF7FFFFFF0300F2FF0700F3FF07000600FEFFF6FF04000A00F9FF02000400F6FFFDFFFDFF05000B00FBFF05000900080007000E000300F3FFFAFFECFF050010000800FCFF0000F6FFF0FF0300EDFF0800FBFFECFF00001400F1FF1200E0FFFFFF0400FEFF00000E0001001200F9FFF8FFF2FF0000F4FF03000000FBFFF6FFFEFFF6FFF4FFF8FF01001800FAFFF4FFFCFF03000700B60E7FB7708849FEDB54F41A68314805A5C0766ACC9F338A46B29EAAC00087AD394D1695059DFF40AE256C5D5EDABFB69F5F40F37A588F50532CA408A8168AB1");
        int smlen = 2881;
        byte[] sm = Hex.decode("14CA42B0BCFF0A0DB3E20897E1A6DF1DF2A9BDF34F73D8E42B60706EE8F0C60D8430CA12F0E11E7B79CBD89743DF155A2CF70DB62BF45C1F2D16B37341DF548E93F5776C9D955E3A58AB6711339BC4DF1006B1A8FC60F2B804719C5CFD04499D3524ECE1C008AC586A7833852D3DCF9FEBA864C2A477E755FDE7271B16AB2313397142DA6EB6B8CDB65267BB3FF3E383611A4C54FDA66A8D60C7613BB9130E87E5A105F5055ABECD33B5CD4D26CFC222F7C8BCD667ED167074F620D940F12CD11D76131F76B6CA32750819246EC386788DB1FE466C855FE4AECA477AD18C2DE1FA871A572042864F7873EE11B69CC2FD244F2C9103E6D71CA34139A429F6F052CC1990A9ECC0DAF1F11FF0DB092F166194A291A278E73275AD809D20E3CD7D74A3F37A61CFD4CBAF58AFB36C11D658CF2619E2BF773D9379ABFB89E608DCC7F94E2A8E664734F8D89A3BECD865E76C05E236B1F6365F8063314835D38240DEEE166D9413D037912B0918314CAB4490021BD939BF291C992A67EE087FCEA6F1CD012FBD933B56E0B307168115DE30010B802799BF3333F58D9E19505C2B041F546FD8DA5488AE1F149D7205D32DBA7043B28059A2C3C927724DE0D7ABC407E7280E7CA32BB441D4759A0BC1D30C20042DC0807208FAE857A7ABE6D2AF45B5241423BCB45E2F17D6BAA08A1DDC123144B02A0D5BC28CA266E4B615846BA23D540ABB951A3C5E5C1FD55D05CAEB2E0EC7483D8B2865474ADB37AC484543DEB10B3BD62490D0DC5AEE4216FE0A9F06BD8E89A216576399BD18AD4D63D7BB5DA8DDAD27BDEDB4DCAA5BD7B49434BCA3ED398BF9FD5D16FF07479E49A2778E58AA0D7687D15A9D4CC4089DA0A8269140A28099BD8AE802FEC2E38DE976971F9037AB8BB8C9C3E27D8EAB169F5D8F4B1BECCBF937CA0D926E83BC14CB49762877E667751F29ACAAB622A9FA56646854592B548074385F61103DE9B4589CFF79233C77EAF55362C083256F7FFFBCC82148C2EE226108DF2AEA520ADC4DCCAFE059F735DFAD95CE1F1B91C2CBD878B7526A15B3A934325733C8B45D79EFFB9746FD2E0318B3371C5316B9D946EAA2CA4975C78B183B6A75CC48DF776A714999EBDCCACA5C2C7BC1CE12290B084728356ABCFACA40D4830F6354CD9545FF120F99AC686F6211D8A4DE0AC426BABFBDE2398F272EA688920D682B9A31500854752A9C44A3AF2A65BD52215F8552B4AA9705A2FD043CE5C89311587F400B618F93C04280543AF730A0E16FC4DF0AB47A0F9C320FEB48A1849BE46D588FB677CF87BA62BB51CD21E627D28083452B9CCA286AFA5D0CF67FAEDCA84819A1DD5A6DAE249C95E2B6ED0F903588F0C20DF9E90E990E25975DCEF53BDCCEF15780952B508504C52CBF9099165D9AFFBC94F33CC72C63454AD8E4BF1BA8DB701DDBA7F893DD3D05300D028789F3C3D062DFE0830A07340E5C3EA9DCC5D3798F28647EE7003B6C65C5E71722E9C12BCA140E266060A862F8AA12C7F43C8A30CC10BA9E1B118D8A6C6F647D94D34E3E163C1BC7EBA6EC97E52E7EED3E082EFD9B60E3BAA045905C4A1068EA8797D9C19FC3F121DB2A1714020B4AE6526423BD8AF705D342629E8DE7A77CEDACB61222105B80BAF59D285455831B183897CA81F93E08703D2F086C593FA6C583A383A7A9DFC5A890FDD7739C9B3797709CED9FA93AD4B0572FB5192FFAFBADB6725A13FA2C7C0F62E6AE1B89C094B14165AD00554C472BEFF44FD5AB60763F02A0A930C360B7F220A0039684A41AB45A18262C9BEA2BA7B5AFB7462F4EB2882572374F8B5C3FE34802A21F3EC37996593B707D7189C75547B5BD9A4D120B3FB27E7D505378FAF91E2F62333C06A2411CD70FA5D269A8509CE0A11E12D69B04D9B242116D1256E0F863081A3AC0C4FBF2525CB2D985FA88E7F270662C97BE3AA27FD19FF4F7973C107FED99693135D2C9536A90FC0BE1C3CD2BBAF34F7655F4167D41FA71E3331C0C898003746AFA42D5C9027868338E42819C18F6702D7E24B9F418E69737FD28F3F6E261EB7F72DF5E1DF899790CDCE2C965BABC93419AED0C83458C43806819FA1311EE317D2C49BD341F6442284989C4E71C577305489DF1D30936493700948C1F7590719948263BAD1812077391323AE1B8B01BE3D68E7F41C1CF1D2556252E99400430ACDDA6901674B63C2265A843B71A85C2E33A40ACA4C40CB0F4EF3E9FC83FAFF3010BD6C97F17B26519F588F35AE75F5A5E4651D8CC56262685F4230B392993CA0765A2CC5D986A945C82C251554B421DBF546D4D7505C2E2FBB5F9721B5ADAA8F389BEF5624F49CDE0E317A11433CD49F9FD0A0BD1BAC539CDF2579FD5A248BCC36231031C101431E09F5AF0E763E6437E5D8068789E10014F42BC3011472D9530E0D5BAA97D03F03A69FF197C448C3081A5F2B778025ECF944D67DE0565618FD89B935F397D620239BD4AF85528AD4753F4E1E7EF8BFBB357D9876E29DE758653E2CA9D083896921D29BE64890142869BFE62CF364465434DC0691408635E3D1991277401C8569AF2F781AEAF0776E4C737FFDD78C41C95957EB756517F3136A9855E6829909953C8C76D5C2983F4862BE27EAA83E0D64F135BCCC553157A5961003DB4BB694AA020F39A947BEE927F0752BD185716A80A976231646E1EAA7B581D8C42531E0442F73FE65ADBA383E57A7995B1FD520643DAF9587FF2600C30FDAD6E2F652D71C7FF7EF41BDF7E4BA9034E0BD6F7F239CFC4485ADA2D84979503F8A91C0ADD6DF19A0B6B00790306F534DED80C8CAFC02160B9C9EA4A93F50FCE66CB2CA041EFD4B469641A7AED232C9593930AB05D4A67C46224E40806EF1DDC951BF1D7D8FF7A0A689EB88887F42D891010D4FF4A7839C3CD9D62B6B27EAADE4A54094BCAA1D114172B4036C1CDE268F43764126FE3E20EF9881BBDEDDF51BE346131DF432AC1E177A5F0CC52B03688FA40D6E033D5ACCC64EBF201519713117329A50C86B9F971AC58C001FF28A51B3FC06F3796986C30D01EEE4D5A607E0246657FD3CA4560AECC4D40AF2FDC07150CB0AB8E40C02FB7A762D3D7976F9E13FA1B953E17A85BDB74FC81F3BB8B2B01541F44C3ED8C3A1630DF1549DA0EEE4F40C49C7314ED728513F6903B8F2AAD159EC30DD988A53523B48626DC7DFF40178B916DD28A895F2F415218DD81D9AB7BBF740DA8371D6312706134955FE39C4028BF8515584683C8622060D8C1552F71AE04E2452B2921F8492332A4580A7B6EB5E464BD916BEF741945319ED0E1EFEB10CE52363D529DB1D1E1D81C0AE43DF2C701149B87E8B7AE191055CB430F0AFB2B9CFE788F0F9214EF777B76C3845F0C8F4BC4D5B32EE029627FBF6F8E00B1B5F7D0A9C16AE368E232E0A5D734433AC8658B04FDBCDA3BB73F62CED23CA21C675D02217EBE7D7203098221251671CB67F2F9E34CE8F7D34DBCDF67ADC9D0BEC46DD33CF5E331EA22BB3809165114E9DF844F20397B514072A9CC6FCE3D48EF97BC61476E46579422C411203FC1FD7EF837BA4B146ED2666F8ACC557E4CEBE80C19EF7D798114E38BF752C4782E964EFEAE069D65D4CECAB9CC966DCCB7BFF75CACF705B0BAD981A91C4DD216612A53EABA8ED09EFED760553A88D6FAE8E9D8BA9CDB3D9AD4432C3CD6467361658E8941EA0B2E373BF00F664A5C5154193904731AFEE48237C91FB15A73347C08F5A867B96BC75EC73CA3813A0A2550E5984AEFF016F898CFB9217F5C258D54DB02C2DCCEEC13EDE30B3AADCBE6803F89CABED28D6B9EA99D43EDE04CA6AE1DFDA670EDCECB55F384CFB65BDD0B6AFDD5645A70FE3ED7E2C21D9C9E401101CE544DC042DD3498107A8E79AB22D566F39390C2AE02C2047DB2C994C4D96301D15B38F7160661BC5233483F4F0AC000D38A25C57BB72505B6CD0D5DCA085B2D48437B8658D7DFAB0C95971282307D1AE68AEDCF89F9F9863DACF17516C74CBF4FA33D681A60561DFCC2ECA2B576BDDD8809BA9856FFD81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");

        byte[] sig = new byte[4000];
        int[] sigL = new int[1];
        QTESLA.signingIIISpeed(sig, 0, sigL, msg, 0, msg.length, sk, QTESLASecureRandomFactory.getFixed(seed, 256));

        assertTrue(Arrays.equals(sm, Arrays.copyOfRange(sig, 0, sigL[0])));
        int status = QTESLA.verifyingIIISpeed(msg, 0, new int[]{msg.length}, sig, 0, sigL[0], pk);
        assertEquals(0, status);
    }

    /*
    # qTesla-p-I

    count = 0
    seed = 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1
    mlen = 33
    msg = D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8
    pk = EA7347183E405433EFF49CB63A9E736B39A86CB67125110ADF35536A44940BAAFAFAB19FCA5B8F11CF72F7199E051A9A607D75D093FD1DD7F7038F4EBB172F9549747FBEDB2EDCF24BD007610C111E032C1852E4A92A8EA33057606200B17C785B8BB0B2A08DBE93185F3B931371B256CEF871167BD21876B1D62FEF325BE2D0A716A6ACC3D3CCF516DCB267093035DA9359E8A698C3946D88200E9033AFA1E87A30A7A626056F944010A5CFD972399AB7C52FC0E87D255A589EE0D3E14C4BABCD5CA50A561E71428C98B72D413B117F827F0FB557559FB16FF4EBC73C539C43040ACD34FD676C1868F59F84AA1398A61E99C090A8E1A7C5A19CC23CD21BE2B9CA6E23F6A7E05E3E69AD6516A085D2C58FFA0883EEC30C04B648414C3D4DF1C87AE2C5F06CCEE989ABE455ADCABB6C84FD17D8A9D1158E91C4A2598A153595B4C2F0921ED24A49F758CCF7FC170B3959B2F26791572ED54AA80368D5800025F6138B595C7D8B6B8AB5F340399AAE0C821C4B0A3D677B530227B33525D9A48AEE067368A81305FFCB2E8615035CD56203EBBED33B5B1F5B575F920A627A770F0644610094EDA55FDB7C7BB7A723DFD4662780ADA0BA214D91AAA9C832FC29DB0B59EC14F4681FF05B6E5D087E91F891416CF8150604DF06BC7901B6ED33A5967E91799BAF9E903EB7967D393772F7C170D4ACFA36AA333BBE00AA2A40FB3A8D1EBE9D88926207677BC27BFEA91ACF49E009725D1CC9CA4566FDFEB762F4DADA0ED3323A5D48FE9D19B0B60809DE4182EBAAD5113019C9FB4F9216DAF2574EDE87B41E14590AF2B6E71950881DF07B5303C13EDD4D516FB059C7B7F1DC5CE6BEF6D2ABB65BC6B2D5A0BD555914BCF21FAB87D417F66C87C0F007DFC6DD6FDF22DB646F887037227A20AA1CDACE683FB7F9E4D4959FD9D361C073D22DBD89C4BA32CA1B9BA803BB8EAAE6495269030C24C08C8844427CA72F321303F112EAD94E3823D354730EF3CB2F561728227BDC2321FAAD7ED43B54603F94CDC42A06CFED0F44CF34F357CE3019973988AE101746513DC8054EE0464A8FA8654A724277C511D0EC41EA009F837116E9B51C9491E0D6E7D4796BBB84E854C6097156F8A77CC8913F3D05E8A478667071AC757557FA30958314499E377262C79EE8EF891201A7E13710F4F6B252EF970B9B71A050681CFB0B2147D6108F7415A55FF1E70CEEF738272B8EAFAE18907E6D64F6729F5EDA8FE2E779554B41846521DC530C3CFD36A60EC145D0FDB6AA61800A534D9853A6B364F48F54558DE0132A39B4E5BC1ABC5BF376A5BC02439498B4C21FA9C64A72A9A55E51078724BD235E3D75D8AA12D4186C2D8E65CFF70E93211D996556B67A0231CF46E80B1F258C8FADD5662BB8D23B84C8C5EEB2612B0BC2A7B432B321AF2253AB16EBA0D24CCBEBC6D9DD83DF22DEB57EDDE1677CA943FAEC92E560E58FA0009F7DC4673722DF8FD38299FBB34FB61239611DC97A6D24B1ECB4CD6DF5EC4658304D34EEC218A55876A338BFF8BB2470B7F8275DE34863B27D5DA1AFAC7A24039DC53ECB99079E0D7DA4E3A5632D97AB065D11EF17BED267CC88EAC42A9A7C119D1211724D0E3A68A54A6220CE471EC3CF49FA21B4541FBD0CB8257B6396E4F2CFC8BD0756D4C0703F5B5CD656268E98C043CE4ECF34A377B8846817DEB391CACC4050E797873A1F88E974106471944D8A2A25E80FD54024C95A2B5E496FFA076F7930EA29AED839AA58954E5228F2EF55420C048E3AD1EA894EBBD4851AAF0A8C99CACA3057C486A0E0C2F1763B4F3440C87BAA44705F563EFA435FC68D165D0544902A3FB3B84FA8D74001F4C314F106D4AF37BFC54191598D2A28869F46D76B68D72D5FF91AC1F0E31F556F2030C816EBADFC9F72A55B9CB5F9D4C881DDF35448140025651B9D0EAD4C59845119C8D3FDBFEB219142C3C6820032BFA7644DF7E7D2783E27E8786053B02EC68EB4CE6DF29BF9FA8B1BA2E8A6015419D0A3D491E884C4059184B9C6E7BC35908EA60BAF531EFEC1D2379389291BC5E17A31F1ADBB5AC09EB3EB845F3044D31706543F063644F6D5E7D6DC686750134C9811B4BC230EB1EF7E8B214D82E444B0D3EC367D5D5D0912B5D6EF40F3D36302D726D9A988C208567067B5C5D9521EAD36A23C8E9C956443141FF78569A8E0D9EA2BD815A3A9746CF4F1CE603E0894529948D873A67C8F244DC10D9B706E127D508C0A814E9132E1AAD7DEC1BFFFCBB98EC65F1BDD6A8A03DD08256EE50869EA3509C2797184BACAD88798492F8958327D5F1071A90F0698EEA7676B4A86DA0ECDF4F3EB5553599514CA78773CBDFC9F091124E62181C637793A98E02847143ADC41CB3987334566846E4D201CE926D23AD382CA2E5E153342E7AE8CDE9FDD76148251F09C7290ABCCA43037BEE98947BD673B1FE28C0951298BDC45317AF1896D0E4B91BDC2AC886D18DB6008D8565FDE10D5D87322A5777C66A910FA2710F83BF61B396E9F82C2D68FF4B524616261D444F7AE05B57B4A86E23C6B759504812C305906ADFB5C900360E79EF73F0BF0233F5181608ADD756B40EA15DBA12B4AF06B1952F3ACE3908F6AE4625202DB122B5087E7808963426B23CE9B85260C924A677812EFD1A55E08CE2ED673BA2D6DAC7222A336CA6F0A05996DA63269EC3F5BA62E24593472AD7818C1800DB5A727D0C8A492EEEB22AB981CB688853751DA34F34A6723591909E2197D1A4D065737AE476831C19F92953CB7F889EBAC46A31D247A9108B3450A8F3B4437D0208B0D21558AF4E31DA942CEA458DD88A605DBCF1136A2E47897CE17030984952ABC600B8F30292DA4274593CC71497E9BCEB9CF84986E4C2047BE8821F406F1E000E18F050E3DD8E7F3FBC923D0830D1A84DB2B08F8E0623E3480A20A48E20A2F0F37E144CA58283A97A20E12DBE95327D69CAE4234381457CBA8FA237F88C466E8DAA72BF89E9517C28BBF4744D3214EE8B3263DD64C06C78AD9D0CC42517048DAF4AAD330BE626F23338FB6819329D11C10D928C11FDB96BC2A00C269D7839DEF20580F82F7D9B48CE896C45F568A6B38F123BE6B0690722DE463690EAF8C8336F829D4D48E001A7DB63470A39430E6929BEA765B3E8127C4213658C6938CE5D566546528D60C8B938196BE5B3378755580816C8120803A46084BA1980D9F129D47462874022454DA5E040456B2F406218E315149D1B79F7115C81B7F98E1A1A3F61C96138152C0A1B3E124E630902E6033742F7C74946B5D2B4D08DFDFD29FF7479C313FE889B1CCDA14904E0CADD9963F21E564EC09202A1B263440E9CD8EF3C25F2F5D58D278DF530F3940B79D7AAD270497DB9EAB1536C2F59549CFED6E5F4A9AC9907E586357C7CA305170B622CC3A571E45E1891690EF11C1BE641A2E4169C2D037EF6130C7C70104D4BF844CDBBB6C805A9B210B853417F6E2E4C85CF4D6053DDCC94122D5F2CEBAB51E0232E0DE9B19FC5CE0B78D569884F4F2E33BC4B1BF6A370B7F2E317670A136FADB81873EA13178798FA48E9E1123DC5B31D88301054F0D964C3939C0CF1201DBE5B43C1CA9E95698AD80AF3EE0633F973665468039EB73C63FAC0E70DAFD81F17492B022E98C61950A5D50846FB707CB7CDC7C51BA2EB7B2648C22BDF81C17A8EBEAA351C396E2BAA27D014F16388F215C5DD5CF53D077A4BECD1F57D0BCE1CC415C52052934179366443F80EC1D2266A80EF5A4CC09BA0E2301219CB9DCD88F30639B0A5363CEC3847CDC0207FE65B260EC1A4B5D40E3870EBFC1C02F2F4591A4D666E2754A523D9F1A5E79B69FE553B8405E338E4587EE2D03336EC2675A95AE9A35D9FA2D91FF934D30D3FFE4C7635C2DDD2FBF852859AA91EF913263070E238AF16D140A470A8A4A2A38720BD667EEB08E3436EFC4B74A9CC9725A7F0ED64B55B084E8EA7EBD1ABCB8A21E03CEB0F9CE5E3445F226B5797613C030F4ED5C445DFDF886AA6D7230962548B53CB551F3E6CB2FFF4799AE47E2293AD0FB30AD70417BB9F12CE5E7CBF9835B593F8659D98840D5F93FD67E0C48268F770E13726687DDDF8FD41D5B729B1B800892BC46D46154449A230139E80B59BC827B7638E1DDB20C366583892B8FC40E5B038772E4055BB625996969CFBCD95374F5966B5CCCDE8EC98CA3170A43417A941FD1CD00348E12465568A3DBD075A08D282D84401553B658FC64E233C5D3E5BC383606C737A3581CD38CC7BC362A7E79D46CBAAC8A76C2093879E2EAD94A9E9CA4703ED884E56FCA8B4EFF34BA4A002C31C2A15258879610551BCDDC393C0E1E4CDB543BF3273C4AA541D107D3EAE2DC643993779E15D214B7FC318970FCC976C344ED4D147BC226D1F193A7026E949778E67B395B111F943D44CA98E5A4EED33272B13986D48902692325FF749F546A9E6674FD6B8F67901725B8A0543C81AAB10228ACF3AB5F7EB2CA870DB85A69E4E63153DA7F5F8D8CBCB254E2CF003E04362F4E94C6EAB08F53200158B8F3CC8E8333E2EC6D5A4DBB607D6B180D45CBF05A7A9A60FE9ABD902A2EF248B9CA9C516D5871C88AF24C5376A4B3DA19B96E454DC969BD4DFA81170C627A2F6A0F0D3D9C65BB03DC24C470944CE27E108F3402062614F878088945A201EAAE842C20AC99D743E650DAAC82970709EC2D1A6CD5A49A36C434496ED6F5E1558C0580B61312F63C195C4FE5CBF43BD8C3B189FD5F0766041E8DCF336C550EB66C4C0F2B9AA420F260D1458448D4AA5CCBE22340058D60BB0C7B21231ECB2AEB51CFAADD4D10B683248F8ED6D2B61D4D5C66EDA259B30101F71F1C19A60C987019F236C35259E7C39DE6709806D24BCACA2897CEC81BAF76205A488E6920A3792A0B906BA71B9B5095C85F6FC368ED0214F026A6342359CF05C768EF34F1CA5E1F30E76D57ABEF961EA7097B82F8B81B9219D9D5EAA4143F23FB4812CC8E8AA5C089F35E697F1FAE5F45B725560892EA7A99F9C8AFAB2ED9033262780AA97DFD88B0E810EF4ED113494B8B4556C46C287BED57E7F60E0FE2A93938C25F910ECCAAE27293243956F9D8E14F08FC0D6CF1E1F43E5FE5FEA8A1156C94DC94EAC01D61A47966CB7819AC17E8A6C9CB361F4B13DD43A61156D378EC627B0E7414A29BA7CB0300FF1EFA20CDC4A2D2CE25C628B5A6109F4542C23B6E2D3E27C808AD2B706399C23E392D350BF6D7C02F0926D9E40B2CDFB98971AA06DBE751854D8DA832824A68CDD67ADF855541F9B1004B48E921E69FFA23271AB2AC3F2F170035553B8A8A00C8C248E2D8A763A4C95A709A38C56622FB8F4E3694D5B923A2CD8E538F113E8A08DCF19655C3E5818586C334D4E09BC4703573D24DC77804B24EABCF3841F372CECC9954A56ECFCEE60431CB015C84FC6B61C11E15B5899A81D07EA453DE77551070EA5B484FD937CF5C3BA7E8380D38B474379AD0211E35281A4FF6A2291188853439D472E476B2E93FA44F707FB7BE136CA62AB3E9F02D2B864EE25B357621AC7C08AFFBE1B7D6C184428E7A59C0D5365E21DEA5328B183D540DA779A38CDF2B55B710A3B8181A853D04482829AA656C77B94DDEE372B77CAC11D8781F3C554D54C3A74583E630C3FF32063672E903DD4382A85E577043B0ED269D9A5523E1DD32974640BE7AE82E94A13906B19DC3521F1950E1A5FF054C593D413446B3646E738636878C5D2FC64BD602F7D731F7CFCBC297A979A4B2922972EFC28BFF3EA51CA87B504AB011FDECF3344216DC8C99921BBED2E697203B4E994E4F88CCD491329A4E15BA8D757E6804C0F13C0D37D9064B1648C435229CBA60E53A764D9CD4047FED34209F16005BA94D07E0C12E1C27C38406181C347096472AB7145FE3B24069CE1BAF274408FA690391B73CFA1CA56ECD497D5770E01BBB2B8BD424873CFDD8B3D1A28AEDD7DC4172A5489194529A880F1115AFEFF020224FFC7F1B199D7408D888F765CA6F75F4F000508A9707BEEC60E144572D8E13FEE95956968628003148332ECF06136A9504E4DFDAC8BB6BD4A1267809478E43D693A6E8ED6C104A05908A37C75087BDB5954CC6D0FABAA841B86F5DB6473134015F75D28CEC95E0CB87B0A687D37A704B9B7EA7BB9DEB76BA63DEEB2F0ACD7C1140AD02A7FF1422B3FB8CED19962738FFE453F561E908519451F884A015003E65D98D81A61CD8FD7DA2AD14BB4EB2E7FA80E28BFF59DCD12D9065B9549641FE599F41E582E1821C2CCAC0C4DBA6159E0BE7F0BB2847F2299EE23010B7114925C4AC8C2BBA87EDF43694A1824B08745686EA845C02A7BCE2D98F973D49500E79F563B8F0DC054C5F1D30E4826093BB5944D7095E662CF008628278D85C869A69B634AEA2735D4AD59CE0DAB044D6D2F94004A2B9C1591F2FB1F7F88ACD7F5AB252B7E72922287E4473014D26CC43AA3D631B6A0E98444AA8E31186F8A7922C3A6F911A3AD2F03F4372F143F89AF8B758DF20FF26255C31E5E8C3DA86816318AEE2DAAD6655A36CC36A375EDBDFDA241BE8DE13080163D59E6221A90299AF4D070D6658D8EEAA88553DDC03778EF9872DCAF19114F8D6D8B0C13ACB647C49FB0102D79A388148C52BAE905C9D787015463125B336193B495F16C8E35F2146F496EBF780C859EDFD95773B6A19E9E5E582220D2DADD167379F632D8AAD683CC9B1EAA77F141DA66B6F002339C6DAF929F67A57B14191A2829CC55EC5A940716F09FC5A9B08C23881D956A36E2BADFC84E5427A866E2E76B476B2A0DE1B9CD3FB6AE156C74A7689B08D25DCA0AEC4191E33CC091B181F8C67BFE2A5DD82EDFC226D49A1AC7BE8936C27DE05D243209276003A63875B43E20BDBF79D8CA81F7AC56AE94EF46CB3FC9BE5473DC0C9715BF8DAC744D093350B4C75560CB1C099681F0E440FD682A387E7AA70B3F335546F026C5351440A5D61E3C83BF96F07A46DE986A21F7E5A2EB0A28AAC2087C3896E933B708B4A44234EA8AE48946C6A10213521A553A020D7C9991CC31526A4E94D210F97E4216BD88504779F3EA21D52C2A205FA47CCD2405D26F411A9312D561D4CBCA0763311A0EBA45FA48CCE15C80419FE5CA04BF416395D25265280E0382BFDCC868C719874DDC795329E07CBF5C8FE83A3CCC4DDA4B31B15702AEBF561F53634315EC8B1A5423470DAB46963403E10EEC58E9E1C5C4DCB3935B518D4623E6C8C68A4FB13B492B155E06EE3D16BCE6C3E79AC891742AF3B8D01767542EB6B7BC8EC71579136ADE2BC39FD07AFA207C3D3012229267DCDF6CC3E9DB25AD378F836763BC517DDA13CD264C90983D73E2C9E2703740DB4C38773B49625967933F41FF0220F40C976385367675005FE20AECB7FBC1EF5C71255BEFE4A39CE59ADA83F148C5E4383BC65F0440A1F5826537EE40CD55862E7239ABFAA1D458F64F7423668EFE8E1E979B34EE18A71F82BD1975E09EE1613D9F45870B98B9855D28F3C00DA8B9740F50E0C51E506DF1C7C804FBD2A1DD912DEE604B2080069AFC5095D23D726D94552EB7986C14C86ADB5A1306C6B074F5D3605A6C2189C4D22E1C8795FDB77803C60E3CC04B82A021BB89BE2E3C45AC5B914966D4A3DDCBC32A760ED7BA6291B6C728F13AC684A6B6F0ECBEFC06B54249FDB3633A786E0822B1A2E43C3F59011263DA540FE2B4B5D31F5FE2A0954E45E106E1255EEFF02A717BB9061BDB528CBBB7854956824311A755B68EC1C179213C418AE21B7DCFFA9F9DFD8CAE58FA1D0B88670E5A25934E7F07916844AC026CD5E1F768978FC0F3AF91922014D75E50F4253A2C2E3420DB1856C206CA20651703D4AE01AE22B8C3DAC60B8961586986F17A93258ED44C83DA6276E04A9D0E03B04E93939FBBDBCAD6833960F02337AB1211E72BC180EED3DC605052CF86F31F1960DD8DD46E848584E909800DCF13146B6A71A79AA92F2BF8D254132423794FC2416A412B001C47A9875FA4B866868A9A88487FE410F81BE5236B13BCFE9302BA9443F3C4523CD3ACE7DE93CBEF6D9E4E6090214494027F065AA834CF24F6CBA9293A02934E52F20C1C2BC9609B559846B643BF49CAE7FB8332BB91B719E1F1838D7F63F5C3A7D5107431E3B854E03EBA795DE9C717B0C9D692B566138CB338C3E5C6F5931DC33214B74F3A116BED19B91E27572A5EB875F14EE81A8B5F2CA2C98739C93C04611335D221EE922C62F02E304BBE507E82E329B4359807F595D11BB5CF761619FF685034004A5ABC89BA4DE82FFAAD693221002F399A5F1D11302B68291F85079D10AA2D1C4536C70C7739CD16293EAD510CE3A04D91AB80D5BD2D02A93C6CF5BEF703A2273E628EA272987167F8A3E2F8E53C3FBC907C2A5AB051653051266470D74F14B632AFBEE256AB24CFC2C7F6E035A0580EC3D1DC11DB98C7FE605183884CF3D7F24C4B3A3D05A697F95601C367EDE314FD3D7CDCD618DB63BB7599E4577D6ED62E891CFD85C9B0E43F0CA588CF282A5E5070AF8E9CBEA9F1AA1FEC53CF411C3EC301967130267B769177AF5508DAFB62F5AD7D8AC9445C62E59612A54F77B1606BD9EEA24998726ACA7EBBCE63F73C143A56435B3EEFD63310A6DF908979DE38D04D7CC75B5FAD9548071D7D1647EC6AAD9663DB156622FBA093B1C470C535BA155FF88EB90BB7CAC9BF4CD367F8CF68CBC5129A577C31BAEFDA834CABB52E0D02FF1A44FF9E85BC88F4BE69DD5C1EB9D4A547395DCDF8DD82C1F98252266BA21395B4272A50420000A40A50CCB22546CB50617F2D7FCE96DA0DAA8FD668D3DF70F3639B45D25910B8970A6F26ADB6001DBEC9D78E94D020307793CAC8A4E69865CD8B7565765C4C4686B0941F7945095A4ECF808A46930AC66F0B569908E97E9557400D265AD10D2A4CDD023D421922BAF3DFD93D7120E4F2C4D20900BB32AE8242295B3EC9D61252BDCE14AC6EF5B2F73895DC27E5CDBD878F24369A533B33DD67ED239C61C333C9FD879D267446F1DEE3837B66C410E3AB8B8BC4C782CBD8449C7B2CC89E81C0CD0DBBC2DD6FE3AE7F2537DC3BE3E7EBCE49EB63A76FEE5ED0209650BF6E06344FE0A46693855AF3D87FC61DFA621D5CDCF0A39C80F2715392DF2C12685F37390982BAF96FF6475CB436DBC6DBCE4716781BE983393D197902C1C757B831BA1564149711D3D8231E908C8458AEFE45C3147A71F87E046193C6BF35FCCAABF592E48724C7E0582077FF94EF1DAE47D911BDBCC43876978BA38C7D6372B23DF650AD5F27C95BDBBA2352D492B5873C3835ECD142C5D3007A4D16FA35DEFD4C21F929A8B02ACB71CFCFB9540B489F9F0C2609CC2E26C5E85847D06E82B7E53B37C698659482300A18B9C42E962E9CDA8968ACAB266CF1340298693C87CC18AF9A52832449EAB89E84FE63BCBD45AC3F9BDAE65E62EE8F97F1165E40D874E9EF75763972A9413C81D18A1E551AE0208053B6276841F8470C23BF48F493BE5A0AA94AC10CB69F0E60267BDAE69EEE405312F8056A54C47A80CD01DC81EEABEBD8336FFEDBE19E8D66C566658D0F8EBE7999BFDD8FBC9BCCC59480F98B5701C8CA3156A94794ABFCF3132445832DC9A582AFC83BA2E41B6D64C8A1560880B7DA9976FB61F1C33ED52506570AC3BC65E345629A00A611A442928BD908A93CDDACC7D8D997ADC9AD9EDC836A803FB392593D03A79440D4F2F812B4C76CBD8F01D3B7119E42B98C64865EB2AA1626EF1B4C1877F6E484BC4D776C6C47712E88E9AF422D676103A71EB6CB31F360FC0EE898A6C28950A448D77CC07D513CB6A58D6364CB1480892DEEA7585CC9774A42F6AE49468A65A7215D4112C5B38AE6516798CA6A1281042F435AA4D6872A2AD8FD600638F0297B9C732E3D08AF5EAA9E24334E56C57C931B3D5AD37C5E5A5255B3038311A89C600944C0946008FA7F433EFDF3C60B8CB0083DCE9A46247E7B8C790E9ECCD03CAA10379C13D171B2C912927324A818D3EB762ED56B1B1C6EF068453A75B2C3757AED2D04333A11E21F12060EA5FE58B4649970A194E223CEC7B9D2BE63D57742317E93AA66F422E0AD7689878224E921CC95B53511069CA6C5492779864E3657CAE50AA46CD8BAE0B29D8DDEA69F05D41EEF627749BA606F1A614166D143923E0A43A1822D726613B24F4B7C691205F6C6F569EDC542228BB244A6A133D6A97BA66018F9AC0D79884B2623442536F17D9A3EDCBD00975A5890A34FE87C37B718A67A085A2B3579822D6673A3041BB61EE24072B5B67961B01DE05F348A63E15BFCB48D3EE991BE1699E11A06E02255F522BDBB1F74A5E90BC7F46FAA51EC84D1473BD47A9DDF9B0C226DB8602EF74D9D6A54E2685D6631EF6AC744F51BE6609B30BAA0DFADABAC90F6322C4D6D0CCE589F09A659FD2B4FCD7F70874FC1E32C7602D4A70EE1F1A0424445A3A2015185C80838391C80637B369F43896BB990A00D55D0C44CE10A5BF10C853E7702B9B03AEC1CFEB983ECEB22C22F199776CC7EC01DE1782D27359DE58A4B177B138D59934A2308E937F4A6EDDE167113E87001C6D485974DC7ACD95BD3A0C79436EF4A9305EAF894889CE7AA3FB758C2C98800EE51C37F4204C11716384A997FDD4F9CFDF71723B37B8D4F4B15E457126BB98ED49099F0881E0386F4CCBFB86F246AEA4A2790D1B62B6430E35271025CE8C710A1413D293959B8264F6C41FEA8EB007FFAF1FE0B57A0672F9ADB6734C2F8FBE051DE3B3E80670F8169DCFB30CB6EA4A7A9A7E56ECAFD79B4A8C7E35796F94E89A1795D9B7E19FC40253E27967338BC4883E7205E2D70765C38D8256BB2504BAB38274CD9645F3F9C65CDA32A50D09C1B7F98F0467D9FFE3A7385B6473EC2012F265D06BCD1522BC9B82019163632C63049D60C8F79DAD64BD92EA183B3FEDC67B450B88FFB825E0F3C36443394D6FD02D61D42881823D8E224FB0D93F68D39FE0C8AF40C08C7E5A438B9B686F3280B67CF7998532F53DFC01299C7732A69DE3076F28D14769A324620C5535EED84289AA55B06FFBF2BB4D73FA75AC8EB66609C5486559FCB920A2F4217F7FC25184A27D75B197F6C2A479D6900D1D56CFADAB446F002615736C9D541981928E08B4C4A75B6D9E0ADFA6795E374D71640EB096BD017BC16B9A6E71EFECABECC9E85040D9803C88A5F11F2DAFD49B506CDA6AE0EA5BBA9A627C0E89FA6B0D35FA493E4C853D728B1AB214EFE14E39A999E4872857F039C67024E106454328641577DBC7B74F441B01A613576BF0A21950B079937BC9427464CF4428CA5EC21AA34F55A0F42005845D62355FEA077B9E6111DD2402C715A972F8FA43C317713C71255D834588DBDB63B8F8C1DC5D672B346135E138D835B36334A38B0B1514FDD87EBB6D8FB8DC41D13DA74BE01A1823E417D3F932083FAD5F2FAA0B099DD03A002B5BDA0F1997B65B62E2097B948B406968CF7759AA75936CAA33B3279A1A92882A9C9A7109090E0FACF49790B1AD1BD606D551A806B1EF434D491AE50FCE2FD7B17BD605236E4E20616F7B7E27CA1C0592F25F3AA967EA41A73D72F4FE4F241610D4F7806E603A1A188EED49D4C7EB6F34CEC63F7E8B82F33B16D7CCE26CAC7151F4A7674667406941291FB0B6315CFEDCA1039B1B28C0E3F29FD3AD285B044C3C24D317A4D83D47985A2EB0F661AF5589F647D92554407AB5664187871F4D22869948A11E31E59ABCD8A14E314CC46D88FD8E2F4679C473B02C3FA0B5704BD2ABB65BD4917C3E6ED2CDB400CC4C82F9A7B9BC71C02E0AC7A029C159E894A88426E60599BE62F97223D12E318037A16DF3C2AB4F90A76F6594297CD5580DFC287D080AC03B445A9278F51C61E8D693123262014A2802201D92241C1269ABB4AD0ECC02FFBAE5AF52D2BA5AB08DF8CEF1D5116C809497279E7D4D9754AA5BD616BF0B5EFFD40195FD0BD17A180BCFE0585F8ADB1741F52DC34D403993C71519314F103FC207AED3F205DC546CD7996E2A2CD2712E26008A74B292A75A1011BA15E8D567BFC19A97C4359F5209A93600B81CA32A0CB1333BB535B699C0CE95496EA897292410D8C89B2FB9157002F82CCE582D62ADC159C08C85357FCAA0F9A10D137F09C5CB1F427725732BF1AE5D12C95045DC4B8F04BADF4A3BD6DA9D99E30D0C79C3FC49763883F77397D1908A74D84FC9BE14BE0AE638B4CB261FAC04EE77AA2BAA5745BCB4282ACBFEB4945EC820CF507B834C70DB6ADAD6A3E5D0796B375B6A29B42D7564EF51E43943C708FA28C4F565D5867FD7E6260D44FCDBB491B4F1394120002271EAD1C1DEC08CE3E942EB8D681D837EF9387E960B33762B59459CC1812E8A847F7EAD81E0220F4F0A4896DAE94C2C6967EC578AA4D56D0D7CF72C53D17D57DD00079D10CF2E98282C2060B483735BFEF6197619182D592E3D9D7540929DEA260D6BEE7F38A21C267AD0B7194A1FD37082117529F2DBC64A39E170343ED8B8717796D802A57B57975A1232ECD48C79D2713EC1EF8F6FC731118B78F081B680CCB79A0A4232DE73D1EACA3455AF0331921195A8E70DA28D8BD04C178198D55D6DF1C5A8C1B641C26FCE25270A6D07D2C1B52A824A2C089988C35191A98A6085EF3A000D22452AD2C55DB0B87CF00C6BF2AB7E66E341C03BAEA55899AC814DC988391250A4D666A9F98F4A1CB16C80B23C4A97309AD0D42EA85A2776D3F097587648CE0564826CE4127DD1E7314EA9A9CF4910E17EBDCC40B4CEC74647B7271C3B735DC5AE8E958CC30617F01C3BD61B5515C91C75B98EFD8DF09D8BA8DBD513C5CCDBF7C5152C340500B09EDFBA42EBCA260DA419FE8856B4B1F904782815261B3924A5F9347673C02CA252B666D6498518A79682B321A8BCF2514CFE07E387DE3CCA6F92AFD4C31D2E83381A1FA741F5760845202EDFBB55582D3CFF2FF2B04A7D469825F1976CD2A8C388FF958F88B4E52C5916B30E6FE03BB9FF6D721ABAC2E7EC46CF6DAC3362929F00321FBB0BA622E1E87A279D5B01D43326D4AD95574CCB2B77E5C8F5E7E9670F4F1EAC11DC3716E070A8BA20E1FFB4FDBB0B75FDACEEC6E4C426C31CDCFA95DF4A1E4E6FCA2D6D674E641CD707281B9D5EDB5DEF9AC42A212A1DCC342DE5C1057E49763A791EE7635F8194533BB2541A690688CAC2293FF19F26B12E2CAAD572B616DCD9058918866155347FC3B7DCFC5A9FD84A9E020126E57CB6DBB5C3788D8B20C9D00EA68DCB344988BC7D92AC98E3E6A278CB536F0AD1A0D0DD8A60D2EE9775347EA0654566734F3687FC669D270A4FD2574770740E1E85D8453E4C7A8A97BEB84F229A630632B1CC90857FE2666E08FB105AAEC690B22B9035766D5A2ECDD63326AF9B48A3247D7F4007947B9BEC525611223B0957532B818B5A686A027FC0C5DB24A849EB573CCC55C204A2EA6927CB1E811F17E4E23D11399C3F88874B79B455D9470FB47833B10258B6739C120533FCC0A64E97B87DFFAABC3982A62DAD557F01F926B2D01A44DA5845BAB6C784D1E226539663F9AB7C59FAC757CF8C930D0BA7CC74CD98B7A60C755BF63B2362F854BD0D4327C6829E53421122BE8E46C54687958B142857039E565DABBC660F289F40E3036E5FCB332644C9BFE40F88DD932FAAF338188D4B7DE60C3D9C2153BD024ECC1BF3E7B653A3704A14B7EA6437B03FF83DBFB25413528AE9D4E8BACE91B93323BF6006A982D34981AD395D3E52BD33337D02A8370C088C2616B9CFA71CEA8B1AC23D3053F85C4B4B195B7F1F7B2BC11D0CD5FB5FA4FA64D95D14F0FBC26873F31703E15A74EA25CDACE3D8AD595A2EEFF6385406A2CD9F182C24B05D842DA26AD7CB762C76E5B255803BC6A281243700ED74093B6974B88EF179FE09D70483CDE0282E26EE377D526B088CAE8B72AF4D82DC178D71FD05BA2DDF7A912602EDB6153F45E3250571D1CA84D49E543B3717DE7E876D19C543F0A0EB8AF9774A6E2E7A17C679DCF2345D4775F292B150FD5789DEAD85DD1536E5FBD9D3445FD5A78FD7A9761A8D588A8CC97720523513DED7D6E95CDF640C7F7D0667B3A09134571A2E741DF8A007EA56765AE6EC046BEE94439E675BB49B6E32EA14F56AA3FAB2AA45FEAF65938EFA7D83934B5487896152F7C0409BA2572C18C7EE4EF61A5484963586E10F709A1396AA2565DCD9C0B4736B56D205851D2452CEC5E324FA4CB6B8698EAC2C9CE9074A17558F23FB7BC14868B8E73B424C8CABFADCD4C5A3EBB6903CEB7543FFCC5585B85BFFA94DD2AA324C505D7F08EDBCC0024DA4E5C1671B6CE012E605AA6B1BFD58D92E8353F05DA5893E3D3822D76338A4D8013297C5F643D648A53F62E8920674B58675C64D0C662FA08FBBC1E9FBC088FCA457E14608CB0D0272A4C77735BA3A7A26D1DB6DD2D0845178F4FE627EBA84ABD7679B2F86E3D9AF2171927FC74104A9F198733FDECEE23D2D51431641F657A85D63244E96D2636096315F291C019197E73C9E11B5C5A015C12A43D176F6D33E34D9C423C1050545E4CB89DAB3E6A58A8E2FF3415B4831A91E72718E5D09832C4970D3C3D600CAE926FF8A24ED9D14A5E5A623C7A777639C145D306F20A9A5B4DB24C99F824F40B5BF387A0E1B6B49468A62755CC437E787DF96748EA3FA5E537922307E7C0694699D227350BA020A5DECF680599AD95F00C0D73F50B13E8385C04BA03C0F52BEED8F4C1C1D9132A3B9608AA1039169A8FA850DDB4CF01966CF881C64EBFD758CFB245B486FE5689C20FDA833F67DDDAD4CFE4638BFC7F6D967F039786A330D8393EAC7A52150DD7D5D30F79A09CFA383A5B7E96E3B2EB6BBD66CB3D6D844B0BEE333E06D027E4379259465A38516686255550A6074B1814100A60F84BBC3CE560AAD08B21821CE740D90EF12452BD53516DC90E60A4480CA758401660FE1A6EE8A88B433C14698CCC86C4A270338DDEA2DE2A5ABBE1C5CDA9F2C222590AC705A0C86F927D830EE91FD1A3B9ADF35C4EA05915FAB0F988D17C522971B7FD2431088020CABA03543C1E76255045A198EF900099FF2A982D626A4DD09F0E3B573E0660E2B09A8C0E7000DDCFAD466E890A4746D92AC1877A53215E35B9D3EE718B92A14706FBBC87B18A42D91CD4017AF5C6D2F549A052A09B57CBF186D1E9C004624D4A3A7A8A03A89C47353EACFB90647B2C6B29F73C506835E320DB751A1EAD0538B74DFD39B383FD7042B51CD82CF10DCE0C984AE75C12DE1A5BD614045DC91989095D32250EB1137827EC5E0FF91D5AE8807389D238AC331185DDC332C90CC9EE4394FD9EB81CDF04DE8D22F6856C5BEE1B4E5739FFB19CC8A948D24D764947FCBC99218B4DA2C439DC410BE7262C062486D55AEF977C09A36D9262E2BAA088383422BAAA20F4D8F86C3A4D8422851B6343AA15C4A1DD5EF0ACDE63937BE7D7F7444286BF00621CB279F49B47835925D71E07FCFED911E94D378A73548539CEAA7D8D84EEF4BE67EADF7C7B57452CDC106033D2B22DBB25D05856C4617E144F4E23094ED4D2BCB7A5DD1DEDD661432CD2AA369EC0B32169D52314A8646699B49DA27FC6C233C449884F540068127850D6E383DA6CA607A0806561363928FBB259AB5D98ECCF00B697E1810CB5422AC9B2F12AF205CB3721B5FE1680BE7C8E9B89A6EEE126E75866EB44B48B3DB48CA63818E6EB691002B2130B6C591F2605152E382251153A042708781773146D57C7B16D62D5FCC2252CCDCFF10EFFA1BCF2D4305C34E4F19F07595102B0A23929CC5470B9E16060DFB7D0F28956492A5DCC8825FAB6133D490BE3BCA7141F049A52548BB792E8A84B0C6A2F7B13196BB8C27DBCDAE620019EC8E480E6521393C98866B04863B8736039F42C23CA001E3B83178E1A65FAC153CC2F32EAD32440FF6A8A4AC29762903B32140B49BB59E591B6480BACEDEC7CDC77D89C82F60E23B5B127B72B9A271996E2C9FE310346D739045EDC020668D69D7EFA248FD6F786FDC4A5199685D68084A1B4ECB0719A8781EA366B630F0C18D023F57CB302D92F8153FB99ACA4EC2E16C943FCB944650EF9733C97F66F986945B8531B65CA531798CA139D8A31A1CC2657515B0FF4235F0EA527E0EFF2E83B9F160857956C894E60AD59345C95D2319CA82ED49306307B75800036D0CFE6689BF9672F9D065678861F7E174489B789FAC5D6942A792ABAC3D85359C36D35286A51DB42C022B305D182E65A9D11602B6D2E88AEC5A556EDF3979E1660F162409FA90C3FC1377370C9389CDCB305772A225671345D30055A528F27AAA77819A7819F64AD7185202827EBE0D92A1E30B05BC17F45E8422E2A0DFCD3BF1347841339842F908E30502CEDFFBDBF01E2A1CA4C8F8BFD8489FB6A60F1EA4A2BEA49A9F986A9BFE1792F97D0842B74AFAD6E97902FA043A087F2DF276C5D30DBB274A824208EEC77AF7B84B0D4D18DB495E976EE802AD61672EACD514F7CBD355FC7F11673D9198447BD142B6AC1A6225851BA2D7CD3565CBD3D8A7341915B40F713165D6B4B949140B91AF9F89E46FD45CE4ECCB2C259BAC0DE91ACC11442A8C146623A0A64ABA992816FBCE99C835554B6ECA8C53A04CF70E81067BA2854FD2332E9A3813F9A3F1E039D4CE9F349FC1BF9327492DA648740E5ADB7E470B513B9375D439FADDB93A6B928440A31FF6F1184C33E1342CD3B29AD04C22AA2D68F4F3613450B7CDB2A3590CF60C03401949AEA3AF2060047A25F37B6B4D81783A6E3BEB0E6F3EDF523667F25D6093FFC23C0B38C99DFEAA9A6EECA7A7322ACA8417F80F819CE53A3090811733E71EA07B5D3773553335EA7BDED1128D48087FCC05E5860546186B657233B4A370B26969D7E179C49BE552B0D17DB34537645DA06F6B1E40A897FA632D1623303671A20F38971357C139602A03BD170783F6F061FA433986AE9747F3D235B662D29D1DB7F077004E34133EEBA14B2C271F3C160AB1FEA528C85404EF08A33A23256BB47A0E55AFF01ADB49845AF72057F2B9FCC6C9927EC5EFC0B510D65D81A123D082B3AA20CBAAA1301C425CA97CD8EBB2FC9D0DFA17C8F0010343BE3E4B2764A269C598B8E541E02295707B6D30968C75B5EF76A1E27B6C5190B818AB5D543E3E8525D007AE95B948B53E81E96D349041DD97AC579ABC59FE1AC5302691FA88F8453D90BA87796491EDE09F70C67422AE3BA6A5914219321E3EE34DD59379E412009869E6A611D4E0CFC7A56D645AF62E130779438BB89CA54BD04ECF012C94B59A800987B449BA086C859C91F1FF5D4C2C5A558342B2B836DD427D45C07D8789EBAD66C2445F5931EFCDD4EEC651EE22081953C30F7DFFBE1B98A8295A545F829C256060A36849FD80D4BEA694A404B4252D86496521EA0EF4BA1415BE3C3A4FE687E67E715D15C7DA44CD7FA18A010F46E8F9221466CE53503D3A9840FB77D7765B84D5D4CA19223CCB22FE81BE7215C8DD0E49C84D787FA921456A6943C5892539062313FE024A0C2E24D15D75A8097D0D393C422099BED9259878E4EA02ECF174CA3B8F5C80D01E998487123C10EC2E04043A4D87154BEB2087C7194F74201BDC8FAE3D8F202EE83A21DF9E5B3B0908C9321F4431CF108444CF5A93175B4563B253F84897E3F720E8EE87E6B268DCABA7017BB07C5DD29133B5878B6CBEF6DDE103E3E34D8BF6DF151A3A24C077D8529BCD02681DC9E5701F93939B5AAC45FACE46A5855E4B4C3AF82C303999937C48CF3D88734EAF75E3EAF171768F6F48FE2CD5FA9BF40328E642D2510E331BE5C3AD6632875A9BD51D6904B95BD5C17B24C43971D45055C7AC0299017249A936BA40E3BD17B63B510F4B7A3B4F236BC073EEF4F61CE561D893AB5B0A720D70AC138D47CCD5426C827E1AB13B2C140FD6E6903EEAE7B30A06851759FDAA28810A258306160452486199EDD0F2B44F32361E8EDD4A458A93012DDB8B4C08A565DC49EC6BAFCC759237AE69DA0DA41251D9E7E8509E4A09A8917418C6B2705CF7C463CFE64A67F88749CCB80B8B1B20A33B5D9DC3F1E74BAE981AC670EE2D86D7B4C8E891F3D5C98B3F5455423412C641C0315F27A263DE975D8D6DE1F17D6FA51262D8E6B3F32AFD9EFB72958460B5D58F4BB5CBF5AE1CFF2D2835FA294760854FF53522E2D52981FC276793EE5EDA989EDC921CCDC50D4B63A908BF47587E4FAAE3A8A1BCE3A21E331D9230B6B1C4CEC7743AEBB83EE003690D2CCB27301D88518A43B266A2E2DA78742230B2258E5D1855A990827B3A8B900362791AE617A3DC0BA2D12766A70316229028E09F96EAD7C773158A549AD9E500751D812D3F759468E22B86FF85DFB0C7C79148CE152A813D0B2D3979A3DBE3765102204ECDA68D24FA6330D599481516603607FA04439B9A0498BCB359F1EE20D65A5A84816AD43750AD1838EF4597876291C98E82E1F46A6963C7726C89470E778BD0A65CAD07E2A167AF6067CD058152E9C14979152103A7235DCD0755BDD793F9B23AE031133756EE3448CD1F93985B40EBE72F7F54124838E3787182147B84C3B3BF8CA901253E04BF808E3F3AEB84C05AB5CCA8D0C755D7B0CB02BF9E06F3113FFC098557DA3F439D397251D48D2FADEBC40286A17C66E0A8533328DB4DFCE9BE32F115A293567E4EA004157045D6996C7B73F27ED2F25536C2A381996257FD23EE4D962B663940C2A57442F5A7CB41B4E6615B223E91B55A7F98B416B2A6003D3A27B496F5E1A446DA9F0DED6A5AA0D7C283F34DEF97065049150B136B2D0F7A4207C904D836EB1E35BCA84EF2780068ACEF1942C2B31BF1F89CF218044A30CED4AF8743EF034D7F526989B99390D79D7454961C4606F6AD659487A803F4CF5FDA4F0A039664F3EA84AC4D7E0E805759A79B959906655FFE28609963BD8BEF5C82A50922A9836ADB18C9416358C092D69292C40FB3BA288D4029FC6B200E59C7C2FC9423360B11F157E5286D0A796A74A088E257F00954CA0789E3507E572EF3DBA68E3CDC7AE328F2072BEABC0E901D5F5DB1A1F41D14732F471F089FEA9D022660949C80D350B37B7F2F551DC22F665DE00FDA868F131E30C110CCB4C746663513E9DA22E143796EE2E241CDC47E2BBC148A230157C0378193F75248FE64858899B3B357CDC21CE8A6C79D2438569CDBE5A44015038C0CB8C260EA75698C272C9D5B169A4D2FDA21AAAB502DE3C4609707BA7C1B2E118F3F5B8A17DEE019465C6EA6B098139BCA2E6873D9945791F7D5488EDC2FD08E09973A55415ECC21556C422F2E0057387363A3D762FE41B054D3C5ED107C4628C15A409C0ECF77AA5AB911A7D896C9D106DB44720A42E0F89447B9E8D277859C941A5E49F4A577C0B6B0049972DBEA98A1E57991F6C0D239BA052CF369D94CEA0D2AC4A0F178D0652F9E028E12423D8D14D7C8ACE33F7E9FA9C2F8B987F89B1BC22190146FBF99B124D028A5AC57D4B21A8F2A2C9BF1F67841BCF3F47051EBD205822DD7F13AEF2D9EEC54D465D89C987851630D0F7930B4451914393C31468126AE0C607ADF304433E581A71C5A19356231A9C7D9810D282F3DBE109F6789BB997BB73E97650844F62FA1954D9BA9C227A23A65F500AB459AEC13D0D25DAC9DC885A01912C70005F440B0EB1A2C0FAD96C7D597DA59AD0199F7978D8DC871BCD4B8143420F5F9900600FEEF0D8C908CD259AAF1D446841B2F76827CE888E1B8A2C2C2FA63AA0C63764E173FF170526FA3D7973931E6C1317F9E7175BEC6F2D6D9FB36730A604879CE7B2FF5350D1A689A57C5D366EA0C219A8E839838A0FCF45A2ED7FD08AEFD2BEC15C47391D9D18E42C18F03B068DE6FC160C176499D06ADBBAD50F1773D036CE5AAA26247B4ED0B68415D4CD101C8B97567290CE4068F4CAE9A778F996A3831FFEF44CA682100850BB5B6290AD8CAA7C10878352C707C0E7D0D0D90462DD46C6317755E4151FAF1755106983B75B6F0A3FCB923D56BE32573D59062008A48AD6A4A87D6242FB13DCC2A7354D470633D292F3EC598A24AF75362BF3A4096C7400A1E97E31FFD716D75BDE945F8FE5A2A40C8C557A5181E7C4CF155F0E1F168A0F25F3FBD0D24C743977C12F1B6D0B4CA5042017194AC81EDE63A324CFE149482AEB04CE5209F0BD768C7CE90508DFBF5EA9A66A5A6FE038746852359919DDC76795A68A4B522C86D5CFDBA46BBE140DCC5B377F70FFD7B776AD3A7885C43A9A7B5BCE599415FCAEB0CA7EBC1D51573F95822CB3135B602ADF40AEDE049501F6BA26EFC18D4A5E9814EA2C2C4CF301AF331672896A9B383F7E582F3A09BAE7BBCB9AB088A0D7FE43827C393E5EC27F08BC5E85C4705EDDA2862BEC9A4DD0ED9BC56D592F6062F75719ADB6A9CF1C8C2526D6B79E4F53932AEF6031D30498587788B0569F6C0FB226105FE5CA0B8B5239C3D11C795674DFE2C8B46FE16DFE5C389888775E56BD14DAE9985960D0817E5354FAE5F20147B30001A9E8D89E5BDEC5567561A27A08A84E2DEF8182060C003A8CF5DD667AC830497A9D4BD1D003019630FCA28C1E272C8C2EADB1DBECEF8E2CAB9B60BAFDFBD6D75562294E0E169506FACDFDC559581B86559720FB517AD8A010D64D03ADDD2CF9CFE8D2FD244A4378DE585F2DC009B2ED6DAC2FEC87D6097A25CC720E7DC989332C5A341503B7D03CC57A875A1A26DBA88D840F24EF8C86DBBEF37905CBA382A8A5C9980504D0CD6CEBCF00F7335705BFAFDE3C3F82EB3225E5EC63D6D69EFD015C9C51AF71B23215E4BBA667AD525852CA6C29AE3AB303AFDE0279C45668D02A2AA96625FA7B41B268E783F829A3A2464F22436917940E6EB3B1D313F794BAD2514B35954718CB2D92CD7865EBA847D388F046CC7D5D3E3B57D12714E9BFD4A09A18A8A626CDDBB21FB599EBE030CED022E16D6C65085EFC6911F7D154B8C9787D3C4107110809219414377EB07AF5441DFAF02EED0B6C7A6BAB1D9902D7A3211F22536AEC7A0A365BAC29BF69021B46EC80143CFC6B92DF4B09954DD20371C1E88087D73F0C885A68327486A812A1C9C36DA7E
    sk = FFEB02F6010609070CF80CFCFD01F7FBFBFE02010004FFF002020900F2020602FC090000FEFC12F6F6F9F601F6F904F9030101FE04FF020203010B0706FEFFF7040A040900F8050805FDF3FE070D060C0A00FE0CFE0D0D02FBFE0B04EFF90002F7FDFF030307F303FFF8F5F4F60505F9150304FD0AFFFA1500FBF409F801FEF909F3F3010201FCF90B17FDFD0101FC00F002F000FB08050EFEFD06F504F5F906EDFEFEF3FB07FB01FC0106FB0304FBF6080005FDF605FA00FB07FAFFFA07F8FAFF050810EC0001FDF107F9F2EC03F408ED06FFF70009F80C06F60102F6FBF4FB010207FB0A0304F9F6F90C02F80007F30D0C04F5FA0702FDFDFBFE0607FFF0FFF803F30D07FBFB010300FEF9FEFB0A13F007030A06FCFE03FD00FEFCFFFF070B1004F8FAFFFC0D0605FE0306F803FCF30506FD0211FD060507F8FCEF0CFE00FBF80DF20A0F02F8080011FD01EEFDECFDFBFDF5F8F4011210FF0403F8F3EB0D050212F3F80609FFF903F5F309F8FEFF0AFCF6000EF80BF6FEFA0C01F4F3F2F508FA02F8FF0A060009F9F70EFD04FB060005F3FD02FE01FC0DF30AF706090CFC0006FDF80AFD03FFF80BFA0CF30B070B0B07FC1003FB1404F5EC0709030EF701F705FB00FAF2F500000A0406FF08F5F202F8150F070BFFFEFA0603F9040303FC0206F8FCFDF6030507FF03F4070409080C1106F107F20AFAF3FEFF070CFCFFF4F5F10710FDFC070EF7F803FE060103FFF4F6F50D0B0202EFF30CFAF5F80C05FEFE070802F8FCFCFD02F81B100404080213F8F90C04FFFA080AFCFBFAF903F600FB00F60503FB0106F2FEE80003FBF9FFFD14FE04F50C03F70103F2FE00F5FAF600FDEF03F70AF70604FAECFBF70EFF01FAFE080803F20F0D1704FC08ED00F304F904FA020403F207FE0DFDFA040B1006F7F9EF06FCF909F903F7FD06F602080501FDF9FAF40106FA07FB0CF50C07FF12F702080A0900FDFFF8040A0BF20D04FD0F00F8F8FBFC00FAF0F91705F901EAFCFE0304FBF7F6FF0E0802FF0FFC020B02FC0801FE03F2FEFCFBF7FFEFFBF503F8F707000612FD0605040404F7F3F9F6040B01000009F5F901050202FCFCFA03FD1501F6F104000DFBF7000DFF0EFFFE0000030804F1FDF313F403FCFEF7090E0708F702FE0C040BFE0812FBFE0EFB0311F7FBFF00FC01F8F20405F502F40008F8F70FF705FA06E8FD09F8FBF2FB0704FCF4F3F5F9FE0AFFFF05020D06F4020413F500F703E7FFE30401FB04F9EFF407F9FF04000EFDFF0707EF0509FB03F506F9FCFC0400FF0900F3050AF50CEAF7030905EEF50C06FDF8FBFDFBF40400F902FC0300F6FFFDF7FCF1F014FB03FB09FE15FCFD02FAFF07FA05FE01070E0402FDF31102FE010802F902F4F90AF60408F9FBFCFBF503140FFB0DF80B0DFAF9FBFC0102FC06FA03FDFC04F90DFEFB0301F3010C0FFE0FF90207F80703FEEDFF0A000407F1F8000807F7051306FA090800FE0EF4F6F6080AF503F112F106FCFCFEFD0BFE020CF40DFEFFFE0F01F6FF08FE03F40B02F50406F401020301ED01080508F70907FA02FDFEFC030108FE08F708F6FBFD02FFFF0000FBF9F7030505F6060809000BF8FB00FC02FFEAFAFB030309F806020109070DFC030104FDF701F3030518F9FD0800F9F60DFCFF04F8F41108FF0202FE03F6FC02FCF706FCFDFE08FAFB04FA0B01FAFA080209FB0CF1050C0EFB03FE02FEF80CFFFD150803F7FDEB09F8EEF1F2EFFDFBFAFD0A08FEF7ED06FDF4FC03F7FAFBEF07FF06050A0307F710FB04F5FD0100E901FE09F0EBF6F203FBFCFBFA0008FE02FF0A00FA16FBFFF70BF80FEDFB0000EF01FEF900F9140C0E0901010606FDF2F4FC0FFF0EFF0EF8FF06F9080403FC04080BF7FA01F4040705FEFEFC0203010C090AF1FC01FC06FB01ECF3000B010E08EDF0FEF9FBF4FB0DF506F4F007F6FCF3030D0A04FBF9FDFA00000D010C00FBF0010100EAF7030DFFF608FCFEFB0207F601FCF80109020010FF100702F9EFF800F40109FCFE08F8FDF508F2F6FBF6010EFC02FE0101020D030BFCFBF2ED01F8010210080EFCFA000B120017FF051711FF03FAFBFB17F805FAF9FB0102FD09000CF90B1A0AF500FCF60EF7FCFC09F1050DFAF9FEFAFEF7F50CEBF5F8F3FAFCF6F6FAF308F6F505F6F9060A00EC05020AFAFDF9F50200FA0306F707F9FC150A000D0702070B03FAF5FE0EF7160D06FF050004F9FCFB05010107F2F50103F60305030610FF0B070A03F704F602EEF411FFF9F5FBF2F5F00101FE080BF303FB090402F30509031107020102FDF502F5030301F2F8FCFC07EE0A04F4FE030406040802F406F4060FF2020DFDF803FE01FC030AFF06F50A00FDFB12FB00F4EC04FB000B05FFFFF60EEE02FFFFF7F301FC0CFC08FB06EE06F8F9FAFCF5F30BEF01F4FE090400FDFF01F8F20BFCF40D0001F708F20304F906F20201FA0BFBF4FDF309060BF6FCFE1007ECF30202F907FEFA0AFBFB05FDF60BFEF5070CFCF60C00F5FB0AF909F1F40302F90D000503010705EDFFFE0103FC1004090C0007F80012010DEBF3ECFE09000807EFEF09010EF202FD0A04FFFBFFFD02F3010906F808030409F9FC0D010C0200060703040606F407FF0006FE05FBFA00FB0FF6FEF9F8091105EF09010300051304070DF80702FF06F30A01000102F7FF0EFD010500EEFBF802F8F6F9FC0602FE100105FBFFF7F8F00AFCF906FF0401FE02050A0205FB03140B040806FAF900F5F3F906F90FF9F604F602F705FFF8FE0A020C09FF08FE0FFDF6F3F6F2070002F8FEF1F90709000301F307EEFCFB06F9F7FBFEF9F50EFDFFFFFFF508FF00FEF6FEEDF7FC02F3150106F60803FCFD030FF9FF0CFD02EF0510F6020801F70AF7F8080502FFFCFC04F7FB090BF1FBFE0AFEEA0407F8F4FAFFFD0FF5EFFBFAF7EFF7FF000E00F906FBFD01F9F91A00EF0C0502FF050BFAFB09FE04FA0703FCFCEE0507010707EBF3130103FD04EFFE0DFB0503020C0D0AF7FB010000FDF409FDFFFDFB010BFBF404F0FC00F8F007030FF8F5FAFAFB00F700071205FEFF02FCFCFFF2FE01F00C020BFB04FB020206FA04021008FA00F609FD0C06FAF009F60FFDFA07FC090E0C090CFDF9F7FAFA07FB04F20BFFFC0500F8050DFF08FB09F30104FDFCFE02FE0AFC0CF9F70903FA06F6FBFF01F305F8000807F1F9040E07010A03010301010D11F502FDFFFEF2F9F904FE02FEFF09F4FF05E9110309F3F504F3F807F2FCFAFFFA0BF501FD040107FDF816FDFCFF040404F9F7060AEBFEFD07F50000050B00FFFDFD0108FFF806F5F60D09F909F610FB05FD09FF0C06080EFFFDFEFAF7F9F70B05FA01F4FE03FFFEFD00FFFCF8030D07040B00FE03F3EF03FE00F5F8FF00FAF9F80CF9FC0102FFFEFE0B0108FAF7F8FFF805FBFE02FF06FD0311F8FF0CFBFEFE060CFE00060200FDFFFA0C00F30EFC060608EFFEFDF2FA0405030707000108FE05FC050403FEF800060408F301EE03100CFFF700F9F2FEFC040800F8F8070104FA07FCFE01EDFE020A09F00EFA0C04F70CFFF002070BF908F50201FDF8F80AF90CF205020BF41103100205FB0104FDF50502FB02F7F907EDF3FBFC0E0E09FF0C0505050E020700FE00090609F60C03040FFCF8FB090AEDFEF4070AF3050D02EDFF05FC0503040A0AED0803FF09F50201150F0CFFFE0604FAFF0EF801F90CFCFBF9FD04FFFC06FF06F6EF01F811F807FFF9060407FEFF00FF060B030100FF02F902FD08F905FCF50700FC0D09FA0302F901040AEE0602F401FDF6021703F50406F803FEEAF10AFB01070916F0FD11000E060204F707F60802040302F60F0B09F802030001040114FC09FCFC0A0B05F5FEF80F04FDF8FFFD01F8F3F6FBFB00070704FF0FF70A06F3050D06F3FEFB040001F103100F06FA03FD04F4FD02FE05FA06FBF40FFC10F11407F8FB0AF6FEFB0303FBF7FCF4FFFFFFFD00FD05050900F20600FC0601F40D070403FFFA0505FB06F806FF01F4FC030910F70A03F20809FEF0FF04FFEC06FA090404FE01EB010106FFFBFDF9FAF4F91703F7FCFC07FD0DFCFF07000AFD07FBFB050CFA0702FCF60E04F9010603FB0501070AF806F6000BF6F4F9100BF4F90904FA0EFE0203FEFE09FAF3FD03F908FCFFFB05FC06FA0DFC0001FEF803F60200FEF80D10F80E0B030503FEF103140A02FB12FD0301FFFAF8F905000408FD070C03FEECFC01FFFA000F0C050203F9090404FA0710FE0DFE0FF4F8080808EEF404030909FE07F805F800F7FFF9F4EFFA0307FE06070005FA0FF5F3050A0400F8FCFDF001F2F312FB0D030E000C00FDF4050904010602F705F20207F708FA050E0B0206EF04F8FC000410F0F30DF7FFF508F7EAFFF9FDFFFA0504FFFE09F5FEFE1607FCFF0AFEF40206FC03F401FBF7FAF7F50402F3F8F9FCF8000903FEFAF801090504060307FEFE070E0AF6F501030FF501F40407031007F90206FF14F7F9F300FCF008FC0C060AFE04F905FEFC080704F6FDFE01F8FBF0FE080A0509FC05F803FF0E02FE0E05FA02FF1000FE050814FFFB03FBFBFF060CECFD01F901060705FC030B0BFE08F5F70300FDEE08F1F5F70204FDFAF4F6FF0705F50AF5030610F90F0C040DFE050001FBF9FCF60A05FE05060107FE0304F11104E3FCFD03FCFAF7FF0805FF0FFDF8FFFF050101FEFCFAF30C08F2F30107FBFEFF10F0080403F40309FF030B00FB04F50DFC09ECFBF506F711FDFEF401FF06ECFA0600020108F70CFC000DF9FBFD0111FA0002FA01F90008FF0B09000AEEFDEF01F506FFFEF909F80CF806FF0503100206F0F700F602F901F202F9FA1402F705F8FEF80A07FF0CFF000DF808FA0FF7110701FDFE0CFE100500FCFE03F1080EF60B080603FA06FB0802F9F30D03FB03FB020903FD080700FAF8FAF8F9F2FC0707FAFF0208F4FFF7FC140001FD090108F80D0AF1EC0AF909FDEE0500F1060507FAFDF9F6F8EE0204F3ED0308FE0B0101FE0C02F303F5FD0BF9F5F00C040102FAFF05FE0C010408FC06FD03F5FEFA030700F9090109FF0A000108FA0901F5FF00EDFEFD070705FB0600FEF2000E09FDFDF1020500EE0503F2F8FFFEFAF8F803050B0602FDFCFA0C00F708F40602EFED04FF0B04FB0115FEFEF6FF0AF7FB190006EF01FA0BFF02FEFE05FB010107FE02F7FD00F10EF4FEFE01010302FEF4030700030BFDF5F903F503F10D0904000A0A09000106FD0DFF02FA03F701FA02FD0C080F0D04FDF603F6F7F900F8FD0609EE0BF702EEF5F4F4F70105FBFA14F708EEFDF1FBF901F7FDFCF3F40204F9030401FA0203F103F90EF4110704FD00FBF001F60905FA04FD11F305FB0A0C0406F7FB04F6030A03020AFB02FD02FEFF0DFDFB04FDF9FC060B0905FBFBFB0BFF01EDF50200FBFD110D070803FDED0D010C0B0006EE0302040108FFFFFE0304F6070102EA0EF90701FD0711FCFDFBFF08FB06FCFD09EFFB0DFDFF01FFFA04FEFB0DF90A060D0407F8060D02FEFF05F90AF60DFEFEFC0F08FA0102FC01F6F6020501F407F90DFBF500030800FDFC02FC020AFE08F909F0F8FEFFFB03FD10F5F3FD04FEF80BF4F5FFF6FCF5FE03F8030107F500FDFF0DF2F2010AF90007010B07F2FFFB05FA080EFB07E9080614F6FE0E020206FA01F4F5FEF4FFFB03F6F2FD0000F60007090103EB0211F1040203F5F90901050D0F05E5F307F909FAF8FEFD00FEFEF9030C0BF2070605FF0806FC0011040309FF02FDFCFF01F404F80AF9F807FB00F5FF04FC0DF3F504F90DFFF900FD05FA0908F90303F50AFE0CFC0DFB0FFD120906FAFA0813FB02F7030107F700FC05FDFBFBFB020D030BFAFCFE1000F9FEFE050303FFFB10FB0104040B0B09FE0102FCF7FCFC02F6F9FFF90BFFF90F01FFFEFEF9F6F2EFFC0309FBFDF701FA12F605F7EE06FCFE04FFFB03EF0814FA05EFFCFBF0FF0BFB18FEF7090BF3F50011020C060604FDF015F706F30EF30206FE0A0403010507F5FB00F902FC0C03F901F718FD02000703FAFCF70B00FCF3040602FDF8090106F800FBFAFF0BF9F902FB0615F9FF00F401F9030709FF0305FCFB08FFFFF505FB00FBFA00F611F9FC0A0A04FE11FF021207F7FBF702FA010305FE01ED07FD030E11F900FE000101FBF608FD080F0D0DFC0BFDF900080F020FFCFBFC030513FDFFFC0EF7FF07FE0C09F4140602F70201030501FB07F30C040D0603FFFE010603F2F90CF70203FBFCFFF2FE0801F507F8FB0405F8FD07000C0102F4010009FDF5FFF2FE08FE01FF07070908F7FD0E0601120205FB010606F8EEF9FDFBFD04F80304150AFFF9FC09FA0BFFFB03F80B07FDFE02080DFC020CFA01FDFA0B0702FDFBFAFF05EB04FC03F1F90C03F9EE0F030B1202FA12060505FFFEFDFBFC01FE02FEFE1400070AF8FD0204F7F80DF10714020805FE02040106050C0315F60704FC1201080A0307FE0004100A05F407FDF60AFEFFFCF40400F9FFFCF9F810F00203FBFFFF07030A00010E04F5F106FDFA0EF80D12FAFAF20EFB05F20307FEFFF2F809FE05070800020009F0F6FEF7EC0A0601F2FEFA0AF508FE060004F606FBFBFC05FDFBFE02F9FCF7011100F6FAECFAF7EF030EF9FD0DFC000202FA0B0103FAFD03FCFAF8000F0703FBFDF4FD08FDED09F70B07FE0006F5F508F202FDFD0BF2020807FB0FFAFFFD04010408FA0803FFFDF7F00001FEF4FD01FDFB0E05F4F8F9F6F3F40406F709FA0EF805F7FE010B0309FBFBFE0706FE0B03000D0701FCF30610F3FEFAFFF6F80311FF09F60804EFFD0F080706F805F104FFFF0605FCFD05F9FB040BF614F5FC0502FA0705F4F6FCF407F4FAFE03F6130600FF06FE05FD0208FEF90AF7FCFFFEFDFC0EF6011101DC12FDF70407F609080D0CFD02030AF4000305FAFAFBF10C05F6F0F9FCFE0009F7000100FC08010DFDF805FDFDF5F7F7EC11011103F9060505F4FE07FE03FC0308040E04FEFB0305F9F5040AEFF9F50601FF010AFE0C00FEF6F9FE0BF80303FE0303FEF40A070D080308FE05FFFCFC11FFF501F9FAFAFBFAF9F701F9F5070703FAF7FCFFFA0C02FE0D07FEF20FFDF8F80705FAFF02FE0308FEFC01010C00F70813061103FFFC01F90CF3050C010F05F50101FB1202F805080D0701F7F302ED0AF40B0CFCFD0005F707F813F9FE02FC0101100401F90CF70B08FE0108010000170004FD06FEFCFB010106F9FFF80702150D02F902F8F1FA10FE03F9FB09F1F6FEFF0906FEEB10FB06FE04FBF5FBF806CFC6B92DF4B09954DD20371C1E88087D73F0C885A68327486A812A1C9C36DA7E4F5C254B6292FB5C3DB9561B8793D8AE3E1611423AC0A9F8CFC13E1C85FEC6B5
    smlen = 2881
    sm = 1A8FBE71887EBA96C44F36AF4FDF1B81329E7965BF152679D92EEFA250AEB4E7DD23D31C5A3BAA6BE605ACFF3EE79C1FC6C48D97891F136C4214B2A25A6465527DD97EDA9DC84593AF544E02048E772A74B75823AF07D39B4E28CB4E316230925778A5F2055711CF7F7A274941DD9106395CC4D9FD659A9C1E90F1B11C81AFCD9C2F9B5F6C64D1B62228CACDBAD3EFF26FA205F659F5B79E25148E06E3D768D18511E0B90062605974F0A9F1829DE78EC3208760BBE34A56E6B8AA037F9DB3A0F868753321C59C420DC570F9A7EE6992B847DA993B5A038EF4AE0FFE985D3297B45395173CAFD4976FC37B2AA70283E9C8915D272940397D21960C746D126790BFD43A1C6D03D9E1708E247A2F832DEE0AE387698C37B624CCCFAD26B4A3363AB8825C8E2501BC204F6B0578AF171BE1A88C1BB2AB88E89A21CAA1C604125ADFFBAF46609DFC01F22C59DA3ECC78CF6EF3EA9F2FB5D15DEC3C723D81C8CD895BBF3753782026ECA9975B872F8E85B3F375F0BF40DD7EC6830EE0858FB6470F8A788A21189BBCDFA61316A0D9E49B0117D2726F72EBB2F730C88AD4D76E0ABFE4801B36FC0BC3CC8514FE2F8BA05396DD03B897C564185E90B3E3B8559ADD6E9689CC11DC45F50E27D549704D79CC5EAB7A85BD25420DFD83F0C68B56B2B5069BDBCDA20A39930BBAE70396DD0CA35DA7E9FDF3D09AFF121AFB6DB40D63F15EEC54BBC8BACC9C229BCD650BC5D117597C7FD9D60DC792EFD4B32DBDC550D2D3DCAFB7C77800905C427F79FB4C81867F6B1BAF6119FFCA4799789A682795CE803AF398182AF92A1EBE6645BD793BA3C0641D9F8E9765F5B7081889219072763D9032549E03D4C9D825B2B8C5E34EABE189E083003F4CF0C5D9890E755E3D51EDFA8A4D14F4D3DE989187D1BCDC0D9BBC5E3E25C3277087E1A6EA1F47E6ED29E0C48E2CC80E29E3F868656DA301B845D379F886BC2279BF4027754D0F8BF833899348706DC3C20C5178A1E91E5CC38280291D05300D9B8C937BAB8F8DD52CF82B039DA547B8DF8AA60E15194B1E3E61C13CFCC785740E4D0609916AE5502A42007338F33225550F5FAB2EAB1749876478CA7052E6FCCD60E51D629DC70C20E3B5C8C088D9C4483CFA791C5508ECC8F4FC559364CADCA6A108BB5E0C23E4DDC1C0B8329663E3872CFC33A8CEEC0634561A0AD6E2A940A7526DCA17E5DB3FDAFAF712352EE9E83C834C5DDCE41947B1115D0CD71D35A362C58043035131A870EE1C1AA4340F1F4F21F8882A5E0FA069E2C8645F853A8CEF5557C6DEB87CC609434131074EBC1358DEEA690A8EA021D99C9C8975E57B887433BC4CD14148A645216F15315EE63EEA174950E8EA9F02877DA8797D5C6A7A69100C5115377DF31EE637675EFC2466A42B621EB131FBFA8EDBB76798EEC329444C481FD2307F9C7A39E317E05EFA82784D59F84FB042EA328064058602754D54DB5E40E28B9C0336A4F4ECCC4C2886DFAEA1B9613B5DB5FD7586B8CF6E777D9271971109A1818B9632864BC24512420A3EB61BD03A00FAB0F77756CDDBD8707F4F38E8EA8DBBE7F420C0729A65DC230B9D43E7D6AAC8FE9FB0F1B3938FC1E2D2FF4FF2D798AA2812EEBE4539BDC3FBE6A95F67D61051D9D2597F5D306CBB328DFAE70BAEB3754D327636C1026ADD5C0D75670C9BB56F6B159FC629B1237238D24FFD4EBC698EFF040410807C30811D21F59B6A67124030FB2083BB6F86982782EE1CD18EECFB58D7062C11339784144C6BF3F34CF0A96AD5452E9796A7E662937D906189A839F4E6D40F7CA7AD89B3A1B52558FEC20B68191B64549006F36B3FF31F9891040F9684DBC8DE48B277A55408CEE7A38087FB9BFDEC2B899D4190378F6F26B0BFCF2965CA461CE9CD3D5CFF54A197FDEE95E23B977D9567DB840544BBA5444AD7F4680AE7F3D736653C3FD7D8BB43D6493DB3644E2A11685D563B74499B94B2005DD909BD0F1A7AD6402ED2A0B5DC778542BDE9A65F3A0BCE35D8C03DBBC41F582A8082537773D9910FA1BDF8704EB5C6B99307124D9952C5917B13909E4833352DDC73F9A17B8019BDFF0413E16EF2330A1B2930670C977EE44160B1C22EECBF4E4CD3C1D2044CBB1E24D24B202CCF002BFA12FCA3D8731B3DEDD5AEDB767062A517D82C1AEF3EB20CA7EDE83D64212AF8CCC90F6CF648D2F0705B613DFFBC4FAA8EE2B3F15E81F1F8CA3885647CB754DBDEFE0E96C4F9999A8359AB4093EF21AB4BF72CA61583F4FDAB034EAA5E8337B9F0346645462860913B3ED357711DC018D9985BE5C3179BAF35139D39EA488B88BB070D523A5AD9FA7B360D7951D0214D6734BAC6EB40FA59588EDA3E23F3DD07B6A6C91644EF19785B59D49CD5EC439E73E4213E46EC5FC1E673BFDF5A99DF2C661B46B9E2A2B27AEB9FB462611F4F1DDDC65EE1585154326E71515E2B20EBF35D057E1A6F794D5DD52B5E87BB2B5CA46C00381568847C4ED353028F02DD0FE4B3E7FDDEE1C5B50BDFC2EFEBDDAA2F276FA689C194A35AFC44592E266C630C902F5A7B2CB06F97456924F0EADBABE4488CF0E2CFB5918C2A95F4F63AD2AA32AE727F43A3352F8B7BB26262CEC8AA8FFF7E83873BD64F5A17ECDFED210F578A9E2C9B530CCA1DFA28634B844D4ABD4A6AA649678BA7698D3242D32E6E64E89EF60EB39B8D1989C5691AB1C79EE242DD152B97111C6C871731E6503BBC65155E6E95BD3A1FA9C13F5905BFC396A4860236F5434CEE94290F6FD74A5F531DA5823322EC147F628FF6A6317E4B66342E4A2DEA3B7755A0B6483B6DF8910C27CB45E2F78AA5D6A4D822324EF3A620039594615625CF45CC8E700E2B1CD467B1823559C9DCEF70F9F12E45C70C27E5A5073E9A7A5EC6E08FD0A9D05EF4E02E4CE3B0B372CB2314E6FE2D56B99397D92C099FDB31E34DDC479F73E7086BE45A63DBDA7631CB771DA132828ECDA08F91FAD9CC06CA26CFBC605F5D41D8CD8A2E3518B4234BF891946A591B52CE4D41104FCFDB33C6A594F8BDB19B163C0FBBC34560918E488E1FE12E3FDE4669605EE3D28A9D9D7D143D3F8F8CD0FE63913094FA6AB347031EC8EAB8E069C9BA9ED39CE9765612A3F387BEA6B01E404850F70A3E07B038DCF57E3CFB1EC2EBFF349373921780524FB3B5C50749FFB88624E2FE4019DACC253B3421E08104CD31CE76482D3F882262531FDDCD17A30DD0C7DE4BA12EF537BC8DE4514DBBF48C5640BCE5D683C5A48ACE662A4D109E02686AF6ED546F807F8B5EF618B240C3CB8B98EB58D060485EFD3E39665158371D880C22E4DDEE5BC90000039283D52CB5CBECFD08C1FFCAC063D4B87C83A55D39CCE55D51250BC54452DE0C049243BE86827B006643FC396C2A2FC54C23A0A0DA249325EA6E0A1D801BA75143908F776C627680945C4DB46069767CE8F3AD26FE2ADF457FCB6F5D96796740F31930FE48493B77720B90D1AD646B8771470E77F42DA1573F40394D5DA4E8D71E451CAFF1944071A994278C26B50E3FBAA34C6102F5DE823A279D3280AE42E2973D39665404490902E573BC8021084C5A7559452E0978751AD65C161FE202282CB15484461AD06E815AC90DF18537191A535029D0F650B01F2B44111D01172A7C8545BBEFF80B0664871D714E3E4B8F773384082BC7B4456A79F48004B35201C6F6AFC8222E11E1F58250C7A33FB67EBCA408F762302545759E0F6CDF65D562EEF948EAA38663F1796FD3037F140A9310392BA1C7A4E2CF9D5EB0078D3DA3A2AF4FBF5BB3558CF00E16D6F2F59DF81C4794A257771C7FEA3F3BEC7A48207685BAA0BF5D7E9E9E0E8042B219F2ECA73E6C14DB051BA37DA60501DFB2623C9C7DF216B8E25E8076CC386A4C3A7C5B2C1B66833EA585C727CC0D4E38582BFC580539956A9BD790B868870F49FA8D6E597348D294045E1DF1F1B9FB18D1A68688278ABCD9FA51AA306516078E16377A371B2E69FD92B01656E3813CE22EC095F08F72E7E97D491AAA1E2996A017C5F91FC0449DD81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8
    */
    public void testCatPIVector0()
    {
        byte[] seed = Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1");
        int mlen = 33;
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] pk = Hex.decode("EA7347183E405433EFF49CB63A9E736B39A86CB67125110ADF35536A44940BAAFAFAB19FCA5B8F11CF72F7199E051A9A607D75D093FD1DD7F7038F4EBB172F9549747FBEDB2EDCF24BD007610C111E032C1852E4A92A8EA33057606200B17C785B8BB0B2A08DBE93185F3B931371B256CEF871167BD21876B1D62FEF325BE2D0A716A6ACC3D3CCF516DCB267093035DA9359E8A698C3946D88200E9033AFA1E87A30A7A626056F944010A5CFD972399AB7C52FC0E87D255A589EE0D3E14C4BABCD5CA50A561E71428C98B72D413B117F827F0FB557559FB16FF4EBC73C539C43040ACD34FD676C1868F59F84AA1398A61E99C090A8E1A7C5A19CC23CD21BE2B9CA6E23F6A7E05E3E69AD6516A085D2C58FFA0883EEC30C04B648414C3D4DF1C87AE2C5F06CCEE989ABE455ADCABB6C84FD17D8A9D1158E91C4A2598A153595B4C2F0921ED24A49F758CCF7FC170B3959B2F26791572ED54AA80368D5800025F6138B595C7D8B6B8AB5F340399AAE0C821C4B0A3D677B530227B33525D9A48AEE067368A81305FFCB2E8615035CD56203EBBED33B5B1F5B575F920A627A770F0644610094EDA55FDB7C7BB7A723DFD4662780ADA0BA214D91AAA9C832FC29DB0B59EC14F4681FF05B6E5D087E91F891416CF8150604DF06BC7901B6ED33A5967E91799BAF9E903EB7967D393772F7C170D4ACFA36AA333BBE00AA2A40FB3A8D1EBE9D88926207677BC27BFEA91ACF49E009725D1CC9CA4566FDFEB762F4DADA0ED3323A5D48FE9D19B0B60809DE4182EBAAD5113019C9FB4F9216DAF2574EDE87B41E14590AF2B6E71950881DF07B5303C13EDD4D516FB059C7B7F1DC5CE6BEF6D2ABB65BC6B2D5A0BD555914BCF21FAB87D417F66C87C0F007DFC6DD6FDF22DB646F887037227A20AA1CDACE683FB7F9E4D4959FD9D361C073D22DBD89C4BA32CA1B9BA803BB8EAAE6495269030C24C08C8844427CA72F321303F112EAD94E3823D354730EF3CB2F561728227BDC2321FAAD7ED43B54603F94CDC42A06CFED0F44CF34F357CE3019973988AE101746513DC8054EE0464A8FA8654A724277C511D0EC41EA009F837116E9B51C9491E0D6E7D4796BBB84E854C6097156F8A77CC8913F3D05E8A478667071AC757557FA30958314499E377262C79EE8EF891201A7E13710F4F6B252EF970B9B71A050681CFB0B2147D6108F7415A55FF1E70CEEF738272B8EAFAE18907E6D64F6729F5EDA8FE2E779554B41846521DC530C3CFD36A60EC145D0FDB6AA61800A534D9853A6B364F48F54558DE0132A39B4E5BC1ABC5BF376A5BC02439498B4C21FA9C64A72A9A55E51078724BD235E3D75D8AA12D4186C2D8E65CFF70E93211D996556B67A0231CF46E80B1F258C8FADD5662BB8D23B84C8C5EEB2612B0BC2A7B432B321AF2253AB16EBA0D24CCBEBC6D9DD83DF22DEB57EDDE1677CA943FAEC92E560E58FA0009F7DC4673722DF8FD38299FBB34FB61239611DC97A6D24B1ECB4CD6DF5EC4658304D34EEC218A55876A338BFF8BB2470B7F8275DE34863B27D5DA1AFAC7A24039DC53ECB99079E0D7DA4E3A5632D97AB065D11EF17BED267CC88EAC42A9A7C119D1211724D0E3A68A54A6220CE471EC3CF49FA21B4541FBD0CB8257B6396E4F2CFC8BD0756D4C0703F5B5CD656268E98C043CE4ECF34A377B8846817DEB391CACC4050E797873A1F88E974106471944D8A2A25E80FD54024C95A2B5E496FFA076F7930EA29AED839AA58954E5228F2EF55420C048E3AD1EA894EBBD4851AAF0A8C99CACA3057C486A0E0C2F1763B4F3440C87BAA44705F563EFA435FC68D165D0544902A3FB3B84FA8D74001F4C314F106D4AF37BFC54191598D2A28869F46D76B68D72D5FF91AC1F0E31F556F2030C816EBADFC9F72A55B9CB5F9D4C881DDF35448140025651B9D0EAD4C59845119C8D3FDBFEB219142C3C6820032BFA7644DF7E7D2783E27E8786053B02EC68EB4CE6DF29BF9FA8B1BA2E8A6015419D0A3D491E884C4059184B9C6E7BC35908EA60BAF531EFEC1D2379389291BC5E17A31F1ADBB5AC09EB3EB845F3044D31706543F063644F6D5E7D6DC686750134C9811B4BC230EB1EF7E8B214D82E444B0D3EC367D5D5D0912B5D6EF40F3D36302D726D9A988C208567067B5C5D9521EAD36A23C8E9C956443141FF78569A8E0D9EA2BD815A3A9746CF4F1CE603E0894529948D873A67C8F244DC10D9B706E127D508C0A814E9132E1AAD7DEC1BFFFCBB98EC65F1BDD6A8A03DD08256EE50869EA3509C2797184BACAD88798492F8958327D5F1071A90F0698EEA7676B4A86DA0ECDF4F3EB5553599514CA78773CBDFC9F091124E62181C637793A98E02847143ADC41CB3987334566846E4D201CE926D23AD382CA2E5E153342E7AE8CDE9FDD76148251F09C7290ABCCA43037BEE98947BD673B1FE28C0951298BDC45317AF1896D0E4B91BDC2AC886D18DB6008D8565FDE10D5D87322A5777C66A910FA2710F83BF61B396E9F82C2D68FF4B524616261D444F7AE05B57B4A86E23C6B759504812C305906ADFB5C900360E79EF73F0BF0233F5181608ADD756B40EA15DBA12B4AF06B1952F3ACE3908F6AE4625202DB122B5087E7808963426B23CE9B85260C924A677812EFD1A55E08CE2ED673BA2D6DAC7222A336CA6F0A05996DA63269EC3F5BA62E24593472AD7818C1800DB5A727D0C8A492EEEB22AB981CB688853751DA34F34A6723591909E2197D1A4D065737AE476831C19F92953CB7F889EBAC46A31D247A9108B3450A8F3B4437D0208B0D21558AF4E31DA942CEA458DD88A605DBCF1136A2E47897CE17030984952ABC600B8F30292DA4274593CC71497E9BCEB9CF84986E4C2047BE8821F406F1E000E18F050E3DD8E7F3FBC923D0830D1A84DB2B08F8E0623E3480A20A48E20A2F0F37E144CA58283A97A20E12DBE95327D69CAE4234381457CBA8FA237F88C466E8DAA72BF89E9517C28BBF4744D3214EE8B3263DD64C06C78AD9D0CC42517048DAF4AAD330BE626F23338FB6819329D11C10D928C11FDB96BC2A00C269D7839DEF20580F82F7D9B48CE896C45F568A6B38F123BE6B0690722DE463690EAF8C8336F829D4D48E001A7DB63470A39430E6929BEA765B3E8127C4213658C6938CE5D566546528D60C8B938196BE5B3378755580816C8120803A46084BA1980D9F129D47462874022454DA5E040456B2F406218E315149D1B79F7115C81B7F98E1A1A3F61C96138152C0A1B3E124E630902E6033742F7C74946B5D2B4D08DFDFD29FF7479C313FE889B1CCDA14904E0CADD9963F21E564EC09202A1B263440E9CD8EF3C25F2F5D58D278DF530F3940B79D7AAD270497DB9EAB1536C2F59549CFED6E5F4A9AC9907E586357C7CA305170B622CC3A571E45E1891690EF11C1BE641A2E4169C2D037EF6130C7C70104D4BF844CDBBB6C805A9B210B853417F6E2E4C85CF4D6053DDCC94122D5F2CEBAB51E0232E0DE9B19FC5CE0B78D569884F4F2E33BC4B1BF6A370B7F2E317670A136FADB81873EA13178798FA48E9E1123DC5B31D88301054F0D964C3939C0CF1201DBE5B43C1CA9E95698AD80AF3EE0633F973665468039EB73C63FAC0E70DAFD81F17492B022E98C61950A5D50846FB707CB7CDC7C51BA2EB7B2648C22BDF81C17A8EBEAA351C396E2BAA27D014F16388F215C5DD5CF53D077A4BECD1F57D0BCE1CC415C52052934179366443F80EC1D2266A80EF5A4CC09BA0E2301219CB9DCD88F30639B0A5363CEC3847CDC0207FE65B260EC1A4B5D40E3870EBFC1C02F2F4591A4D666E2754A523D9F1A5E79B69FE553B8405E338E4587EE2D03336EC2675A95AE9A35D9FA2D91FF934D30D3FFE4C7635C2DDD2FBF852859AA91EF913263070E238AF16D140A470A8A4A2A38720BD667EEB08E3436EFC4B74A9CC9725A7F0ED64B55B084E8EA7EBD1ABCB8A21E03CEB0F9CE5E3445F226B5797613C030F4ED5C445DFDF886AA6D7230962548B53CB551F3E6CB2FFF4799AE47E2293AD0FB30AD70417BB9F12CE5E7CBF9835B593F8659D98840D5F93FD67E0C48268F770E13726687DDDF8FD41D5B729B1B800892BC46D46154449A230139E80B59BC827B7638E1DDB20C366583892B8FC40E5B038772E4055BB625996969CFBCD95374F5966B5CCCDE8EC98CA3170A43417A941FD1CD00348E12465568A3DBD075A08D282D84401553B658FC64E233C5D3E5BC383606C737A3581CD38CC7BC362A7E79D46CBAAC8A76C2093879E2EAD94A9E9CA4703ED884E56FCA8B4EFF34BA4A002C31C2A15258879610551BCDDC393C0E1E4CDB543BF3273C4AA541D107D3EAE2DC643993779E15D214B7FC318970FCC976C344ED4D147BC226D1F193A7026E949778E67B395B111F943D44CA98E5A4EED33272B13986D48902692325FF749F546A9E6674FD6B8F67901725B8A0543C81AAB10228ACF3AB5F7EB2CA870DB85A69E4E63153DA7F5F8D8CBCB254E2CF003E04362F4E94C6EAB08F53200158B8F3CC8E8333E2EC6D5A4DBB607D6B180D45CBF05A7A9A60FE9ABD902A2EF248B9CA9C516D5871C88AF24C5376A4B3DA19B96E454DC969BD4DFA81170C627A2F6A0F0D3D9C65BB03DC24C470944CE27E108F3402062614F878088945A201EAAE842C20AC99D743E650DAAC82970709EC2D1A6CD5A49A36C434496ED6F5E1558C0580B61312F63C195C4FE5CBF43BD8C3B189FD5F0766041E8DCF336C550EB66C4C0F2B9AA420F260D1458448D4AA5CCBE22340058D60BB0C7B21231ECB2AEB51CFAADD4D10B683248F8ED6D2B61D4D5C66EDA259B30101F71F1C19A60C987019F236C35259E7C39DE6709806D24BCACA2897CEC81BAF76205A488E6920A3792A0B906BA71B9B5095C85F6FC368ED0214F026A6342359CF05C768EF34F1CA5E1F30E76D57ABEF961EA7097B82F8B81B9219D9D5EAA4143F23FB4812CC8E8AA5C089F35E697F1FAE5F45B725560892EA7A99F9C8AFAB2ED9033262780AA97DFD88B0E810EF4ED113494B8B4556C46C287BED57E7F60E0FE2A93938C25F910ECCAAE27293243956F9D8E14F08FC0D6CF1E1F43E5FE5FEA8A1156C94DC94EAC01D61A47966CB7819AC17E8A6C9CB361F4B13DD43A61156D378EC627B0E7414A29BA7CB0300FF1EFA20CDC4A2D2CE25C628B5A6109F4542C23B6E2D3E27C808AD2B706399C23E392D350BF6D7C02F0926D9E40B2CDFB98971AA06DBE751854D8DA832824A68CDD67ADF855541F9B1004B48E921E69FFA23271AB2AC3F2F170035553B8A8A00C8C248E2D8A763A4C95A709A38C56622FB8F4E3694D5B923A2CD8E538F113E8A08DCF19655C3E5818586C334D4E09BC4703573D24DC77804B24EABCF3841F372CECC9954A56ECFCEE60431CB015C84FC6B61C11E15B5899A81D07EA453DE77551070EA5B484FD937CF5C3BA7E8380D38B474379AD0211E35281A4FF6A2291188853439D472E476B2E93FA44F707FB7BE136CA62AB3E9F02D2B864EE25B357621AC7C08AFFBE1B7D6C184428E7A59C0D5365E21DEA5328B183D540DA779A38CDF2B55B710A3B8181A853D04482829AA656C77B94DDEE372B77CAC11D8781F3C554D54C3A74583E630C3FF32063672E903DD4382A85E577043B0ED269D9A5523E1DD32974640BE7AE82E94A13906B19DC3521F1950E1A5FF054C593D413446B3646E738636878C5D2FC64BD602F7D731F7CFCBC297A979A4B2922972EFC28BFF3EA51CA87B504AB011FDECF3344216DC8C99921BBED2E697203B4E994E4F88CCD491329A4E15BA8D757E6804C0F13C0D37D9064B1648C435229CBA60E53A764D9CD4047FED34209F16005BA94D07E0C12E1C27C38406181C347096472AB7145FE3B24069CE1BAF274408FA690391B73CFA1CA56ECD497D5770E01BBB2B8BD424873CFDD8B3D1A28AEDD7DC4172A5489194529A880F1115AFEFF020224FFC7F1B199D7408D888F765CA6F75F4F000508A9707BEEC60E144572D8E13FEE95956968628003148332ECF06136A9504E4DFDAC8BB6BD4A1267809478E43D693A6E8ED6C104A05908A37C75087BDB5954CC6D0FABAA841B86F5DB6473134015F75D28CEC95E0CB87B0A687D37A704B9B7EA7BB9DEB76BA63DEEB2F0ACD7C1140AD02A7FF1422B3FB8CED19962738FFE453F561E908519451F884A015003E65D98D81A61CD8FD7DA2AD14BB4EB2E7FA80E28BFF59DCD12D9065B9549641FE599F41E582E1821C2CCAC0C4DBA6159E0BE7F0BB2847F2299EE23010B7114925C4AC8C2BBA87EDF43694A1824B08745686EA845C02A7BCE2D98F973D49500E79F563B8F0DC054C5F1D30E4826093BB5944D7095E662CF008628278D85C869A69B634AEA2735D4AD59CE0DAB044D6D2F94004A2B9C1591F2FB1F7F88ACD7F5AB252B7E72922287E4473014D26CC43AA3D631B6A0E98444AA8E31186F8A7922C3A6F911A3AD2F03F4372F143F89AF8B758DF20FF26255C31E5E8C3DA86816318AEE2DAAD6655A36CC36A375EDBDFDA241BE8DE13080163D59E6221A90299AF4D070D6658D8EEAA88553DDC03778EF9872DCAF19114F8D6D8B0C13ACB647C49FB0102D79A388148C52BAE905C9D787015463125B336193B495F16C8E35F2146F496EBF780C859EDFD95773B6A19E9E5E582220D2DADD167379F632D8AAD683CC9B1EAA77F141DA66B6F002339C6DAF929F67A57B14191A2829CC55EC5A940716F09FC5A9B08C23881D956A36E2BADFC84E5427A866E2E76B476B2A0DE1B9CD3FB6AE156C74A7689B08D25DCA0AEC4191E33CC091B181F8C67BFE2A5DD82EDFC226D49A1AC7BE8936C27DE05D243209276003A63875B43E20BDBF79D8CA81F7AC56AE94EF46CB3FC9BE5473DC0C9715BF8DAC744D093350B4C75560CB1C099681F0E440FD682A387E7AA70B3F335546F026C5351440A5D61E3C83BF96F07A46DE986A21F7E5A2EB0A28AAC2087C3896E933B708B4A44234EA8AE48946C6A10213521A553A020D7C9991CC31526A4E94D210F97E4216BD88504779F3EA21D52C2A205FA47CCD2405D26F411A9312D561D4CBCA0763311A0EBA45FA48CCE15C80419FE5CA04BF416395D25265280E0382BFDCC868C719874DDC795329E07CBF5C8FE83A3CCC4DDA4B31B15702AEBF561F53634315EC8B1A5423470DAB46963403E10EEC58E9E1C5C4DCB3935B518D4623E6C8C68A4FB13B492B155E06EE3D16BCE6C3E79AC891742AF3B8D01767542EB6B7BC8EC71579136ADE2BC39FD07AFA207C3D3012229267DCDF6CC3E9DB25AD378F836763BC517DDA13CD264C90983D73E2C9E2703740DB4C38773B49625967933F41FF0220F40C976385367675005FE20AECB7FBC1EF5C71255BEFE4A39CE59ADA83F148C5E4383BC65F0440A1F5826537EE40CD55862E7239ABFAA1D458F64F7423668EFE8E1E979B34EE18A71F82BD1975E09EE1613D9F45870B98B9855D28F3C00DA8B9740F50E0C51E506DF1C7C804FBD2A1DD912DEE604B2080069AFC5095D23D726D94552EB7986C14C86ADB5A1306C6B074F5D3605A6C2189C4D22E1C8795FDB77803C60E3CC04B82A021BB89BE2E3C45AC5B914966D4A3DDCBC32A760ED7BA6291B6C728F13AC684A6B6F0ECBEFC06B54249FDB3633A786E0822B1A2E43C3F59011263DA540FE2B4B5D31F5FE2A0954E45E106E1255EEFF02A717BB9061BDB528CBBB7854956824311A755B68EC1C179213C418AE21B7DCFFA9F9DFD8CAE58FA1D0B88670E5A25934E7F07916844AC026CD5E1F768978FC0F3AF91922014D75E50F4253A2C2E3420DB1856C206CA20651703D4AE01AE22B8C3DAC60B8961586986F17A93258ED44C83DA6276E04A9D0E03B04E93939FBBDBCAD6833960F02337AB1211E72BC180EED3DC605052CF86F31F1960DD8DD46E848584E909800DCF13146B6A71A79AA92F2BF8D254132423794FC2416A412B001C47A9875FA4B866868A9A88487FE410F81BE5236B13BCFE9302BA9443F3C4523CD3ACE7DE93CBEF6D9E4E6090214494027F065AA834CF24F6CBA9293A02934E52F20C1C2BC9609B559846B643BF49CAE7FB8332BB91B719E1F1838D7F63F5C3A7D5107431E3B854E03EBA795DE9C717B0C9D692B566138CB338C3E5C6F5931DC33214B74F3A116BED19B91E27572A5EB875F14EE81A8B5F2CA2C98739C93C04611335D221EE922C62F02E304BBE507E82E329B4359807F595D11BB5CF761619FF685034004A5ABC89BA4DE82FFAAD693221002F399A5F1D11302B68291F85079D10AA2D1C4536C70C7739CD16293EAD510CE3A04D91AB80D5BD2D02A93C6CF5BEF703A2273E628EA272987167F8A3E2F8E53C3FBC907C2A5AB051653051266470D74F14B632AFBEE256AB24CFC2C7F6E035A0580EC3D1DC11DB98C7FE605183884CF3D7F24C4B3A3D05A697F95601C367EDE314FD3D7CDCD618DB63BB7599E4577D6ED62E891CFD85C9B0E43F0CA588CF282A5E5070AF8E9CBEA9F1AA1FEC53CF411C3EC301967130267B769177AF5508DAFB62F5AD7D8AC9445C62E59612A54F77B1606BD9EEA24998726ACA7EBBCE63F73C143A56435B3EEFD63310A6DF908979DE38D04D7CC75B5FAD9548071D7D1647EC6AAD9663DB156622FBA093B1C470C535BA155FF88EB90BB7CAC9BF4CD367F8CF68CBC5129A577C31BAEFDA834CABB52E0D02FF1A44FF9E85BC88F4BE69DD5C1EB9D4A547395DCDF8DD82C1F98252266BA21395B4272A50420000A40A50CCB22546CB50617F2D7FCE96DA0DAA8FD668D3DF70F3639B45D25910B8970A6F26ADB6001DBEC9D78E94D020307793CAC8A4E69865CD8B7565765C4C4686B0941F7945095A4ECF808A46930AC66F0B569908E97E9557400D265AD10D2A4CDD023D421922BAF3DFD93D7120E4F2C4D20900BB32AE8242295B3EC9D61252BDCE14AC6EF5B2F73895DC27E5CDBD878F24369A533B33DD67ED239C61C333C9FD879D267446F1DEE3837B66C410E3AB8B8BC4C782CBD8449C7B2CC89E81C0CD0DBBC2DD6FE3AE7F2537DC3BE3E7EBCE49EB63A76FEE5ED0209650BF6E06344FE0A46693855AF3D87FC61DFA621D5CDCF0A39C80F2715392DF2C12685F37390982BAF96FF6475CB436DBC6DBCE4716781BE983393D197902C1C757B831BA1564149711D3D8231E908C8458AEFE45C3147A71F87E046193C6BF35FCCAABF592E48724C7E0582077FF94EF1DAE47D911BDBCC43876978BA38C7D6372B23DF650AD5F27C95BDBBA2352D492B5873C3835ECD142C5D3007A4D16FA35DEFD4C21F929A8B02ACB71CFCFB9540B489F9F0C2609CC2E26C5E85847D06E82B7E53B37C698659482300A18B9C42E962E9CDA8968ACAB266CF1340298693C87CC18AF9A52832449EAB89E84FE63BCBD45AC3F9BDAE65E62EE8F97F1165E40D874E9EF75763972A9413C81D18A1E551AE0208053B6276841F8470C23BF48F493BE5A0AA94AC10CB69F0E60267BDAE69EEE405312F8056A54C47A80CD01DC81EEABEBD8336FFEDBE19E8D66C566658D0F8EBE7999BFDD8FBC9BCCC59480F98B5701C8CA3156A94794ABFCF3132445832DC9A582AFC83BA2E41B6D64C8A1560880B7DA9976FB61F1C33ED52506570AC3BC65E345629A00A611A442928BD908A93CDDACC7D8D997ADC9AD9EDC836A803FB392593D03A79440D4F2F812B4C76CBD8F01D3B7119E42B98C64865EB2AA1626EF1B4C1877F6E484BC4D776C6C47712E88E9AF422D676103A71EB6CB31F360FC0EE898A6C28950A448D77CC07D513CB6A58D6364CB1480892DEEA7585CC9774A42F6AE49468A65A7215D4112C5B38AE6516798CA6A1281042F435AA4D6872A2AD8FD600638F0297B9C732E3D08AF5EAA9E24334E56C57C931B3D5AD37C5E5A5255B3038311A89C600944C0946008FA7F433EFDF3C60B8CB0083DCE9A46247E7B8C790E9ECCD03CAA10379C13D171B2C912927324A818D3EB762ED56B1B1C6EF068453A75B2C3757AED2D04333A11E21F12060EA5FE58B4649970A194E223CEC7B9D2BE63D57742317E93AA66F422E0AD7689878224E921CC95B53511069CA6C5492779864E3657CAE50AA46CD8BAE0B29D8DDEA69F05D41EEF627749BA606F1A614166D143923E0A43A1822D726613B24F4B7C691205F6C6F569EDC542228BB244A6A133D6A97BA66018F9AC0D79884B2623442536F17D9A3EDCBD00975A5890A34FE87C37B718A67A085A2B3579822D6673A3041BB61EE24072B5B67961B01DE05F348A63E15BFCB48D3EE991BE1699E11A06E02255F522BDBB1F74A5E90BC7F46FAA51EC84D1473BD47A9DDF9B0C226DB8602EF74D9D6A54E2685D6631EF6AC744F51BE6609B30BAA0DFADABAC90F6322C4D6D0CCE589F09A659FD2B4FCD7F70874FC1E32C7602D4A70EE1F1A0424445A3A2015185C80838391C80637B369F43896BB990A00D55D0C44CE10A5BF10C853E7702B9B03AEC1CFEB983ECEB22C22F199776CC7EC01DE1782D27359DE58A4B177B138D59934A2308E937F4A6EDDE167113E87001C6D485974DC7ACD95BD3A0C79436EF4A9305EAF894889CE7AA3FB758C2C98800EE51C37F4204C11716384A997FDD4F9CFDF71723B37B8D4F4B15E457126BB98ED49099F0881E0386F4CCBFB86F246AEA4A2790D1B62B6430E35271025CE8C710A1413D293959B8264F6C41FEA8EB007FFAF1FE0B57A0672F9ADB6734C2F8FBE051DE3B3E80670F8169DCFB30CB6EA4A7A9A7E56ECAFD79B4A8C7E35796F94E89A1795D9B7E19FC40253E27967338BC4883E7205E2D70765C38D8256BB2504BAB38274CD9645F3F9C65CDA32A50D09C1B7F98F0467D9FFE3A7385B6473EC2012F265D06BCD1522BC9B82019163632C63049D60C8F79DAD64BD92EA183B3FEDC67B450B88FFB825E0F3C36443394D6FD02D61D42881823D8E224FB0D93F68D39FE0C8AF40C08C7E5A438B9B686F3280B67CF7998532F53DFC01299C7732A69DE3076F28D14769A324620C5535EED84289AA55B06FFBF2BB4D73FA75AC8EB66609C5486559FCB920A2F4217F7FC25184A27D75B197F6C2A479D6900D1D56CFADAB446F002615736C9D541981928E08B4C4A75B6D9E0ADFA6795E374D71640EB096BD017BC16B9A6E71EFECABECC9E85040D9803C88A5F11F2DAFD49B506CDA6AE0EA5BBA9A627C0E89FA6B0D35FA493E4C853D728B1AB214EFE14E39A999E4872857F039C67024E106454328641577DBC7B74F441B01A613576BF0A21950B079937BC9427464CF4428CA5EC21AA34F55A0F42005845D62355FEA077B9E6111DD2402C715A972F8FA43C317713C71255D834588DBDB63B8F8C1DC5D672B346135E138D835B36334A38B0B1514FDD87EBB6D8FB8DC41D13DA74BE01A1823E417D3F932083FAD5F2FAA0B099DD03A002B5BDA0F1997B65B62E2097B948B406968CF7759AA75936CAA33B3279A1A92882A9C9A7109090E0FACF49790B1AD1BD606D551A806B1EF434D491AE50FCE2FD7B17BD605236E4E20616F7B7E27CA1C0592F25F3AA967EA41A73D72F4FE4F241610D4F7806E603A1A188EED49D4C7EB6F34CEC63F7E8B82F33B16D7CCE26CAC7151F4A7674667406941291FB0B6315CFEDCA1039B1B28C0E3F29FD3AD285B044C3C24D317A4D83D47985A2EB0F661AF5589F647D92554407AB5664187871F4D22869948A11E31E59ABCD8A14E314CC46D88FD8E2F4679C473B02C3FA0B5704BD2ABB65BD4917C3E6ED2CDB400CC4C82F9A7B9BC71C02E0AC7A029C159E894A88426E60599BE62F97223D12E318037A16DF3C2AB4F90A76F6594297CD5580DFC287D080AC03B445A9278F51C61E8D693123262014A2802201D92241C1269ABB4AD0ECC02FFBAE5AF52D2BA5AB08DF8CEF1D5116C809497279E7D4D9754AA5BD616BF0B5EFFD40195FD0BD17A180BCFE0585F8ADB1741F52DC34D403993C71519314F103FC207AED3F205DC546CD7996E2A2CD2712E26008A74B292A75A1011BA15E8D567BFC19A97C4359F5209A93600B81CA32A0CB1333BB535B699C0CE95496EA897292410D8C89B2FB9157002F82CCE582D62ADC159C08C85357FCAA0F9A10D137F09C5CB1F427725732BF1AE5D12C95045DC4B8F04BADF4A3BD6DA9D99E30D0C79C3FC49763883F77397D1908A74D84FC9BE14BE0AE638B4CB261FAC04EE77AA2BAA5745BCB4282ACBFEB4945EC820CF507B834C70DB6ADAD6A3E5D0796B375B6A29B42D7564EF51E43943C708FA28C4F565D5867FD7E6260D44FCDBB491B4F1394120002271EAD1C1DEC08CE3E942EB8D681D837EF9387E960B33762B59459CC1812E8A847F7EAD81E0220F4F0A4896DAE94C2C6967EC578AA4D56D0D7CF72C53D17D57DD00079D10CF2E98282C2060B483735BFEF6197619182D592E3D9D7540929DEA260D6BEE7F38A21C267AD0B7194A1FD37082117529F2DBC64A39E170343ED8B8717796D802A57B57975A1232ECD48C79D2713EC1EF8F6FC731118B78F081B680CCB79A0A4232DE73D1EACA3455AF0331921195A8E70DA28D8BD04C178198D55D6DF1C5A8C1B641C26FCE25270A6D07D2C1B52A824A2C089988C35191A98A6085EF3A000D22452AD2C55DB0B87CF00C6BF2AB7E66E341C03BAEA55899AC814DC988391250A4D666A9F98F4A1CB16C80B23C4A97309AD0D42EA85A2776D3F097587648CE0564826CE4127DD1E7314EA9A9CF4910E17EBDCC40B4CEC74647B7271C3B735DC5AE8E958CC30617F01C3BD61B5515C91C75B98EFD8DF09D8BA8DBD513C5CCDBF7C5152C340500B09EDFBA42EBCA260DA419FE8856B4B1F904782815261B3924A5F9347673C02CA252B666D6498518A79682B321A8BCF2514CFE07E387DE3CCA6F92AFD4C31D2E83381A1FA741F5760845202EDFBB55582D3CFF2FF2B04A7D469825F1976CD2A8C388FF958F88B4E52C5916B30E6FE03BB9FF6D721ABAC2E7EC46CF6DAC3362929F00321FBB0BA622E1E87A279D5B01D43326D4AD95574CCB2B77E5C8F5E7E9670F4F1EAC11DC3716E070A8BA20E1FFB4FDBB0B75FDACEEC6E4C426C31CDCFA95DF4A1E4E6FCA2D6D674E641CD707281B9D5EDB5DEF9AC42A212A1DCC342DE5C1057E49763A791EE7635F8194533BB2541A690688CAC2293FF19F26B12E2CAAD572B616DCD9058918866155347FC3B7DCFC5A9FD84A9E020126E57CB6DBB5C3788D8B20C9D00EA68DCB344988BC7D92AC98E3E6A278CB536F0AD1A0D0DD8A60D2EE9775347EA0654566734F3687FC669D270A4FD2574770740E1E85D8453E4C7A8A97BEB84F229A630632B1CC90857FE2666E08FB105AAEC690B22B9035766D5A2ECDD63326AF9B48A3247D7F4007947B9BEC525611223B0957532B818B5A686A027FC0C5DB24A849EB573CCC55C204A2EA6927CB1E811F17E4E23D11399C3F88874B79B455D9470FB47833B10258B6739C120533FCC0A64E97B87DFFAABC3982A62DAD557F01F926B2D01A44DA5845BAB6C784D1E226539663F9AB7C59FAC757CF8C930D0BA7CC74CD98B7A60C755BF63B2362F854BD0D4327C6829E53421122BE8E46C54687958B142857039E565DABBC660F289F40E3036E5FCB332644C9BFE40F88DD932FAAF338188D4B7DE60C3D9C2153BD024ECC1BF3E7B653A3704A14B7EA6437B03FF83DBFB25413528AE9D4E8BACE91B93323BF6006A982D34981AD395D3E52BD33337D02A8370C088C2616B9CFA71CEA8B1AC23D3053F85C4B4B195B7F1F7B2BC11D0CD5FB5FA4FA64D95D14F0FBC26873F31703E15A74EA25CDACE3D8AD595A2EEFF6385406A2CD9F182C24B05D842DA26AD7CB762C76E5B255803BC6A281243700ED74093B6974B88EF179FE09D70483CDE0282E26EE377D526B088CAE8B72AF4D82DC178D71FD05BA2DDF7A912602EDB6153F45E3250571D1CA84D49E543B3717DE7E876D19C543F0A0EB8AF9774A6E2E7A17C679DCF2345D4775F292B150FD5789DEAD85DD1536E5FBD9D3445FD5A78FD7A9761A8D588A8CC97720523513DED7D6E95CDF640C7F7D0667B3A09134571A2E741DF8A007EA56765AE6EC046BEE94439E675BB49B6E32EA14F56AA3FAB2AA45FEAF65938EFA7D83934B5487896152F7C0409BA2572C18C7EE4EF61A5484963586E10F709A1396AA2565DCD9C0B4736B56D205851D2452CEC5E324FA4CB6B8698EAC2C9CE9074A17558F23FB7BC14868B8E73B424C8CABFADCD4C5A3EBB6903CEB7543FFCC5585B85BFFA94DD2AA324C505D7F08EDBCC0024DA4E5C1671B6CE012E605AA6B1BFD58D92E8353F05DA5893E3D3822D76338A4D8013297C5F643D648A53F62E8920674B58675C64D0C662FA08FBBC1E9FBC088FCA457E14608CB0D0272A4C77735BA3A7A26D1DB6DD2D0845178F4FE627EBA84ABD7679B2F86E3D9AF2171927FC74104A9F198733FDECEE23D2D51431641F657A85D63244E96D2636096315F291C019197E73C9E11B5C5A015C12A43D176F6D33E34D9C423C1050545E4CB89DAB3E6A58A8E2FF3415B4831A91E72718E5D09832C4970D3C3D600CAE926FF8A24ED9D14A5E5A623C7A777639C145D306F20A9A5B4DB24C99F824F40B5BF387A0E1B6B49468A62755CC437E787DF96748EA3FA5E537922307E7C0694699D227350BA020A5DECF680599AD95F00C0D73F50B13E8385C04BA03C0F52BEED8F4C1C1D9132A3B9608AA1039169A8FA850DDB4CF01966CF881C64EBFD758CFB245B486FE5689C20FDA833F67DDDAD4CFE4638BFC7F6D967F039786A330D8393EAC7A52150DD7D5D30F79A09CFA383A5B7E96E3B2EB6BBD66CB3D6D844B0BEE333E06D027E4379259465A38516686255550A6074B1814100A60F84BBC3CE560AAD08B21821CE740D90EF12452BD53516DC90E60A4480CA758401660FE1A6EE8A88B433C14698CCC86C4A270338DDEA2DE2A5ABBE1C5CDA9F2C222590AC705A0C86F927D830EE91FD1A3B9ADF35C4EA05915FAB0F988D17C522971B7FD2431088020CABA03543C1E76255045A198EF900099FF2A982D626A4DD09F0E3B573E0660E2B09A8C0E7000DDCFAD466E890A4746D92AC1877A53215E35B9D3EE718B92A14706FBBC87B18A42D91CD4017AF5C6D2F549A052A09B57CBF186D1E9C004624D4A3A7A8A03A89C47353EACFB90647B2C6B29F73C506835E320DB751A1EAD0538B74DFD39B383FD7042B51CD82CF10DCE0C984AE75C12DE1A5BD614045DC91989095D32250EB1137827EC5E0FF91D5AE8807389D238AC331185DDC332C90CC9EE4394FD9EB81CDF04DE8D22F6856C5BEE1B4E5739FFB19CC8A948D24D764947FCBC99218B4DA2C439DC410BE7262C062486D55AEF977C09A36D9262E2BAA088383422BAAA20F4D8F86C3A4D8422851B6343AA15C4A1DD5EF0ACDE63937BE7D7F7444286BF00621CB279F49B47835925D71E07FCFED911E94D378A73548539CEAA7D8D84EEF4BE67EADF7C7B57452CDC106033D2B22DBB25D05856C4617E144F4E23094ED4D2BCB7A5DD1DEDD661432CD2AA369EC0B32169D52314A8646699B49DA27FC6C233C449884F540068127850D6E383DA6CA607A0806561363928FBB259AB5D98ECCF00B697E1810CB5422AC9B2F12AF205CB3721B5FE1680BE7C8E9B89A6EEE126E75866EB44B48B3DB48CA63818E6EB691002B2130B6C591F2605152E382251153A042708781773146D57C7B16D62D5FCC2252CCDCFF10EFFA1BCF2D4305C34E4F19F07595102B0A23929CC5470B9E16060DFB7D0F28956492A5DCC8825FAB6133D490BE3BCA7141F049A52548BB792E8A84B0C6A2F7B13196BB8C27DBCDAE620019EC8E480E6521393C98866B04863B8736039F42C23CA001E3B83178E1A65FAC153CC2F32EAD32440FF6A8A4AC29762903B32140B49BB59E591B6480BACEDEC7CDC77D89C82F60E23B5B127B72B9A271996E2C9FE310346D739045EDC020668D69D7EFA248FD6F786FDC4A5199685D68084A1B4ECB0719A8781EA366B630F0C18D023F57CB302D92F8153FB99ACA4EC2E16C943FCB944650EF9733C97F66F986945B8531B65CA531798CA139D8A31A1CC2657515B0FF4235F0EA527E0EFF2E83B9F160857956C894E60AD59345C95D2319CA82ED49306307B75800036D0CFE6689BF9672F9D065678861F7E174489B789FAC5D6942A792ABAC3D85359C36D35286A51DB42C022B305D182E65A9D11602B6D2E88AEC5A556EDF3979E1660F162409FA90C3FC1377370C9389CDCB305772A225671345D30055A528F27AAA77819A7819F64AD7185202827EBE0D92A1E30B05BC17F45E8422E2A0DFCD3BF1347841339842F908E30502CEDFFBDBF01E2A1CA4C8F8BFD8489FB6A60F1EA4A2BEA49A9F986A9BFE1792F97D0842B74AFAD6E97902FA043A087F2DF276C5D30DBB274A824208EEC77AF7B84B0D4D18DB495E976EE802AD61672EACD514F7CBD355FC7F11673D9198447BD142B6AC1A6225851BA2D7CD3565CBD3D8A7341915B40F713165D6B4B949140B91AF9F89E46FD45CE4ECCB2C259BAC0DE91ACC11442A8C146623A0A64ABA992816FBCE99C835554B6ECA8C53A04CF70E81067BA2854FD2332E9A3813F9A3F1E039D4CE9F349FC1BF9327492DA648740E5ADB7E470B513B9375D439FADDB93A6B928440A31FF6F1184C33E1342CD3B29AD04C22AA2D68F4F3613450B7CDB2A3590CF60C03401949AEA3AF2060047A25F37B6B4D81783A6E3BEB0E6F3EDF523667F25D6093FFC23C0B38C99DFEAA9A6EECA7A7322ACA8417F80F819CE53A3090811733E71EA07B5D3773553335EA7BDED1128D48087FCC05E5860546186B657233B4A370B26969D7E179C49BE552B0D17DB34537645DA06F6B1E40A897FA632D1623303671A20F38971357C139602A03BD170783F6F061FA433986AE9747F3D235B662D29D1DB7F077004E34133EEBA14B2C271F3C160AB1FEA528C85404EF08A33A23256BB47A0E55AFF01ADB49845AF72057F2B9FCC6C9927EC5EFC0B510D65D81A123D082B3AA20CBAAA1301C425CA97CD8EBB2FC9D0DFA17C8F0010343BE3E4B2764A269C598B8E541E02295707B6D30968C75B5EF76A1E27B6C5190B818AB5D543E3E8525D007AE95B948B53E81E96D349041DD97AC579ABC59FE1AC5302691FA88F8453D90BA87796491EDE09F70C67422AE3BA6A5914219321E3EE34DD59379E412009869E6A611D4E0CFC7A56D645AF62E130779438BB89CA54BD04ECF012C94B59A800987B449BA086C859C91F1FF5D4C2C5A558342B2B836DD427D45C07D8789EBAD66C2445F5931EFCDD4EEC651EE22081953C30F7DFFBE1B98A8295A545F829C256060A36849FD80D4BEA694A404B4252D86496521EA0EF4BA1415BE3C3A4FE687E67E715D15C7DA44CD7FA18A010F46E8F9221466CE53503D3A9840FB77D7765B84D5D4CA19223CCB22FE81BE7215C8DD0E49C84D787FA921456A6943C5892539062313FE024A0C2E24D15D75A8097D0D393C422099BED9259878E4EA02ECF174CA3B8F5C80D01E998487123C10EC2E04043A4D87154BEB2087C7194F74201BDC8FAE3D8F202EE83A21DF9E5B3B0908C9321F4431CF108444CF5A93175B4563B253F84897E3F720E8EE87E6B268DCABA7017BB07C5DD29133B5878B6CBEF6DDE103E3E34D8BF6DF151A3A24C077D8529BCD02681DC9E5701F93939B5AAC45FACE46A5855E4B4C3AF82C303999937C48CF3D88734EAF75E3EAF171768F6F48FE2CD5FA9BF40328E642D2510E331BE5C3AD6632875A9BD51D6904B95BD5C17B24C43971D45055C7AC0299017249A936BA40E3BD17B63B510F4B7A3B4F236BC073EEF4F61CE561D893AB5B0A720D70AC138D47CCD5426C827E1AB13B2C140FD6E6903EEAE7B30A06851759FDAA28810A258306160452486199EDD0F2B44F32361E8EDD4A458A93012DDB8B4C08A565DC49EC6BAFCC759237AE69DA0DA41251D9E7E8509E4A09A8917418C6B2705CF7C463CFE64A67F88749CCB80B8B1B20A33B5D9DC3F1E74BAE981AC670EE2D86D7B4C8E891F3D5C98B3F5455423412C641C0315F27A263DE975D8D6DE1F17D6FA51262D8E6B3F32AFD9EFB72958460B5D58F4BB5CBF5AE1CFF2D2835FA294760854FF53522E2D52981FC276793EE5EDA989EDC921CCDC50D4B63A908BF47587E4FAAE3A8A1BCE3A21E331D9230B6B1C4CEC7743AEBB83EE003690D2CCB27301D88518A43B266A2E2DA78742230B2258E5D1855A990827B3A8B900362791AE617A3DC0BA2D12766A70316229028E09F96EAD7C773158A549AD9E500751D812D3F759468E22B86FF85DFB0C7C79148CE152A813D0B2D3979A3DBE3765102204ECDA68D24FA6330D599481516603607FA04439B9A0498BCB359F1EE20D65A5A84816AD43750AD1838EF4597876291C98E82E1F46A6963C7726C89470E778BD0A65CAD07E2A167AF6067CD058152E9C14979152103A7235DCD0755BDD793F9B23AE031133756EE3448CD1F93985B40EBE72F7F54124838E3787182147B84C3B3BF8CA901253E04BF808E3F3AEB84C05AB5CCA8D0C755D7B0CB02BF9E06F3113FFC098557DA3F439D397251D48D2FADEBC40286A17C66E0A8533328DB4DFCE9BE32F115A293567E4EA004157045D6996C7B73F27ED2F25536C2A381996257FD23EE4D962B663940C2A57442F5A7CB41B4E6615B223E91B55A7F98B416B2A6003D3A27B496F5E1A446DA9F0DED6A5AA0D7C283F34DEF97065049150B136B2D0F7A4207C904D836EB1E35BCA84EF2780068ACEF1942C2B31BF1F89CF218044A30CED4AF8743EF034D7F526989B99390D79D7454961C4606F6AD659487A803F4CF5FDA4F0A039664F3EA84AC4D7E0E805759A79B959906655FFE28609963BD8BEF5C82A50922A9836ADB18C9416358C092D69292C40FB3BA288D4029FC6B200E59C7C2FC9423360B11F157E5286D0A796A74A088E257F00954CA0789E3507E572EF3DBA68E3CDC7AE328F2072BEABC0E901D5F5DB1A1F41D14732F471F089FEA9D022660949C80D350B37B7F2F551DC22F665DE00FDA868F131E30C110CCB4C746663513E9DA22E143796EE2E241CDC47E2BBC148A230157C0378193F75248FE64858899B3B357CDC21CE8A6C79D2438569CDBE5A44015038C0CB8C260EA75698C272C9D5B169A4D2FDA21AAAB502DE3C4609707BA7C1B2E118F3F5B8A17DEE019465C6EA6B098139BCA2E6873D9945791F7D5488EDC2FD08E09973A55415ECC21556C422F2E0057387363A3D762FE41B054D3C5ED107C4628C15A409C0ECF77AA5AB911A7D896C9D106DB44720A42E0F89447B9E8D277859C941A5E49F4A577C0B6B0049972DBEA98A1E57991F6C0D239BA052CF369D94CEA0D2AC4A0F178D0652F9E028E12423D8D14D7C8ACE33F7E9FA9C2F8B987F89B1BC22190146FBF99B124D028A5AC57D4B21A8F2A2C9BF1F67841BCF3F47051EBD205822DD7F13AEF2D9EEC54D465D89C987851630D0F7930B4451914393C31468126AE0C607ADF304433E581A71C5A19356231A9C7D9810D282F3DBE109F6789BB997BB73E97650844F62FA1954D9BA9C227A23A65F500AB459AEC13D0D25DAC9DC885A01912C70005F440B0EB1A2C0FAD96C7D597DA59AD0199F7978D8DC871BCD4B8143420F5F9900600FEEF0D8C908CD259AAF1D446841B2F76827CE888E1B8A2C2C2FA63AA0C63764E173FF170526FA3D7973931E6C1317F9E7175BEC6F2D6D9FB36730A604879CE7B2FF5350D1A689A57C5D366EA0C219A8E839838A0FCF45A2ED7FD08AEFD2BEC15C47391D9D18E42C18F03B068DE6FC160C176499D06ADBBAD50F1773D036CE5AAA26247B4ED0B68415D4CD101C8B97567290CE4068F4CAE9A778F996A3831FFEF44CA682100850BB5B6290AD8CAA7C10878352C707C0E7D0D0D90462DD46C6317755E4151FAF1755106983B75B6F0A3FCB923D56BE32573D59062008A48AD6A4A87D6242FB13DCC2A7354D470633D292F3EC598A24AF75362BF3A4096C7400A1E97E31FFD716D75BDE945F8FE5A2A40C8C557A5181E7C4CF155F0E1F168A0F25F3FBD0D24C743977C12F1B6D0B4CA5042017194AC81EDE63A324CFE149482AEB04CE5209F0BD768C7CE90508DFBF5EA9A66A5A6FE038746852359919DDC76795A68A4B522C86D5CFDBA46BBE140DCC5B377F70FFD7B776AD3A7885C43A9A7B5BCE599415FCAEB0CA7EBC1D51573F95822CB3135B602ADF40AEDE049501F6BA26EFC18D4A5E9814EA2C2C4CF301AF331672896A9B383F7E582F3A09BAE7BBCB9AB088A0D7FE43827C393E5EC27F08BC5E85C4705EDDA2862BEC9A4DD0ED9BC56D592F6062F75719ADB6A9CF1C8C2526D6B79E4F53932AEF6031D30498587788B0569F6C0FB226105FE5CA0B8B5239C3D11C795674DFE2C8B46FE16DFE5C389888775E56BD14DAE9985960D0817E5354FAE5F20147B30001A9E8D89E5BDEC5567561A27A08A84E2DEF8182060C003A8CF5DD667AC830497A9D4BD1D003019630FCA28C1E272C8C2EADB1DBECEF8E2CAB9B60BAFDFBD6D75562294E0E169506FACDFDC559581B86559720FB517AD8A010D64D03ADDD2CF9CFE8D2FD244A4378DE585F2DC009B2ED6DAC2FEC87D6097A25CC720E7DC989332C5A341503B7D03CC57A875A1A26DBA88D840F24EF8C86DBBEF37905CBA382A8A5C9980504D0CD6CEBCF00F7335705BFAFDE3C3F82EB3225E5EC63D6D69EFD015C9C51AF71B23215E4BBA667AD525852CA6C29AE3AB303AFDE0279C45668D02A2AA96625FA7B41B268E783F829A3A2464F22436917940E6EB3B1D313F794BAD2514B35954718CB2D92CD7865EBA847D388F046CC7D5D3E3B57D12714E9BFD4A09A18A8A626CDDBB21FB599EBE030CED022E16D6C65085EFC6911F7D154B8C9787D3C4107110809219414377EB07AF5441DFAF02EED0B6C7A6BAB1D9902D7A3211F22536AEC7A0A365BAC29BF69021B46EC80143CFC6B92DF4B09954DD20371C1E88087D73F0C885A68327486A812A1C9C36DA7E");
        byte[] sk = Hex.decode("FFEB02F6010609070CF80CFCFD01F7FBFBFE02010004FFF002020900F2020602FC090000FEFC12F6F6F9F601F6F904F9030101FE04FF020203010B0706FEFFF7040A040900F8050805FDF3FE070D060C0A00FE0CFE0D0D02FBFE0B04EFF90002F7FDFF030307F303FFF8F5F4F60505F9150304FD0AFFFA1500FBF409F801FEF909F3F3010201FCF90B17FDFD0101FC00F002F000FB08050EFEFD06F504F5F906EDFEFEF3FB07FB01FC0106FB0304FBF6080005FDF605FA00FB07FAFFFA07F8FAFF050810EC0001FDF107F9F2EC03F408ED06FFF70009F80C06F60102F6FBF4FB010207FB0A0304F9F6F90C02F80007F30D0C04F5FA0702FDFDFBFE0607FFF0FFF803F30D07FBFB010300FEF9FEFB0A13F007030A06FCFE03FD00FEFCFFFF070B1004F8FAFFFC0D0605FE0306F803FCF30506FD0211FD060507F8FCEF0CFE00FBF80DF20A0F02F8080011FD01EEFDECFDFBFDF5F8F4011210FF0403F8F3EB0D050212F3F80609FFF903F5F309F8FEFF0AFCF6000EF80BF6FEFA0C01F4F3F2F508FA02F8FF0A060009F9F70EFD04FB060005F3FD02FE01FC0DF30AF706090CFC0006FDF80AFD03FFF80BFA0CF30B070B0B07FC1003FB1404F5EC0709030EF701F705FB00FAF2F500000A0406FF08F5F202F8150F070BFFFEFA0603F9040303FC0206F8FCFDF6030507FF03F4070409080C1106F107F20AFAF3FEFF070CFCFFF4F5F10710FDFC070EF7F803FE060103FFF4F6F50D0B0202EFF30CFAF5F80C05FEFE070802F8FCFCFD02F81B100404080213F8F90C04FFFA080AFCFBFAF903F600FB00F60503FB0106F2FEE80003FBF9FFFD14FE04F50C03F70103F2FE00F5FAF600FDEF03F70AF70604FAECFBF70EFF01FAFE080803F20F0D1704FC08ED00F304F904FA020403F207FE0DFDFA040B1006F7F9EF06FCF909F903F7FD06F602080501FDF9FAF40106FA07FB0CF50C07FF12F702080A0900FDFFF8040A0BF20D04FD0F00F8F8FBFC00FAF0F91705F901EAFCFE0304FBF7F6FF0E0802FF0FFC020B02FC0801FE03F2FEFCFBF7FFEFFBF503F8F707000612FD0605040404F7F3F9F6040B01000009F5F901050202FCFCFA03FD1501F6F104000DFBF7000DFF0EFFFE0000030804F1FDF313F403FCFEF7090E0708F702FE0C040BFE0812FBFE0EFB0311F7FBFF00FC01F8F20405F502F40008F8F70FF705FA06E8FD09F8FBF2FB0704FCF4F3F5F9FE0AFFFF05020D06F4020413F500F703E7FFE30401FB04F9EFF407F9FF04000EFDFF0707EF0509FB03F506F9FCFC0400FF0900F3050AF50CEAF7030905EEF50C06FDF8FBFDFBF40400F902FC0300F6FFFDF7FCF1F014FB03FB09FE15FCFD02FAFF07FA05FE01070E0402FDF31102FE010802F902F4F90AF60408F9FBFCFBF503140FFB0DF80B0DFAF9FBFC0102FC06FA03FDFC04F90DFEFB0301F3010C0FFE0FF90207F80703FEEDFF0A000407F1F8000807F7051306FA090800FE0EF4F6F6080AF503F112F106FCFCFEFD0BFE020CF40DFEFFFE0F01F6FF08FE03F40B02F50406F401020301ED01080508F70907FA02FDFEFC030108FE08F708F6FBFD02FFFF0000FBF9F7030505F6060809000BF8FB00FC02FFEAFAFB030309F806020109070DFC030104FDF701F3030518F9FD0800F9F60DFCFF04F8F41108FF0202FE03F6FC02FCF706FCFDFE08FAFB04FA0B01FAFA080209FB0CF1050C0EFB03FE02FEF80CFFFD150803F7FDEB09F8EEF1F2EFFDFBFAFD0A08FEF7ED06FDF4FC03F7FAFBEF07FF06050A0307F710FB04F5FD0100E901FE09F0EBF6F203FBFCFBFA0008FE02FF0A00FA16FBFFF70BF80FEDFB0000EF01FEF900F9140C0E0901010606FDF2F4FC0FFF0EFF0EF8FF06F9080403FC04080BF7FA01F4040705FEFEFC0203010C090AF1FC01FC06FB01ECF3000B010E08EDF0FEF9FBF4FB0DF506F4F007F6FCF3030D0A04FBF9FDFA00000D010C00FBF0010100EAF7030DFFF608FCFEFB0207F601FCF80109020010FF100702F9EFF800F40109FCFE08F8FDF508F2F6FBF6010EFC02FE0101020D030BFCFBF2ED01F8010210080EFCFA000B120017FF051711FF03FAFBFB17F805FAF9FB0102FD09000CF90B1A0AF500FCF60EF7FCFC09F1050DFAF9FEFAFEF7F50CEBF5F8F3FAFCF6F6FAF308F6F505F6F9060A00EC05020AFAFDF9F50200FA0306F707F9FC150A000D0702070B03FAF5FE0EF7160D06FF050004F9FCFB05010107F2F50103F60305030610FF0B070A03F704F602EEF411FFF9F5FBF2F5F00101FE080BF303FB090402F30509031107020102FDF502F5030301F2F8FCFC07EE0A04F4FE030406040802F406F4060FF2020DFDF803FE01FC030AFF06F50A00FDFB12FB00F4EC04FB000B05FFFFF60EEE02FFFFF7F301FC0CFC08FB06EE06F8F9FAFCF5F30BEF01F4FE090400FDFF01F8F20BFCF40D0001F708F20304F906F20201FA0BFBF4FDF309060BF6FCFE1007ECF30202F907FEFA0AFBFB05FDF60BFEF5070CFCF60C00F5FB0AF909F1F40302F90D000503010705EDFFFE0103FC1004090C0007F80012010DEBF3ECFE09000807EFEF09010EF202FD0A04FFFBFFFD02F3010906F808030409F9FC0D010C0200060703040606F407FF0006FE05FBFA00FB0FF6FEF9F8091105EF09010300051304070DF80702FF06F30A01000102F7FF0EFD010500EEFBF802F8F6F9FC0602FE100105FBFFF7F8F00AFCF906FF0401FE02050A0205FB03140B040806FAF900F5F3F906F90FF9F604F602F705FFF8FE0A020C09FF08FE0FFDF6F3F6F2070002F8FEF1F90709000301F307EEFCFB06F9F7FBFEF9F50EFDFFFFFFF508FF00FEF6FEEDF7FC02F3150106F60803FCFD030FF9FF0CFD02EF0510F6020801F70AF7F8080502FFFCFC04F7FB090BF1FBFE0AFEEA0407F8F4FAFFFD0FF5EFFBFAF7EFF7FF000E00F906FBFD01F9F91A00EF0C0502FF050BFAFB09FE04FA0703FCFCEE0507010707EBF3130103FD04EFFE0DFB0503020C0D0AF7FB010000FDF409FDFFFDFB010BFBF404F0FC00F8F007030FF8F5FAFAFB00F700071205FEFF02FCFCFFF2FE01F00C020BFB04FB020206FA04021008FA00F609FD0C06FAF009F60FFDFA07FC090E0C090CFDF9F7FAFA07FB04F20BFFFC0500F8050DFF08FB09F30104FDFCFE02FE0AFC0CF9F70903FA06F6FBFF01F305F8000807F1F9040E07010A03010301010D11F502FDFFFEF2F9F904FE02FEFF09F4FF05E9110309F3F504F3F807F2FCFAFFFA0BF501FD040107FDF816FDFCFF040404F9F7060AEBFEFD07F50000050B00FFFDFD0108FFF806F5F60D09F909F610FB05FD09FF0C06080EFFFDFEFAF7F9F70B05FA01F4FE03FFFEFD00FFFCF8030D07040B00FE03F3EF03FE00F5F8FF00FAF9F80CF9FC0102FFFEFE0B0108FAF7F8FFF805FBFE02FF06FD0311F8FF0CFBFEFE060CFE00060200FDFFFA0C00F30EFC060608EFFEFDF2FA0405030707000108FE05FC050403FEF800060408F301EE03100CFFF700F9F2FEFC040800F8F8070104FA07FCFE01EDFE020A09F00EFA0C04F70CFFF002070BF908F50201FDF8F80AF90CF205020BF41103100205FB0104FDF50502FB02F7F907EDF3FBFC0E0E09FF0C0505050E020700FE00090609F60C03040FFCF8FB090AEDFEF4070AF3050D02EDFF05FC0503040A0AED0803FF09F50201150F0CFFFE0604FAFF0EF801F90CFCFBF9FD04FFFC06FF06F6EF01F811F807FFF9060407FEFF00FF060B030100FF02F902FD08F905FCF50700FC0D09FA0302F901040AEE0602F401FDF6021703F50406F803FEEAF10AFB01070916F0FD11000E060204F707F60802040302F60F0B09F802030001040114FC09FCFC0A0B05F5FEF80F04FDF8FFFD01F8F3F6FBFB00070704FF0FF70A06F3050D06F3FEFB040001F103100F06FA03FD04F4FD02FE05FA06FBF40FFC10F11407F8FB0AF6FEFB0303FBF7FCF4FFFFFFFD00FD05050900F20600FC0601F40D070403FFFA0505FB06F806FF01F4FC030910F70A03F20809FEF0FF04FFEC06FA090404FE01EB010106FFFBFDF9FAF4F91703F7FCFC07FD0DFCFF07000AFD07FBFB050CFA0702FCF60E04F9010603FB0501070AF806F6000BF6F4F9100BF4F90904FA0EFE0203FEFE09FAF3FD03F908FCFFFB05FC06FA0DFC0001FEF803F60200FEF80D10F80E0B030503FEF103140A02FB12FD0301FFFAF8F905000408FD070C03FEECFC01FFFA000F0C050203F9090404FA0710FE0DFE0FF4F8080808EEF404030909FE07F805F800F7FFF9F4EFFA0307FE06070005FA0FF5F3050A0400F8FCFDF001F2F312FB0D030E000C00FDF4050904010602F705F20207F708FA050E0B0206EF04F8FC000410F0F30DF7FFF508F7EAFFF9FDFFFA0504FFFE09F5FEFE1607FCFF0AFEF40206FC03F401FBF7FAF7F50402F3F8F9FCF8000903FEFAF801090504060307FEFE070E0AF6F501030FF501F40407031007F90206FF14F7F9F300FCF008FC0C060AFE04F905FEFC080704F6FDFE01F8FBF0FE080A0509FC05F803FF0E02FE0E05FA02FF1000FE050814FFFB03FBFBFF060CECFD01F901060705FC030B0BFE08F5F70300FDEE08F1F5F70204FDFAF4F6FF0705F50AF5030610F90F0C040DFE050001FBF9FCF60A05FE05060107FE0304F11104E3FCFD03FCFAF7FF0805FF0FFDF8FFFF050101FEFCFAF30C08F2F30107FBFEFF10F0080403F40309FF030B00FB04F50DFC09ECFBF506F711FDFEF401FF06ECFA0600020108F70CFC000DF9FBFD0111FA0002FA01F90008FF0B09000AEEFDEF01F506FFFEF909F80CF806FF0503100206F0F700F602F901F202F9FA1402F705F8FEF80A07FF0CFF000DF808FA0FF7110701FDFE0CFE100500FCFE03F1080EF60B080603FA06FB0802F9F30D03FB03FB020903FD080700FAF8FAF8F9F2FC0707FAFF0208F4FFF7FC140001FD090108F80D0AF1EC0AF909FDEE0500F1060507FAFDF9F6F8EE0204F3ED0308FE0B0101FE0C02F303F5FD0BF9F5F00C040102FAFF05FE0C010408FC06FD03F5FEFA030700F9090109FF0A000108FA0901F5FF00EDFEFD070705FB0600FEF2000E09FDFDF1020500EE0503F2F8FFFEFAF8F803050B0602FDFCFA0C00F708F40602EFED04FF0B04FB0115FEFEF6FF0AF7FB190006EF01FA0BFF02FEFE05FB010107FE02F7FD00F10EF4FEFE01010302FEF4030700030BFDF5F903F503F10D0904000A0A09000106FD0DFF02FA03F701FA02FD0C080F0D04FDF603F6F7F900F8FD0609EE0BF702EEF5F4F4F70105FBFA14F708EEFDF1FBF901F7FDFCF3F40204F9030401FA0203F103F90EF4110704FD00FBF001F60905FA04FD11F305FB0A0C0406F7FB04F6030A03020AFB02FD02FEFF0DFDFB04FDF9FC060B0905FBFBFB0BFF01EDF50200FBFD110D070803FDED0D010C0B0006EE0302040108FFFFFE0304F6070102EA0EF90701FD0711FCFDFBFF08FB06FCFD09EFFB0DFDFF01FFFA04FEFB0DF90A060D0407F8060D02FEFF05F90AF60DFEFEFC0F08FA0102FC01F6F6020501F407F90DFBF500030800FDFC02FC020AFE08F909F0F8FEFFFB03FD10F5F3FD04FEF80BF4F5FFF6FCF5FE03F8030107F500FDFF0DF2F2010AF90007010B07F2FFFB05FA080EFB07E9080614F6FE0E020206FA01F4F5FEF4FFFB03F6F2FD0000F60007090103EB0211F1040203F5F90901050D0F05E5F307F909FAF8FEFD00FEFEF9030C0BF2070605FF0806FC0011040309FF02FDFCFF01F404F80AF9F807FB00F5FF04FC0DF3F504F90DFFF900FD05FA0908F90303F50AFE0CFC0DFB0FFD120906FAFA0813FB02F7030107F700FC05FDFBFBFB020D030BFAFCFE1000F9FEFE050303FFFB10FB0104040B0B09FE0102FCF7FCFC02F6F9FFF90BFFF90F01FFFEFEF9F6F2EFFC0309FBFDF701FA12F605F7EE06FCFE04FFFB03EF0814FA05EFFCFBF0FF0BFB18FEF7090BF3F50011020C060604FDF015F706F30EF30206FE0A0403010507F5FB00F902FC0C03F901F718FD02000703FAFCF70B00FCF3040602FDF8090106F800FBFAFF0BF9F902FB0615F9FF00F401F9030709FF0305FCFB08FFFFF505FB00FBFA00F611F9FC0A0A04FE11FF021207F7FBF702FA010305FE01ED07FD030E11F900FE000101FBF608FD080F0D0DFC0BFDF900080F020FFCFBFC030513FDFFFC0EF7FF07FE0C09F4140602F70201030501FB07F30C040D0603FFFE010603F2F90CF70203FBFCFFF2FE0801F507F8FB0405F8FD07000C0102F4010009FDF5FFF2FE08FE01FF07070908F7FD0E0601120205FB010606F8EEF9FDFBFD04F80304150AFFF9FC09FA0BFFFB03F80B07FDFE02080DFC020CFA01FDFA0B0702FDFBFAFF05EB04FC03F1F90C03F9EE0F030B1202FA12060505FFFEFDFBFC01FE02FEFE1400070AF8FD0204F7F80DF10714020805FE02040106050C0315F60704FC1201080A0307FE0004100A05F407FDF60AFEFFFCF40400F9FFFCF9F810F00203FBFFFF07030A00010E04F5F106FDFA0EF80D12FAFAF20EFB05F20307FEFFF2F809FE05070800020009F0F6FEF7EC0A0601F2FEFA0AF508FE060004F606FBFBFC05FDFBFE02F9FCF7011100F6FAECFAF7EF030EF9FD0DFC000202FA0B0103FAFD03FCFAF8000F0703FBFDF4FD08FDED09F70B07FE0006F5F508F202FDFD0BF2020807FB0FFAFFFD04010408FA0803FFFDF7F00001FEF4FD01FDFB0E05F4F8F9F6F3F40406F709FA0EF805F7FE010B0309FBFBFE0706FE0B03000D0701FCF30610F3FEFAFFF6F80311FF09F60804EFFD0F080706F805F104FFFF0605FCFD05F9FB040BF614F5FC0502FA0705F4F6FCF407F4FAFE03F6130600FF06FE05FD0208FEF90AF7FCFFFEFDFC0EF6011101DC12FDF70407F609080D0CFD02030AF4000305FAFAFBF10C05F6F0F9FCFE0009F7000100FC08010DFDF805FDFDF5F7F7EC11011103F9060505F4FE07FE03FC0308040E04FEFB0305F9F5040AEFF9F50601FF010AFE0C00FEF6F9FE0BF80303FE0303FEF40A070D080308FE05FFFCFC11FFF501F9FAFAFBFAF9F701F9F5070703FAF7FCFFFA0C02FE0D07FEF20FFDF8F80705FAFF02FE0308FEFC01010C00F70813061103FFFC01F90CF3050C010F05F50101FB1202F805080D0701F7F302ED0AF40B0CFCFD0005F707F813F9FE02FC0101100401F90CF70B08FE0108010000170004FD06FEFCFB010106F9FFF80702150D02F902F8F1FA10FE03F9FB09F1F6FEFF0906FEEB10FB06FE04FBF5FBF806CFC6B92DF4B09954DD20371C1E88087D73F0C885A68327486A812A1C9C36DA7E4F5C254B6292FB5C3DB9561B8793D8AE3E1611423AC0A9F8CFC13E1C85FEC6B5");
        int smlen = 2881;
        byte[] sm = Hex.decode("1A8FBE71887EBA96C44F36AF4FDF1B81329E7965BF152679D92EEFA250AEB4E7DD23D31C5A3BAA6BE605ACFF3EE79C1FC6C48D97891F136C4214B2A25A6465527DD97EDA9DC84593AF544E02048E772A74B75823AF07D39B4E28CB4E316230925778A5F2055711CF7F7A274941DD9106395CC4D9FD659A9C1E90F1B11C81AFCD9C2F9B5F6C64D1B62228CACDBAD3EFF26FA205F659F5B79E25148E06E3D768D18511E0B90062605974F0A9F1829DE78EC3208760BBE34A56E6B8AA037F9DB3A0F868753321C59C420DC570F9A7EE6992B847DA993B5A038EF4AE0FFE985D3297B45395173CAFD4976FC37B2AA70283E9C8915D272940397D21960C746D126790BFD43A1C6D03D9E1708E247A2F832DEE0AE387698C37B624CCCFAD26B4A3363AB8825C8E2501BC204F6B0578AF171BE1A88C1BB2AB88E89A21CAA1C604125ADFFBAF46609DFC01F22C59DA3ECC78CF6EF3EA9F2FB5D15DEC3C723D81C8CD895BBF3753782026ECA9975B872F8E85B3F375F0BF40DD7EC6830EE0858FB6470F8A788A21189BBCDFA61316A0D9E49B0117D2726F72EBB2F730C88AD4D76E0ABFE4801B36FC0BC3CC8514FE2F8BA05396DD03B897C564185E90B3E3B8559ADD6E9689CC11DC45F50E27D549704D79CC5EAB7A85BD25420DFD83F0C68B56B2B5069BDBCDA20A39930BBAE70396DD0CA35DA7E9FDF3D09AFF121AFB6DB40D63F15EEC54BBC8BACC9C229BCD650BC5D117597C7FD9D60DC792EFD4B32DBDC550D2D3DCAFB7C77800905C427F79FB4C81867F6B1BAF6119FFCA4799789A682795CE803AF398182AF92A1EBE6645BD793BA3C0641D9F8E9765F5B7081889219072763D9032549E03D4C9D825B2B8C5E34EABE189E083003F4CF0C5D9890E755E3D51EDFA8A4D14F4D3DE989187D1BCDC0D9BBC5E3E25C3277087E1A6EA1F47E6ED29E0C48E2CC80E29E3F868656DA301B845D379F886BC2279BF4027754D0F8BF833899348706DC3C20C5178A1E91E5CC38280291D05300D9B8C937BAB8F8DD52CF82B039DA547B8DF8AA60E15194B1E3E61C13CFCC785740E4D0609916AE5502A42007338F33225550F5FAB2EAB1749876478CA7052E6FCCD60E51D629DC70C20E3B5C8C088D9C4483CFA791C5508ECC8F4FC559364CADCA6A108BB5E0C23E4DDC1C0B8329663E3872CFC33A8CEEC0634561A0AD6E2A940A7526DCA17E5DB3FDAFAF712352EE9E83C834C5DDCE41947B1115D0CD71D35A362C58043035131A870EE1C1AA4340F1F4F21F8882A5E0FA069E2C8645F853A8CEF5557C6DEB87CC609434131074EBC1358DEEA690A8EA021D99C9C8975E57B887433BC4CD14148A645216F15315EE63EEA174950E8EA9F02877DA8797D5C6A7A69100C5115377DF31EE637675EFC2466A42B621EB131FBFA8EDBB76798EEC329444C481FD2307F9C7A39E317E05EFA82784D59F84FB042EA328064058602754D54DB5E40E28B9C0336A4F4ECCC4C2886DFAEA1B9613B5DB5FD7586B8CF6E777D9271971109A1818B9632864BC24512420A3EB61BD03A00FAB0F77756CDDBD8707F4F38E8EA8DBBE7F420C0729A65DC230B9D43E7D6AAC8FE9FB0F1B3938FC1E2D2FF4FF2D798AA2812EEBE4539BDC3FBE6A95F67D61051D9D2597F5D306CBB328DFAE70BAEB3754D327636C1026ADD5C0D75670C9BB56F6B159FC629B1237238D24FFD4EBC698EFF040410807C30811D21F59B6A67124030FB2083BB6F86982782EE1CD18EECFB58D7062C11339784144C6BF3F34CF0A96AD5452E9796A7E662937D906189A839F4E6D40F7CA7AD89B3A1B52558FEC20B68191B64549006F36B3FF31F9891040F9684DBC8DE48B277A55408CEE7A38087FB9BFDEC2B899D4190378F6F26B0BFCF2965CA461CE9CD3D5CFF54A197FDEE95E23B977D9567DB840544BBA5444AD7F4680AE7F3D736653C3FD7D8BB43D6493DB3644E2A11685D563B74499B94B2005DD909BD0F1A7AD6402ED2A0B5DC778542BDE9A65F3A0BCE35D8C03DBBC41F582A8082537773D9910FA1BDF8704EB5C6B99307124D9952C5917B13909E4833352DDC73F9A17B8019BDFF0413E16EF2330A1B2930670C977EE44160B1C22EECBF4E4CD3C1D2044CBB1E24D24B202CCF002BFA12FCA3D8731B3DEDD5AEDB767062A517D82C1AEF3EB20CA7EDE83D64212AF8CCC90F6CF648D2F0705B613DFFBC4FAA8EE2B3F15E81F1F8CA3885647CB754DBDEFE0E96C4F9999A8359AB4093EF21AB4BF72CA61583F4FDAB034EAA5E8337B9F0346645462860913B3ED357711DC018D9985BE5C3179BAF35139D39EA488B88BB070D523A5AD9FA7B360D7951D0214D6734BAC6EB40FA59588EDA3E23F3DD07B6A6C91644EF19785B59D49CD5EC439E73E4213E46EC5FC1E673BFDF5A99DF2C661B46B9E2A2B27AEB9FB462611F4F1DDDC65EE1585154326E71515E2B20EBF35D057E1A6F794D5DD52B5E87BB2B5CA46C00381568847C4ED353028F02DD0FE4B3E7FDDEE1C5B50BDFC2EFEBDDAA2F276FA689C194A35AFC44592E266C630C902F5A7B2CB06F97456924F0EADBABE4488CF0E2CFB5918C2A95F4F63AD2AA32AE727F43A3352F8B7BB26262CEC8AA8FFF7E83873BD64F5A17ECDFED210F578A9E2C9B530CCA1DFA28634B844D4ABD4A6AA649678BA7698D3242D32E6E64E89EF60EB39B8D1989C5691AB1C79EE242DD152B97111C6C871731E6503BBC65155E6E95BD3A1FA9C13F5905BFC396A4860236F5434CEE94290F6FD74A5F531DA5823322EC147F628FF6A6317E4B66342E4A2DEA3B7755A0B6483B6DF8910C27CB45E2F78AA5D6A4D822324EF3A620039594615625CF45CC8E700E2B1CD467B1823559C9DCEF70F9F12E45C70C27E5A5073E9A7A5EC6E08FD0A9D05EF4E02E4CE3B0B372CB2314E6FE2D56B99397D92C099FDB31E34DDC479F73E7086BE45A63DBDA7631CB771DA132828ECDA08F91FAD9CC06CA26CFBC605F5D41D8CD8A2E3518B4234BF891946A591B52CE4D41104FCFDB33C6A594F8BDB19B163C0FBBC34560918E488E1FE12E3FDE4669605EE3D28A9D9D7D143D3F8F8CD0FE63913094FA6AB347031EC8EAB8E069C9BA9ED39CE9765612A3F387BEA6B01E404850F70A3E07B038DCF57E3CFB1EC2EBFF349373921780524FB3B5C50749FFB88624E2FE4019DACC253B3421E08104CD31CE76482D3F882262531FDDCD17A30DD0C7DE4BA12EF537BC8DE4514DBBF48C5640BCE5D683C5A48ACE662A4D109E02686AF6ED546F807F8B5EF618B240C3CB8B98EB58D060485EFD3E39665158371D880C22E4DDEE5BC90000039283D52CB5CBECFD08C1FFCAC063D4B87C83A55D39CCE55D51250BC54452DE0C049243BE86827B006643FC396C2A2FC54C23A0A0DA249325EA6E0A1D801BA75143908F776C627680945C4DB46069767CE8F3AD26FE2ADF457FCB6F5D96796740F31930FE48493B77720B90D1AD646B8771470E77F42DA1573F40394D5DA4E8D71E451CAFF1944071A994278C26B50E3FBAA34C6102F5DE823A279D3280AE42E2973D39665404490902E573BC8021084C5A7559452E0978751AD65C161FE202282CB15484461AD06E815AC90DF18537191A535029D0F650B01F2B44111D01172A7C8545BBEFF80B0664871D714E3E4B8F773384082BC7B4456A79F48004B35201C6F6AFC8222E11E1F58250C7A33FB67EBCA408F762302545759E0F6CDF65D562EEF948EAA38663F1796FD3037F140A9310392BA1C7A4E2CF9D5EB0078D3DA3A2AF4FBF5BB3558CF00E16D6F2F59DF81C4794A257771C7FEA3F3BEC7A48207685BAA0BF5D7E9E9E0E8042B219F2ECA73E6C14DB051BA37DA60501DFB2623C9C7DF216B8E25E8076CC386A4C3A7C5B2C1B66833EA585C727CC0D4E38582BFC580539956A9BD790B868870F49FA8D6E597348D294045E1DF1F1B9FB18D1A68688278ABCD9FA51AA306516078E16377A371B2E69FD92B01656E3813CE22EC095F08F72E7E97D491AAA1E2996A017C5F91FC0449DD81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");

        byte[] sig = new byte[4000];
        int[] sigL = new int[1];
        QTESLA.signingPI(sig, 0, sigL, msg, 0, msg.length, sk, QTESLASecureRandomFactory.getFixed(seed, 256));
         System.err.println(Hex.toHexString(Arrays.copyOfRange(sig, 0, sigL[0])));
        // assertTrue(Arrays.equals(sm, Arrays.copyOfRange(sig, 0, sigL[0])));
        int status = QTESLA.verifyingPI(msg, 0, new int[]{msg.length}, sig, 0, sigL[0], pk);
        assertEquals(0, status);
    }
}
