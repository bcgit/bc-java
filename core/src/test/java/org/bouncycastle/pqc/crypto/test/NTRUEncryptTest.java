package org.bouncycastle.pqc.crypto.test;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUEngine;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.TernaryPolynomial;
import org.bouncycastle.util.Arrays;

public class NTRUEncryptTest
    extends TestCase
{
    public void testEncryptDecrypt()
        throws InvalidCipherTextException
    {
        NTRUEncryptionKeyGenerationParameters params = NTRUEncryptionKeyGenerationParameters.APR2011_743.clone();
        // set df1..df3 and dr1..dr3 so params can be used for SIMPLE as well as PRODUCT
        params.df1 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.df1;
        params.df2 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.df2;
        params.df3 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.df3;
        params.dr1 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.dr1;
        params.dr2 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.dr2;
        params.dr3 = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST.dr3;

        int[] values = new int[] { NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE, NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT };

        for (int i = 0; i != values.length; i++)
        {
            int polyType = values[i];

            boolean[] booleans = {true, false};
            for (int j = 0; j != booleans.length; j++)
            {
                params.polyType = polyType;
                params.fastFp = booleans[j];

                VisibleNTRUEngine ntru = new VisibleNTRUEngine();
                NTRUEncryptionKeyPairGenerator ntruGen = new NTRUEncryptionKeyPairGenerator();

                ntruGen.init(params);

                AsymmetricCipherKeyPair kp = ntruGen.generateKeyPair();

                testPolynomial(ntru, kp, params);

                testText(ntru, kp, params);
                // sparse/dense
                params.sparse = !params.sparse;
                testText(ntru, kp, params);
                params.sparse = !params.sparse;

                testEmpty(ntru, kp, params);
                testMaxLength(ntru, kp, params);
                testTooLong(ntru, kp, params);
                testInvalidEncoding(ntru, kp, params);
            }
        }
    }

    // encrypts and decrypts a polynomial
    private void testPolynomial(VisibleNTRUEngine ntru, AsymmetricCipherKeyPair kp, NTRUEncryptionKeyGenerationParameters params)
    {
        SecureRandom random = new SecureRandom();
        IntegerPolynomial m = DenseTernaryPolynomial.generateRandom(params.N, random);
        SparseTernaryPolynomial r = SparseTernaryPolynomial.generateRandom(params.N, params.dr, params.dr, random);

        ntru.init(true, kp.getPublic());  // just to set params

        IntegerPolynomial e = ntru.encrypt(m, r, ((NTRUEncryptionPublicKeyParameters)kp.getPublic()).h);
        IntegerPolynomial c = ntru.decrypt(e, ((NTRUEncryptionPrivateKeyParameters)kp.getPrivate()).t, ((NTRUEncryptionPrivateKeyParameters)kp.getPrivate()).fp);

        assertTrue(Arrays.areEqual(m.coeffs, c.coeffs));
    }

    // encrypts and decrypts text
    private void testText(NTRUEngine ntru, AsymmetricCipherKeyPair  kp, NTRUEncryptionKeyGenerationParameters params)
        throws InvalidCipherTextException
    {
        byte[] plainText = "text to encrypt".getBytes();

        ntru.init(true, kp.getPublic());

        byte[] encrypted = ntru.processBlock(plainText, 0, plainText.length);

        ntru.init(false, kp.getPrivate());

        byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.length);

        assertTrue(Arrays.areEqual(plainText, decrypted));
    }

    // tests an empty message
    private void testEmpty(NTRUEngine ntru, AsymmetricCipherKeyPair kp, NTRUEncryptionKeyGenerationParameters params)
        throws InvalidCipherTextException
    {
        byte[] plainText = "".getBytes();

        ntru.init(true, kp.getPublic());

        byte[] encrypted = ntru.processBlock(plainText, 0, plainText.length);

        ntru.init(false, kp.getPrivate());

        byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.length);

        assertTrue(Arrays.areEqual(plainText, decrypted));
    }

    // tests a message of the maximum allowed length
    private void testMaxLength(NTRUEngine ntru, AsymmetricCipherKeyPair kp, NTRUEncryptionKeyGenerationParameters params)
        throws InvalidCipherTextException
    {
        byte[] plainText = new byte[params.maxMsgLenBytes];
        System.arraycopy("secret encrypted text".getBytes(), 0, plainText, 0, 21);
        ntru.init(true, kp.getPublic());

        byte[] encrypted = ntru.processBlock(plainText, 0, plainText.length);

        ntru.init(false, kp.getPrivate());

        byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.length);

        assertTrue(Arrays.areEqual(plainText, decrypted));
    }

    // tests a message that is too long
    private void testTooLong(NTRUEngine ntru, AsymmetricCipherKeyPair kp, NTRUEncryptionKeyGenerationParameters params)
    {
        byte[] plainText = new byte[params.maxMsgLenBytes + 1];
        try
        {
            System.arraycopy("secret encrypted text".getBytes(), 0, plainText, 0, 21);

            ntru.init(true, kp.getPublic());

            byte[] encrypted = ntru.processBlock(plainText, 0, plainText.length);

            ntru.init(false, kp.getPrivate());

            byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.length);

            assertTrue(Arrays.areEqual(plainText, decrypted));
            fail("An exception should have been thrown!");
        }
        catch (DataLengthException ex)
        {
            assertEquals("Message too long: " + plainText.length + ">" + params.maxMsgLenBytes, ex.getMessage());
        }
        catch (InvalidCipherTextException e)
        {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }

    // tests that altering the public key *AFTER* encryption causes the decrypted message to be rejected
    private void testInvalidEncoding(NTRUEngine ntru, AsymmetricCipherKeyPair kp, NTRUEncryptionKeyGenerationParameters params)
    {
        try
        {
            byte[] plainText = "secret encrypted text".getBytes();
            ntru.init(true, kp.getPublic());

            byte[] encrypted = ntru.processBlock(plainText, 0, plainText.length);

            NTRUEncryptionPrivateKeyParameters orig = (NTRUEncryptionPrivateKeyParameters)kp.getPrivate();
            IntegerPolynomial h = (IntegerPolynomial)((NTRUEncryptionPublicKeyParameters)kp.getPublic()).h.clone();
            h.coeffs[0] = (h.coeffs[0] + 111) % params.q;   // alter h
            NTRUEncryptionPrivateKeyParameters privKey = new NTRUEncryptionPrivateKeyParameters(h, orig.t, orig.fp, params.getEncryptionParameters());

            ntru.init(false, privKey);

            ntru.processBlock(encrypted, 0, encrypted.length);

            fail("An exception should have been thrown!");
        }
        catch (InvalidCipherTextException ex)
        {
            assertEquals("Invalid message encoding", ex.getMessage());
        }
    }

    // encrypts and decrypts text using an encoded key pair (fastFp=false, simple ternary polynomials)
    public void testEncodedKeysSlow()
        throws IOException, InvalidCipherTextException
    {
        byte[] plainText = "secret encrypted text".getBytes();

        // dense polynomials
        NTRUEncryptionKeyGenerationParameters params = NTRUEncryptionKeyGenerationParameters.APR2011_743;
        NTRUEngine ntru = new NTRUEngine();

        byte[] privBytes = {2, -94, 95, 65, -107, 27, 98, 62, -15, -62, 21, -4, 119, -117, 7, 68, 100, 113, -36, -82, 87, -87, -82, 24, -45, -75, -74, -108, 105, 24, 123, 117, 124, 74, -27, 42, -106, -78, 114, 27, 18, 77, -41, 105, -113, 39, 49, 46, 109, -69, 61, 77, 49, 117, 14, -29, 42, 3, 120, -121, -120, -37, 95, 84, 60, -9, -31, -64, 31, 72, 115, -15, 21, -6, 27, -60, -73, -29, -33, -81, -43, 106, 65, 114, 102, -14, -115, -96, 9, 54, 23, -18, -24, -76, 84, -41, -79, 35, 88, 11, 41, 67, 44, -63, -28, 76, 84, -41, -103, 106, -22, 35, -2, -40, -48, -121, -128, 76, 63, 123, -11, 103, -35, -32, 21, -51, -99, -40, -103, -12, 64, -80, 57, -56, 1, -51, 103, 83, 50, 111, -87, -98, 7, -109, 25, -51, 23, -92};
        byte[] pubBytes = {91, -66, -25, -81, -66, -33, 25, -31, 48, 23, -38, 20, -30, -120, -17, 1, 21, 51, -11, 102, -50, 62, 71, 79, 32, -49, -57, 105, 21, -34, -45, -67, 113, -46, -103, 57, 28, -54, -21, 94, -112, -63, 105, -100, -95, 21, -52, 50, 11, -22, -63, -35, -42, 50, 93, -40, 23, 0, 121, 23, -93, 111, -98, -14, 92, -24, -117, -8, -109, -118, -4, -107, -60, 100, -128, -47, -92, -117, -108, 39, -113, 43, 48, 68, 95, 123, -112, 41, -27, -99, 59, 33, -57, -120, -44, 72, -98, -105, -91, -52, -89, 107, 119, 87, -36, -102, -83, 67, -8, 30, -54, 74, 93, 119, -3, 126, 69, -104, -44, -24, 124, 108, -125, 73, 98, 121, -49, -37, -24, 87, -71, 91, 8, -31, -50, 95, 112, 27, 97, -93, 3, -73, -54, -16, -92, -108, -74, 88, -5, 23, 70, 69, -49, -46, -50, 65, 69, -54, -41, 109, 8, -80, -23, -84, 120, -77, 26, 99, -104, -33, 82, 91, 22, -17, 113, -29, 66, -7, -114, -101, -111, -47, -1, -3, -57, 62, 79, -70, -58, 45, 76, 28, -117, 59, -117, 113, 84, -55, 48, 119, 58, -105, -20, 80, 102, 14, -69, -69, 5, 11, -87, 107, 15, 105, -69, -27, -24, 47, -18, -54, -45, -67, 27, -52, -20, -94, 64, -26, -58, 98, 33, -61, 71, -101, 120, 28, 113, 72, 127, 50, 123, 36, -97, 78, 32, -74, 105, 62, 92, 84, -17, 21, -75, 24, -90, -78, -4, -121, 47, -82, 119, 27, -61, 17, -66, 43, 96, -49, -6, 66, -13, -75, -95, 64, -12, -39, 111, 46, -3, -123, 82, 12, -26, -30, -29, 71, -108, -79, -112, 13, 16, -70, 7, 100, 84, 89, -100, 114, 47, 56, 71, 83, 63, -61, -39, -53, -100, 23, -31, -52, -46, 36, -13, 62, 107, 28, -28, 92, 116, -59, 28, -111, -23, -44, 21, -2, 127, -112, 54, -126, 13, -104, 47, -43, -109, -19, 107, -94, -126, 50, 92, -69, 1, 115, -121, -52, -100, 25, 126, -7, 86, 77, 72, -2, -104, -42, 98, -16, 54, -67, 117, 14, -73, 4, 58, 121, 35, 1, 99, -127, -9, -60, 32, -37, -106, 6, -108, -13, -62, 23, -20, -9, 21, 15, 4, 126, -112, 123, 34, -67, -51, 43, -30, -75, 119, -112, -58, -55, -90, 2, -5, -46, -12, 119, 87, 24, -52, 2, -29, 113, 61, -82, -101, 57, -11, -107, -11, 67, -42, -43, -13, 112, -49, 82, 60, 13, -50, 108, 64, -64, 53, -107, -9, 102, -33, 75, -100, -115, 102, -113, -48, 19, -119, -72, -65, 22, -65, -93, 34, -71, 75, 101, 54, 126, 75, 34, -21, -53, -36, 127, -21, 70, 24, 89, -88, 63, -43, -4, 68, 97, -45, -101, -125, -38, 98, -118, -34, -63, 23, 78, 15, 17, 101, -107, 119, -41, 107, 117, 17, 108, 43, -93, -6, -23, -30, 49, -61, 27, 61, -125, -68, 51, 40, -106, -61, 51, 127, 2, 123, 7, -50, -115, -32, -95, -96, 67, 4, 5, 59, -45, 61, 95, 14, 2, -76, -121, 8, 125, 16, -126, 58, 118, -32, 19, -113, -113, 120, -101, 86, 76, -90, 50, -92, 51, -92, 1, 121, -74, -101, -33, 53, -53, -83, 46, 20, -87, -112, -61, -87, 106, -126, 64, 99, -60, 70, 120, 47, -53, 36, 20, -90, 110, 61, -93, 55, -10, 85, 45, 52, 79, 87, 100, -81, -85, 34, 55, -91, 27, 116, -18, -71, -11, 87, -11, 76, 48, 97, -78, 64, -100, -59, -12, 19, -90, 121, 48, -19, 64, 113, -70, -14, -70, 92, 124, 42, 95, 7, -115, 36, 127, 73, 33, 30, 121, 88, 16, -90, 99, 120, -68, 64, -125, -78, 76, 112, 68, 8, 105, 10, -47, -124, 39, -107, -101, 46, -61, 118, -74, 102, -62, -6, -128, 17, -45, 61, 76, 63, -10, -41, 50, -113, 75, -83, -59, -51, -23, -61, 47, 7, -80, 126, -2, 79, -53, 110, -93, -38, -91, -22, 20, -84, -113, -124, -73, 124, 0, 33, -58, 63, -26, 52, 7, 74, 65, 38, -33, 21, -9, -1, 120, -16, 47, -96, 59, -64, 74, 6, 48, -67, -32, -26, 35, 68, 47, 82, 36, 52, 41, 112, -28, -22, -51, -6, -49, 105, 16, -34, 99, -41, 75, 7, 79, -22, -125, -30, -126, 35, 119, -43, -30, 32, 8, 44, -42, -98, 78, -92, -95, -10, -94, -1, -91, -122, 77, 0, 40, -23, 36, 85, 123, -57, -74, -69, -90, 89, 111, -120, 22, 5, -48, 114, 59, 31, 31, -25, -3, 24, 110, -110, 73, -40, 92, -26, -12, 52, 83, -98, -119, -6, -117, -89, 95, 83, -25, 122, -26, 114, 81, 25, 110, 79, -49, -39, 10, -78, -65, 57, -90, -46, -126, 15, -124, -104, -89, -66, -87, 24, -45, 39, -34, -40, -13, 106, 12, -25, -116, -47, 79, -81, 64, -17, -31, -70, 87, 36, 46, 102, 107, 48, 88, 34, 46, 24, 63, -100, 106, 27, 58, -71, 38, 60, -66, 45, -89, 39, -60, -116, -14, -119, 118, 0, -24, -9, 38, -71, -79, 124, -119, -64, -9, 71, -56, -82, -73, -69, 127, -1, -20, 123, 32, -43, 49, 5, 49, 105, -5, -2, 5, -105, -111, 89, -30, -41, -49, 61, 80, 69, 44, -33, -116, -45, -96, 63, 28, -17, -106, -94, 90, -40, -88, 122, 116, 116, 113, -65, 104, 119, -3, 96, -45, 18, -120, -111, 83, 43, -5, 101, 71, 48, 104, -112, -95, -46, 53, -96, -93, -126, 96, 56, 104, -111, 114, -1, -44, -120, -112, -19, 100, 41, -122, 23, -78, 33, -35, 11, 57, -18, 106, -40, 74, 61, 66, 54, -77, 96, 70, 108, -128, 91, -97, -36, -23, -86, -91, 44, 58, 117, 2, 26, 44, 95, 79, -101, -81, -92, 110, -81, -12, -88, -21, -83, 60, 93, -121, -114, -48, -34, -119, -1, 127, -121, 54, -128, -106, -39, -108, 81, 17, -3, -13, -57, 74, 41, -122, -65, -107, -118, -65, -61, 103, -69, 19};

        byte[] fullBytes = new byte[pubBytes.length + privBytes.length];

        System.arraycopy(pubBytes, 0, fullBytes, 0, pubBytes.length);
        System.arraycopy(privBytes, 0, fullBytes, pubBytes.length, privBytes.length);

        NTRUEncryptionPrivateKeyParameters priv = new NTRUEncryptionPrivateKeyParameters(fullBytes, params.getEncryptionParameters());
        NTRUEncryptionPublicKeyParameters pub = new NTRUEncryptionPublicKeyParameters(pubBytes, params.getEncryptionParameters());
        AsymmetricCipherKeyPair kp = new AsymmetricCipherKeyPair(pub, priv);

        ntru.init(true, kp.getPublic());

        byte[] encrypted = ntru.processBlock(plainText, 0, plainText.length);

        ntru.init(false, kp.getPrivate());

        byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.length);
        assertTrue(Arrays.areEqual(plainText, decrypted));

        // sparse polynomials
        params = NTRUEncryptionKeyGenerationParameters.EES1499EP1;
        ntru = new NTRUEngine();
        privBytes = new byte[] {116, 7, 118, 121, 6, 77, -36, 60, 65, 108, 10, -106, 12, 9, -22, -113, 122, -31, -31, 18, 120, 81, -33, 5, 122, -76, 109, -30, -101, -45, 21, 13, -11, -49, -111, 46, 91, 4, -28, -109, 121, -119, -121, -58, -113, -9, -10, -25, -53, 40, -86, -22, -50, 42, 52, 107, 119, 17, 33, 125, -26, 33, 55, 25, -77, -65, -106, 116, -67, 91, 105, -7, 42, -107, -54, 101, 12, -12, 57, -116, 45, -107, -17, 110, 35, -64, 19, -38, -122, 115, -93, 53, 69, 66, -106, 17, 20, -71, 121, 23, -21, -45, 108, 97, 23, -98, -12, -41, -31, -53, 30, -42, 15, 85, -21, -89, 118, 42, -117, -39, 69, 0, -63, 83, 48, -80, -14, -123, -4, -116, -90, -107, -89, 119, 29, -30, 69, 22, -84, 47, 117, -123, 102, -116, 35, 93, -13, 84, -9, -122, 58, 101, 93, -106, -119, -35, -75, 76, 27, -125, -22, 68, 101, 49, 103, -13, -98, 93, -56, -110, -19, -12, 74, 104, 7, 6, -11, 47, 57, 90, 75, -30, 47, 66, -58, 14, 14, 70, 11, -119, -36, -118, -55, -53, 101, -73, -77, 33, -29, 96, -86, 38, 47, 103, 19, -37, -17, -50, -82, -87, -119, 37, -54, 77, -69, -16, -48, -52, 110, -26, 111, 35, 26, -53, -10, 9, -108, -34, 102, 7, -18, -72, -26, 24, -50, -43, 92, 56, -94, 23, -36, 60, 28, -121, 27, 127, -93, -79, -45, -60, 105, -6, -88, 72, -41, 47, -51, 3, 91, 116, 75, 122, -94, -113, 28, -96, -62, -29, -74, -85, -93, 51, 58, 72, 44, 9, 18, -48, -24, 73, 122, 60, -23, 83, -110, -7, -111, -69, 106, 51, 118, -83, -18, 109, -32, 40, 22};

        pubBytes = new byte[] {-62, 56, 59, -46, 30, -19, 22, -115, -20, 117, -14, 3, 2, -57, 85, -24, 27, 57, 49, -93, -52, 87, 49, 96, 15, 95, -95, -86, -61, 50, -18, 3, 109, -55, -110, -57, 82, 124, -5, -57, 68, -18, 126, 114, 6, -22, 8, 121, 125, 29, -16, 112, -81, 27, -7, 109, -44, -123, -15, -14, 74, -126, 95, -94, -91, 119, 80, -48, 41, 49, 6, 104, 93, -97, -108, -82, 93, 70, -127, -113, -22, -103, 35, -115, 20, -115, 63, 57, -84, -18, -107, 81, 44, -16, 83, 71, -27, -2, -125, 87, 26, 100, -116, 110, 94, -46, -56, -82, 119, -110, -127, -99, -8, -118, 90, 64, -29, 102, 99, 92, 86, -117, 26, -89, 32, 17, 55, -65, -10, -5, -74, 19, 13, 113, -15, -103, 17, 10, -127, -95, -79, 19, 11, -24, 59, 28, -70, -55, -69, -105, -20, -117, 66, 4, 77, 116, -124, -62, 19, 109, 49, -120, 10, -15, 108, 84, 126, 122, -46, -37, 114, -78, -72, 34, -12, 25, -104, -3, 114, -94, 16, 31, 31, -124, -109, -64, 57, -47, -113, -26, 97, -58, 112, -40, 49, 80, -54, -115, -98, -60, -123, 91, 14, 75, -86, 77, -93, 68, 112, 82, 79, 28, -25, 49, -27, -112, 103, 60, -128, 95, -63, 2, -51, 2, -107, 80, 113, 18, 123, 24, 70, 77, -56, -48, 33, 89, 88, 29, 112, -102, -15, 52, -96, 17, -9, 6, -11, -119, 29, -107, -84, -19, 84, 124, 19, 90, -60, -41, 123, -81, 96, -119, 17, -61, 62, 55, 95, -73, -13, -60, 56, 77, 24, -39, -107, -78, 47, -91, 88, 90, 34, 112, -80, 83, -58, 127, 76, -97, -40, 78, -20, -1, -62, 19, 6, -43, -46, -36, -53, -22, -28, -119, 8, 19, 79, -9, -54, -126, -3, -20, -110, -82, 51, 3, 1, -123, -41, -40, -11, 91, -52, 48, 104, -11, -2, 49, 45, 52, -33, 109, -44, -30, -44, -83, -108, -10, 77, 106, 82, 3, 14, -48, -18, -79, -64, -34, -63, -18, 122, 33, 25, 44, 82, -112, 111, 68, 97, -58, -38, 25, 62, 78, 97, -36, 57, -19, 122, -18, -74, 67, -127, -24, 32, -45, 67, -106, 90, 0, 1, 91, 30, -80, 95, 9, 78, -4, -14, 16, 111, -56, -102, -90, 52, -1, 116, 19, -127, -23, -87, 103, -94, -111, 118, 53, -69, 77, 17, -3, 31, -53, -21, -78, 124, -88, 52, 117, 34, -52, -77, -107, -38, -102, 23, 73, -76, -88, 95, 64, -85, 12, 36, -86, 86, -17, 77, 121, 90, 24, -49, -107, 33, -116, 65, 13, 91, 118, -107, -21, 65, -59, 18, 125, 61, -65, -68, -19, 23, 88, 60, -6, 78, -8, 69, -62, -118, -93, 97, -64, -67, 28, 28, -87, -97, 72, -125, -119, 4, -43, 7, 22, -15, 52, 52, -82, -5, -51, 99, 20, -59, -2, -54, -67, 40, -128, -20, -37, 50, 123, 32, 8, -39, -105, 93, 73, 77, 84, 43, 89, 88, -6, 7, -108, 81, 27, 1, 50, 16, -101, 67, 95, 119, 105, 70, 99, -127, 22, 127, -33, -19, -113, -55, -100, 122, -86, 98, 53, 27, -95, 4, -121, -96, 87, 67, -98, -37, -10, 92, 29, -3, -115, -23, 37, 8, -30, 99, -117, 62, 101, 83, 49, 60, -83, -47, -33, 41, -118, 76, -7, 111, -15, 123, -59, 53, 2, -20, -57, 24, 57, 62, 84, -26, -11, 93, -118, 54, -13, 56, 77, -66, 18, -62, -76, 80, 98, 26, 120, -93, 55, 103, -1, 78, -92, 120, -23, -60, -75, 11, 53, -62, -94, -80, 120, 113, 33, -24, -64, -5, 23, 120, -14, 61, 26, -1, 56, 79, 34, 116, -16, -95, -71, 40, -89, -50, 71, -117, -109, 2, -2, -34, 94, -78, -88, -27, 70, 94, -86, 123, -49, 107, -65, -67, 84, 90, 123, -61, -2, 43, -119, -93, 75, -4, -81, 98, -36, 125, -23, -37, 81, 104, 90, -63, -52, 88, -96, -44, 25, 3, -37, -123, -48, 113, -76, -94, -109, -115, 37, -39, 104, -124, 82, -73, 100, 48, -54, -40, -65, 81, 16, -85, -41, 60, 42, 117, 65, 77, 14, -8, -56, 52, -118, -109, 125, 13, 64, -20, 125, -37, -74, -28, 118, 112, -126, 18, -101, 11, 75, 30, -4, -121, -13, -65, -13, -122, -53, -52, 20, -2, 67, 18, -106, 67, 83, -111, 15, 106, 10, 113, 53, -112, -3, 118, 8, -56, 40, 53, 23, -123, 96, 87, -118, -97, -116, -47, 85, -73, -85, -82, 124, -55, 55, 61, 46, 12, -6, 34, 22, -22, 3, 115, -49, 102, 23, 46, 39, 0, 118, 3, -45, 48, -73, -38, 29, -36, 11, -127, -86, 30, 29, -2, -108, -114, 64, 110, 86, -46, -91, -64, 95, -40, -65, 49, -79, -126, -37, -103, -71, 53, -85, 45, -51, 33, -28, -126, 36, -77, -120, 55, -54, 72, -21, 58, -87, -73, 18, -12, 20, -100, 30, 118, -83, -22, -90, 71, -64, 108, 101, -46, 36, 105, -46, -91, 60, -113, 72, 100, 82, -90, 106, -127, 65, -94, 17, 77, -10, -112, 46, 118, 72, -84, 57, -86, -114, 88, 91, 79, 30, 107, -35, 61, 81, 71, 40, -29, -6, -107, 61, -62, -6, 65, -68, 118, 61, 110, -115, -119, -73, 104, 59, -66, -89, -127, -8, -67, 122, -38, 79, -13, 93, 1, -32, -47, -3, 62, 88, -112, 105, 73, 96, 73, -104, -126, -69, 21, -22, 16, -85, 116, 9, 82, 54, -15, -55, -67, 68, -23, 16, -89, 48, -17, -107, 60, -43, -34, 66, -114, 63, -3, -26, 68, 68, -86, 120, -111, 99, 61, 101, 27, 93, 31, 90, -33, -94, 29, -89, 41, -80, 26, -23, -80, 27, 107, 69, -45, -123, 62, 63, 80, 1, -28, 52, -8, 35, -86, -127, 76, 102, 83, -104, -79, -98, 77, -28, 118, 18, -15, -98, -39, 2, -58, 95, 64, 105, -82, -7, 96, 110, 104, 127, 126, -124, 26, 36, 33, -42, 59, 82, 127, 42, -24, -61, -50, -18, -87, 22, -32, -125, -70, 103, -121, -112, -94, 58, -95, -97, 53, 95, -61, -83, 42, 37, 80, 51, -118, 125, 15, 67, 41, -97, 41, -121, 29, -88, 100, -113, 39, 101, 47, 91, -36, 48, -56, -13, 12, 37, 0, 81, 3, -40, 8, 36, -65, -11, -32, 108, 62, 79, 70, 91, -83, 2, -47, 0, 91, 10, 87, -19, -40, 96, 106, 41, 120, -53, 40, -114, 90, 64, 59, -115, 39, 2, 53, -49, -72, -114, 94, 5, 49, 74, 13, 50, -14, 76, -123, -11, -81, 100, 120, 16, -41, -72, -118, 28, 41, 98, 122, 27, 18, -108, -43, 51, -71, 93, -13, -42, -64, -118, -106, 45, 108, 72, -128, 58, -123, -29, -114, 15, 52, -72, 108, -62, 75, -15, 105, -89, 25, 37, 13, -21, -109, 68, 5, -89, 69, 10, -46, 18, -57, 77, -103, -74, 57, -43, -110, 1, -80, 82, 5, -9, -49, -53, 83, 4, 44, 64, -117, -67, -11, 1, -65, -81, 34, -23, -71, 14, 105, -93, 2, -120, 90, 92, -6, -128, -16, -51, 27, 123, 71, -117, -72, -81, 26, 28, 5, -117, -30, 22, -72, -76, -32, -14, 82, 90, 69, 74, -94, -72, -30, -17, 12, -37, -3, -80, 72, 2, -40, 41, 0, -53, 48, -37, -117, -128, -120, -80, 28, 49, -52, 114, -119, 92, -42, -105, 125, -95, 78, 76, 123, -56, 32, -66, 69, -58, 57, -77, -100, -70, 125, 53, -115, 8, 116, 88, -34, 86, -75, 55, 64, 79, -113, -124, -91, 50, -82, -119, 50, 11, 87, -14, -25, 15, -1, -49, -127, -5, -50, 72, -29, -78, 101, -119, -21, -15, 97, -63, 57, -123, -94, -24, -8, 104, 86, 79, 49, 102, -8, -76, 8, 69, 99, -64, -108, 70, 36, 71, -127, 56, 39, 78, 109, 42, -42, -2, 126, 17, -88, -65, -23, -64, 78, 87, 7, 6, -82, -98, 41, -46, -10, -25, 90, -73, 24, 127, -27, 118, -9, 81, -3, 115, -4, 47, 86, -30, -9, -50, 32, 86, 114, 58, -5, 78, 74, 36, 29, -126, 116, 117, -114, -92, -121, -36, -86, -18, 55, 49, 112, 43, 111, -99, -116, 70, 60, -63, 87, -4, -35, 15, 28, -27, -65, 66, 115, -33, 112, 94, 74, -22, 104, -56, -27, 39, -8, -53, -120, 8, -109, 73, -68, 67, 40, -59, 59, 121, -76, -41, -80, -54, -88, -120, -121, -118, -58, 74, -120, 82, -88, -113, 30, -8, 54, -126, -106, 37, -43, -74, -56, 40, -76, 93, 91, 28, -59, -30, -2, 107, 6, -89, -69, -121, -125, -109, 5, -94, -7, -2, -5, -67, 54, -90, 39, 5, -80, 93, -99, 82, -100, -128, -8, -39, -109, 66, -11, 99, -41, 18, -32, -122, 69, 6, -95, -21, 9, 19, -117, -34, -42, 11, 20, 84, 89, 91, -61, -13, -7, 55, 90, -15, 62, 59, -4, 125, -127, -24, -124, -99, -63, -23, 52, 111, -52, -60, -113, -65, -26, 127, 57, 21, 102, 101, -77, 66, -116, 117, 80, 7, 1, -96, -29, -99, 75, -73, 44, -99, 61, -73, 15, -18, 89, 95, 104, -12, 94, 33, 13, -49, 118, -84, -122, -2, -121, 62, -32, -80, 11, -10, 102, -67, 20, -3, 25, -6, 51, -17, -123, -76, 103, 3, 127, -107, -5, 122, 65, 22, 113, 120, 6, -19, -110, 86, 55, -88, -124, 0, -54, 17, 112, 15, 105, -28, 111, -93, 85, -59, -88, 28, 123, 55, 117, 10, 76, 54, -98, 116, 40, -65, -53, -80, 46, 66, -8, -114, 102, 66, 67, -117, 46, 21, -116, -38, 58, -105, 101, 37, -16, 5, 55, -33, -87, 72, 122, -114, -91, 41, -114, 77, 50, 109, 35, -61, 9, -55, -118, 126, -35, -108, 5, 62, 125, -109, -115, -55, 32, -71, 69, 110, 87, -82, 119, 26, 103, -77, -38, -13, 113, 74, 69, 116, 94, -21, 5, 35, 73, -80, -87, 80, 13, 108, 1, 82, -56, -35, -21, -78, -98, 121, 112, -117, 72, 47, 76, -97, -84, -110, -35, -19, -120, -13, 127, 5, 56, 72, -22, 110, -8, -71, 0, -57, -125, -101, 60, -64, -32, 1, 126, -109, 9, 84, 117, 62, -68, -106, 28, -118, -52, -81, 112, 11, 55, 68, -86, -65, 123, 83, 55, -72, 110, 63, -90, 31, 11, 90, -60, 20, 14, -36, 5, -92, 11, -100, 64, -57, -72, -105, 7, 103, 125, 99, -88, 32, -5, 41, -115, -11, 89, 81, 77, -33, -7, -123, -17, 109, 59, 40, -12, -61, 98, -91, 19, -36, 108, 118, -124, -82, -40, -124, -66, 19, 127, -73, -39, 99, 43, -16, -44, -83, -77, -34, 68, -118, -71, -116, 114, 120, -34, -105, -32, -46, 102, 73, -79, 7, 42, 35, -66, 125, 34, 113, 66, 78, 71, 6, 44, -17, 4, -80, 38, -59, 12, -8, -78, 103, 8, 80, 18, -74, 20, 3, 56, -20, 106, -1, -12, 83, 4, 68, -119, 84, -87, 97, -53, 102, 119, 34, -85, 22, -26, 55, -107, 96, -70, 77, -68, -96, -15, -22, -77, -55, 5, 103, -42, -87, 122, -80, -103, -37, -120, -56, -16, -51, -7, -19, -104, 120, 9, 54, -85, 48, -76, -38, 58, -68, 116, -20, -44, 22, -32, 75, -46, -41, 13, -100, 16, -59, -93, -115, 54, 22, -110, -46, -119, 44, -98, -48, 4, -58, -115, -57, 103, -56, 36, -63, 104, -114, -125, 92, 65, 117, -21, -59, -31, 56, -98, -126, 56, 47, -116, 100, 122, -98, 4, 26, -29, -127, -113, 73, 48, 106, 125, -69, -127, 62, 56, -79, 76, 84, -46, -31, -17, 94, -98, 62, 63, 118, -24, 63, 123, -93, -46, 103, 117, -120, -35, 19, 25, 15, -110, -125, 12, -75, -50, 103, 49, 47, 98, 92, 10, -88, 54, -53, 19, 25, -90, 93, -49, 64, 126, -106, -30, -52, 58, 37, 68, -18, -60, 15, -27, 93, -124, 88, 110, -80, -106, 88, 55, 108, -58, -43, -70, 76, 85, 98, 27, -66, 18, 75, 69, 114, 90, -26, -10, -12, -126, 84, -109, 108, 15, -115, 90, 11, -127, 63, -7, 47, 92, -72, 38, -58, -35, 18, 25, 12, -103, 0};

        fullBytes = new byte[pubBytes.length + privBytes.length];

        System.arraycopy(pubBytes, 0, fullBytes, 0, pubBytes.length);
        System.arraycopy(privBytes, 0, fullBytes, pubBytes.length, privBytes.length);

        priv = new NTRUEncryptionPrivateKeyParameters(fullBytes, params.getEncryptionParameters());
        pub = new NTRUEncryptionPublicKeyParameters(pubBytes, params.getEncryptionParameters());
        kp = new AsymmetricCipherKeyPair(pub, priv);
        ntru.init(true, kp.getPublic());

        encrypted = ntru.processBlock(plainText, 0, plainText.length);

        ntru.init(false, kp.getPrivate());

        decrypted = ntru.processBlock(encrypted, 0, encrypted.length);

        assertTrue(Arrays.areEqual(plainText, decrypted));
    }

    // encrypts and decrypts text using an encoded key pair (fastFp=true)
    public void testEncodedKeysFast()
        throws IOException, InvalidCipherTextException
    {
        byte[] plainText = "secret encrypted text".getBytes();

        NTRUEncryptionKeyGenerationParameters params = NTRUEncryptionKeyGenerationParameters.APR2011_743_FAST;
        NTRUEngine ntru = new NTRUEngine();
        byte[] privBytes = {10, 16, 2, 30, -40, -63, -109, -77, -72, -122, 66, 23, -30, -44, -82, 0, 95, 64, 68, 48, -62, -14, 26, -19, -72, -25, 72, 123, 98, 84, -83, 0, 7, 40, 65, 35, 68, 113, 12, -112, 32, -123, 58, 85, -30, -109, -74, 0, 34, -8, -126, 57, 30, 98, -107, -45, -88, 102, 68, 42, -30, -108, -89, 0, 38, -40, -61, 37, 82, 113, -115, 123, -100, 5, 46, 125, -23, 78, -111, -76, 36, -90, 67, -31, 10, 2, 96, -127, 21, 50, -79, 13, -125, -124, 38, 55, -67, -95, 81, -107, 12, 117, -86, 99, -127, 11};
        byte[] pubBytes = {108, -76, -104, -75, -87, -65, -18, -5, 45, -57, -100, -83, 51, 99, 94, 15, -73, 89, -100, 40, -114, 91, -107, 104, 127, 22, 13, 5, -16, 69, -104, -126, -44, 119, 47, -48, 75, 66, 83, -37, -66, -84, 73, 52, 23, -27, 53, 63, 56, 14, -2, 43, -59, -85, -80, 46, 38, -126, 75, -8, -63, 88, 104, 13, 72, -25, -10, -58, -51, 117, -84, 115, -24, -53, 83, -103, -97, 46, 90, -82, -61, 113, -49, -24, -72, 24, -124, -42, -36, 7, 41, 8, 14, -71, -75, -84, -24, -39, 56, 67, 88, 67, 66, -13, 70, -119, -64, 74, -100, -58, 35, 105, -20, 93, 80, -116, -55, 37, -52, 64, 0, -36, -71, 8, 77, -10, -41, -22, -73, 4, -115, -74, -74, -73, 23, -10, -26, 48, 125, -114, -32, -116, 74, 19, -104, 59, 43, 4, 97, -84, 112, 45, 16, 3, -110, -13, 119, -6, 29, -80, 109, 82, -31, 82, 30, 76, -111, -122, -50, -69, -41, -123, 107, 78, -35, 24, -121, -87, -108, 13, 70, 32, -74, 112, 104, -40, -61, 86, -125, 60, -94, -5, -18, 55, 54, -128, 83, -88, 71, 71, -66, 29, -113, 120, 30, 16, -38, 37, 96, -90, 38, -85, 88, 59, 15, -69, 6, -8, 1, 1, 71, 12, 60, -26, -110, 97, 77, 33, 58, 63, 104, 108, 83, 72, -21, -99, 115, -125, -16, 12, 99, 68, 39, -97, -6, 17, 26, -59, 123, -110, -37, -71, 47, 50, 5, 110, -34, 89, -74, 20, 79, -108, -7, 42, 106, -112, 44, 107, 106, -50, 55, 127, -124, 53, 123, -119, -46, -114, -52, -85, 75, 34, -39, -125, 58, -5, -31, -81, -37, -94, -123, 113, 11, -104, -124, 96, -103, 9, 108, 115, 97, -6, 98, -43, 26, -89, -23, 83, 60, 34, -86, -54, 107, 78, -48, 118, -31, -19, 29, -106, 108, 117, 83, 119, 51, -45, 115, 108, -13, -89, -29, 29, -120, 108, 20, 22, -3, 22, 78, -109, 95, 3, -68, -10, -53, -117, -96, -49, 9, 7, 38, 116, 33, -65, 31, 9, -5, -73, 127, 52, 113, 87, -39, 119, -96, 74, -105, 75, -89, 63, 69, -109, -127, 92, -54, 17, -98, -23, -69, 123, -125, 23, -93, 44, -11, -25, -101, 120, -29, 113, -33, 0, -117, -100, -114, 22, 41, -46, 29, -109, 107, 37, -94, 125, 46, 17, 16, -65, -14, 105, -118, 51, -21, 121, -5, 56, 29, 30, -69, -38, -10, -77, -74, 6, -105, 83, 110, 23, 114, -11, -123, -14, 30, -11, -9, 84, -90, -20, -29, 72, -85, 97, -74, -59, -112, -15, -51, -105, 117, 123, -17, -64, -127, 127, -33, -102, 88, 77, 122, -127, -15, 121, -125, -32, 53, 113, 45, -22, 84, -87, 20, 36, 65, 83, -84, -66, -22, 4, 15, -108, -92, 109, -128, -48, 4, -27, -13, 25, 51, -10, 34, 87, 88, 38, -87, 89, -64, -62, 20, 78, 35, -26, -2, 55, 3, -72, -64, 30, 28, -105, 6, -37, -38, -8, 26, -118, 105, -37, -30, 85, -66, 105, -46, -37, -11, -72, 71, 43, -65, -44, 17, -79, 98, 79, -77, -111, 95, 74, 101, -40, -106, 14, -108, -112, 86, 108, 49, 72, -38, -103, -31, 65, -119, 8, 78, -89, 100, -28, 116, 94, 15, -18, 108, 101, 85, 8, -6, 111, -82, -49, -66, -89, 28, -84, -85, -119, 111, 45, 83, -60, -40, -45, -101, -105, -35, 123, -1, 13, -112, 79, -80, -85, -109, -71, 69, 104, 95, -93, 121, -17, 83, 117, -73, -63, -65, -107, -72, 118, -102, -56, 38, 79, 121, -25, -86, -81, -38, 8, 122, 97, 37, 82, -40, 53, 11, 124, -94, -76, -107, -125, -9, -119, 63, 52, -34, -72, -21, 59, 3, -100, -127, 47, -102, 19, -37, -45, -114, -65, 39, -106, 6, -127, -110, -38, 96, -38, -51, 110, -3, 28, 8, 102, -102, 96, -127, 109, -56, -53, -13, 59, -98, 92, 80, 1, 55, -91, -122, -105, 28, 69, -85, 109, -38, 105, 87, -5, 3, -102, 62, -92, 60, 43, -20, -7, -23, -84, 106, 121, -48, 123, -112, 56, -17, -52, 14, -123, -122, 64, 14, -23, -71, 60, 70, -121, 6, 37, -15, 77, 96, 104, -34, 58, -125, -61, 1, -26, 118, -78, -35, -1, 0, 5, 33, -98, -86, -127, 25, 56, -91, 82, -33, 60, -64, -86, 27, 31, -80, -79, 118, -12, -18, 40, -72, 32, 119, -28, -62, 100, -121, -71, -79, -9, 38, -37, 25, 65, -46, 8, -112, 37, 9, -56, 123, -40, -44, -90, -21, -54, -2, -7, 107, -93, 24, -126, 69, 42, -111, -84, 57, 69, -119, 21, 60, 57, -122, 111, -99, 49, -46, -119, 100, 98, 24, -62, 112, 122, 46, 18, -35, -67, 89, 104, 82, 12, 125, 57, -70, -112, -109, 96, 51, -68, 1, -101, -59, -92, 54, 85, -41, 17, 31, 94, 75, -128, 53, 84, 0, -83, -94, -123, 49, -30, -24, 18, 46, 48, -33, 120, 66, -69, 70, 23, -124, -117, 81, 96, 46, 47, -33, 83, -13, -14, -94, 49, 66, -46, 84, -27, -77, 6, 0, -75, -18, 86, -119, -88, 82, -50, 55, -20, 63, 55, -57, 22, -108, -103, -17, -22, 64, 65, 90, -34, -96, -117, 51, 119, -103, -35, 95, -15, -118, 2, -31, 31, -9, -58, 84, -75, 80, 39, -101, -56, 16, -75, 59, 48, -63, -24, -95, 119, 73, -110, -115, 49, -18, 54, -124, 112, -61, -40, -105, -118, -66, 15, -107, 75, 82, -70, -87, -11, -11, 48, 41, 119, -42, -34, -33, 57, 23, -14, -45, -125, -108, -75, 3, 44, 44, 58, 126, -126, -20, -123, 58, 114, 79, -102, -115, 115, 12, 66, 108, 84, 43, -46, -80, -41, -70, 111, -114, 123, 21, 1, 34, -72, 23, 105, -52, -39, -54, -119, 45, 77, -16, -66, -105, -11, 91, -46, 77, -104, -93, 52, -3, 17, 55, -10, 67, -33, 43, 75, -103, 106, 7, -35, -65, -21, 68, 118, -38, 59, -115, 31};

        byte[] fullBytes = new byte[pubBytes.length + privBytes.length];

        System.arraycopy(pubBytes, 0, fullBytes, 0, pubBytes.length);
        System.arraycopy(privBytes, 0, fullBytes, pubBytes.length, privBytes.length);

        NTRUEncryptionPrivateKeyParameters priv = new NTRUEncryptionPrivateKeyParameters(fullBytes, params.getEncryptionParameters());
        NTRUEncryptionPublicKeyParameters pub = new NTRUEncryptionPublicKeyParameters(pubBytes, params.getEncryptionParameters());
        AsymmetricCipherKeyPair kp = new AsymmetricCipherKeyPair(pub, priv);

        ntru.init(true, kp.getPublic());

        byte[] encrypted = ntru.processBlock(plainText, 0, plainText.length);

        assertEquals(encrypted.length, ntru.getOutputBlockSize());

        ntru.init(false, kp.getPrivate());

        byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.length);

        assertTrue(Arrays.areEqual(plainText, decrypted));
    }

    private class VisibleNTRUEngine
        extends NTRUEngine
    {
        public IntegerPolynomial encrypt(IntegerPolynomial m, TernaryPolynomial r, IntegerPolynomial pubKey)
        {
            return super.encrypt(m, r, pubKey);
        }

        public IntegerPolynomial decrypt(IntegerPolynomial e, Polynomial priv_t, IntegerPolynomial priv_fp)
        {
            return super.decrypt(e, priv_t, priv_fp);
        }
    }
}
