package org.bouncycastle.pkcs.test;

import junit.framework.TestCase;
import org.bouncycastle.pkcs.JCEPrivateKeyFactory;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;

public class JCEPrivateKeyFactoryTest extends TestCase {

    private JCEPrivateKeyFactory.IPasswordProvider passwordProvider = new JCEPrivateKeyFactory.IPasswordProvider() {
        public char[] getPassword() {
            return new char[]{'t', 'e', 's', 't'};
        }
    };

    protected void setUp() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    protected void tearDown() {
        Security.removeProvider("BC");
    }

    public void testPKCS1DERKeyIdentification() {
        byte[] PKCS1KeyBytes = {48, -126, 2, 91, 2, 1, 0, 2, -127, -127, 0, -58, -99, -103, 63, 81, 62, -68, 125, 12, 126, -7, 110, 111, 19, -45, 43, -72, 47, -75, 95, -41, 45, -47, 110, -110, -89, -7, 4, 39, 40, 63, 91, 56, -93, 9, 23, 113, 42, -59, 57, 38, -47, 120, -12, -53, -80, 48, 96, 66, -42, 105, -27, -80, -64, 86, 37, -41, 38, 116, -80, 72, 36, -38, -123, -113, -59, 37, 85, 120, 64, -37, -72, -46, 2, 77, -15, -82, -107, 50, 63, 13, -79, 99, -67, 58, 78, -89, -50, 86, 30, 50, 12, 33, 11, -42, -39, -42, 5, -86, -124, 2, 74, -8, -93, 48, 31, -30, 73, -88, -61, 109, 66, 58, -44, 39, 85, 20, 6, -123, 18, -48, 109, -7, -68, 1, -120, 114, -31, 2, 3, 1, 0, 1, 2, -127, -128, 70, 27, 73, 5, -91, -118, -20, -125, -125, 78, -86, -126, -59, -88, -116, -56, -120, -38, 38, 62, 111, 56, -40, 13, 28, -83, 55, -29, -76, 98, -85, -126, 106, -118, 121, -30, 17, 107, 20, 116, -88, -12, 21, -86, -22, -33, 5, 36, 101, 83, 67, -53, -12, -56, -33, 95, -70, 2, -13, -5, 105, 107, -64, -55, -10, -98, 41, -10, 41, 92, 53, -120, -42, -34, -99, 49, 78, 86, -124, 66, 4, 59, 119, 98, -88, -77, -121, -31, -21, -98, 113, -63, -68, 57, 67, -31, 75, -104, -59, -86, -34, 122, -67, 63, -1, 126, 52, 87, -26, 103, 75, -110, 102, -81, -9, 97, -110, 100, -23, -125, -105, 45, -84, 38, 5, -45, 46, 117, 2, 65, 0, -13, -127, 50, 6, -87, 17, 67, 21, 9, -61, -9, -80, -25, -42, 110, -111, 123, -16, -8, -32, -109, 110, 105, -74, 121, 12, 33, 5, -113, 31, 7, -47, 109, 2, -15, 0, 28, -127, -96, -53, -124, -55, 75, 118, -76, -23, -25, 80, 57, -97, -127, -71, -118, -34, 66, -51, 41, 109, 82, 0, -65, 3, 60, 55, 2, 65, 0, -48, -50, -73, -103, -51, -109, -62, -128, -21, 30, -78, -128, -9, -121, 43, -55, 2, 57, -63, 14, -102, -43, 100, 23, 35, -127, 34, -33, -76, 115, -53, -56, -64, 48, -6, -66, -85, 123, 83, -27, 7, -126, 38, 2, -10, 41, 17, -81, 69, 109, 27, 109, 15, 39, -53, -117, -76, -46, 86, -87, 127, -99, -83, -89, 2, 64, 19, -36, -4, 25, -78, -4, -25, 125, -11, -41, -8, -126, -125, -58, -24, 42, 17, -12, 44, 57, 21, -115, -78, 45, -30, 93, -20, -21, -87, 43, 28, -42, 38, -112, 80, -36, 115, 118, -41, -119, 2, -127, -15, 23, -13, -42, 8, -70, 112, -104, -28, 90, 32, 75, -43, 35, 43, 55, -15, -78, -127, -30, 95, -83, 2, 64, 47, -83, 67, -106, -58, -83, -38, 87, 125, 88, 1, 2, 25, -126, -81, -88, -79, -19, 101, -5, 99, -73, 29, -89, 122, -33, -35, -118, -98, -75, 97, -18, 112, -109, -66, 109, 18, -46, -110, 17, 85, 105, -114, 44, 86, -16, -127, -83, 55, 120, -10, 46, 44, -85, -75, 122, 44, -53, 106, 38, 65, -111, 75, 57, 2, 64, 38, -52, 41, 126, -1, 104, 85, -25, 95, 107, 66, -49, -79, -54, -87, 68, -79, 29, -128, -62, -86, 103, 15, 47, 46, 12, 4, -14, -77, -124, -5, 42, 111, 73, 91, -73, 33, -77, -74, -57, 21, -110, 66, 82, -50, 102, -9, 90, -109, 94, -74, -43, -17, 127, -6, -99, 106, -114, 0, -127, -109, -81, -94, 7};
        PrivateKey privateKey = null;
        try {
            JCEPrivateKeyFactory.PrivateKeyType keyType = JCEPrivateKeyFactory.getPrivateKeyType(PKCS1KeyBytes);
            assertEquals(JCEPrivateKeyFactory.PrivateKeyType.PRIVATE_KEY_TYPE_PKCS1, keyType);

            privateKey = JCEPrivateKeyFactory.getJCEPrivateKey(PKCS1KeyBytes, null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyParsingException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyDecryptionException e) {
            e.printStackTrace();
        }
        assertNotNull(privateKey);
    }

    public void testPKCS8DERKeyIdentification() {
        byte[] PKCS8KeyBytes = {48, -126, 2, 117, 2, 1, 0, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 4, -126, 2, 95, 48, -126, 2, 91, 2, 1, 0, 2, -127, -127, 0, -58, -99, -103, 63, 81, 62, -68, 125, 12, 126, -7, 110, 111, 19, -45, 43, -72, 47, -75, 95, -41, 45, -47, 110, -110, -89, -7, 4, 39, 40, 63, 91, 56, -93, 9, 23, 113, 42, -59, 57, 38, -47, 120, -12, -53, -80, 48, 96, 66, -42, 105, -27, -80, -64, 86, 37, -41, 38, 116, -80, 72, 36, -38, -123, -113, -59, 37, 85, 120, 64, -37, -72, -46, 2, 77, -15, -82, -107, 50, 63, 13, -79, 99, -67, 58, 78, -89, -50, 86, 30, 50, 12, 33, 11, -42, -39, -42, 5, -86, -124, 2, 74, -8, -93, 48, 31, -30, 73, -88, -61, 109, 66, 58, -44, 39, 85, 20, 6, -123, 18, -48, 109, -7, -68, 1, -120, 114, -31, 2, 3, 1, 0, 1, 2, -127, -128, 70, 27, 73, 5, -91, -118, -20, -125, -125, 78, -86, -126, -59, -88, -116, -56, -120, -38, 38, 62, 111, 56, -40, 13, 28, -83, 55, -29, -76, 98, -85, -126, 106, -118, 121, -30, 17, 107, 20, 116, -88, -12, 21, -86, -22, -33, 5, 36, 101, 83, 67, -53, -12, -56, -33, 95, -70, 2, -13, -5, 105, 107, -64, -55, -10, -98, 41, -10, 41, 92, 53, -120, -42, -34, -99, 49, 78, 86, -124, 66, 4, 59, 119, 98, -88, -77, -121, -31, -21, -98, 113, -63, -68, 57, 67, -31, 75, -104, -59, -86, -34, 122, -67, 63, -1, 126, 52, 87, -26, 103, 75, -110, 102, -81, -9, 97, -110, 100, -23, -125, -105, 45, -84, 38, 5, -45, 46, 117, 2, 65, 0, -13, -127, 50, 6, -87, 17, 67, 21, 9, -61, -9, -80, -25, -42, 110, -111, 123, -16, -8, -32, -109, 110, 105, -74, 121, 12, 33, 5, -113, 31, 7, -47, 109, 2, -15, 0, 28, -127, -96, -53, -124, -55, 75, 118, -76, -23, -25, 80, 57, -97, -127, -71, -118, -34, 66, -51, 41, 109, 82, 0, -65, 3, 60, 55, 2, 65, 0, -48, -50, -73, -103, -51, -109, -62, -128, -21, 30, -78, -128, -9, -121, 43, -55, 2, 57, -63, 14, -102, -43, 100, 23, 35, -127, 34, -33, -76, 115, -53, -56, -64, 48, -6, -66, -85, 123, 83, -27, 7, -126, 38, 2, -10, 41, 17, -81, 69, 109, 27, 109, 15, 39, -53, -117, -76, -46, 86, -87, 127, -99, -83, -89, 2, 64, 19, -36, -4, 25, -78, -4, -25, 125, -11, -41, -8, -126, -125, -58, -24, 42, 17, -12, 44, 57, 21, -115, -78, 45, -30, 93, -20, -21, -87, 43, 28, -42, 38, -112, 80, -36, 115, 118, -41, -119, 2, -127, -15, 23, -13, -42, 8, -70, 112, -104, -28, 90, 32, 75, -43, 35, 43, 55, -15, -78, -127, -30, 95, -83, 2, 64, 47, -83, 67, -106, -58, -83, -38, 87, 125, 88, 1, 2, 25, -126, -81, -88, -79, -19, 101, -5, 99, -73, 29, -89, 122, -33, -35, -118, -98, -75, 97, -18, 112, -109, -66, 109, 18, -46, -110, 17, 85, 105, -114, 44, 86, -16, -127, -83, 55, 120, -10, 46, 44, -85, -75, 122, 44, -53, 106, 38, 65, -111, 75, 57, 2, 64, 38, -52, 41, 126, -1, 104, 85, -25, 95, 107, 66, -49, -79, -54, -87, 68, -79, 29, -128, -62, -86, 103, 15, 47, 46, 12, 4, -14, -77, -124, -5, 42, 111, 73, 91, -73, 33, -77, -74, -57, 21, -110, 66, 82, -50, 102, -9, 90, -109, 94, -74, -43, -17, 127, -6, -99, 106, -114, 0, -127, -109, -81, -94, 7};

        PrivateKey privateKey = null;
        try {
            JCEPrivateKeyFactory.PrivateKeyType keyType = JCEPrivateKeyFactory.getPrivateKeyType(PKCS8KeyBytes);
            assertEquals(JCEPrivateKeyFactory.PrivateKeyType.PRIVATE_KEY_TYPE_PKCS8, keyType);

            privateKey = JCEPrivateKeyFactory.getJCEPrivateKey(PKCS8KeyBytes, null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyParsingException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyDecryptionException e) {
            e.printStackTrace();
        }
        assertNotNull(privateKey);
    }

    public void testPKCS8DEREncryptedKeyIdentification() {
        byte[] PKCS8EncKeyBytes = {48, -126, 2, -95, 48, 27, 6, 9, 42, -122, 72, -122, -9, 13, 1, 5, 3, 48, 14, 4, 8, -36, -107, 4, 117, 20, -101, 85, -55, 2, 2, 8, 0, 4, -126, 2, -128, -71, -64, 85, -58, -37, 63, 55, -6, 90, 108, 115, 76, 81, -115, -112, 115, 78, 66, -110, 48, 71, -81, 2, -44, 121, -38, -37, -9, -1, 48, 14, -113, 50, 106, -112, -50, 45, -71, -100, 55, 82, 61, -13, -107, 124, 2, 122, -96, 26, 45, -13, 62, -20, -40, -31, 87, 33, 55, -28, -64, 0, -113, 91, 28, 95, 113, 77, 30, -1, -120, 49, 23, 93, 91, -76, 122, 25, 80, 56, -71, -43, -40, 62, -48, -127, 62, -3, 64, -72, 69, -96, -13, 70, -121, 112, 74, 105, 23, 23, 98, -72, -67, -52, -41, 80, 54, -53, -48, 58, 78, 92, -3, 50, -2, -12, -74, -100, -101, -13, 81, -123, -125, 100, 15, 61, -49, 19, 76, -29, -66, -87, -79, 52, -127, 48, -22, -24, -106, 12, 30, -110, 9, 118, 97, 13, 117, 112, 16, -110, -28, -12, 3, 72, 4, 26, 17, -92, -114, -41, -16, -49, 49, 34, -5, 28, 49, 97, 114, 65, -83, 25, -60, 5, 115, 10, -56, 75, -103, -30, -40, 116, 52, 120, -71, -119, -24, -24, -72, 85, 74, -112, -64, -84, 39, 29, 68, -60, -95, 5, 97, -111, -37, 63, 106, -80, 60, -77, -109, 18, -56, -94, -37, -22, -66, 7, -37, -15, -68, 60, 111, 112, 99, -103, -11, -58, 124, -31, 9, 8, -77, -67, -65, -20, 35, -78, -65, -2, 57, -9, 87, 82, -126, -29, 9, -32, 44, 8, -100, -76, 94, -62, -6, 101, -30, 71, -12, 35, 23, 106, -63, -92, 60, 24, 8, 3, 100, 91, -118, 97, 55, -76, -23, -114, 84, -58, -79, -36, 39, -65, 13, 54, -81, -29, 122, 115, -106, 99, -114, 17, -78, 56, -69, 7, 84, -31, -11, 86, -41, 119, 39, 48, -94, -116, -8, -117, 49, 0, 100, 62, -64, 72, 64, 104, 71, -5, -102, -84, -70, -55, -15, -79, -26, -10, -111, 54, 93, -109, 88, 12, -22, 36, 13, 67, 80, -48, -76, 26, 94, 94, -85, 95, -21, -47, -26, 79, -109, -15, -4, 126, 9, -86, -74, -72, -33, -108, -80, 102, -65, -89, -44, 102, 61, 40, 93, -14, -100, 60, 105, 95, -60, -65, -91, -3, -6, 51, -112, 48, 22, -25, -63, 26, 84, -21, 53, 119, 106, 79, -22, -98, 54, -96, 73, 38, -59, 84, -9, 76, 65, -109, 19, -106, 91, -84, -34, 124, 66, -50, -58, -89, 107, -125, 122, -40, -54, 82, 117, -106, 106, -57, -73, 37, -58, -83, 106, 12, -88, 78, -31, -21, 61, 33, 19, 57, -125, 55, 30, 7, -125, -51, -6, 60, 46, -55, -102, 15, 112, -105, 115, -71, -40, -70, -34, 101, 109, -46, -7, 42, -14, -120, -105, -102, -3, 35, -110, 30, -94, 23, 38, -106, -76, -41, -55, 67, 125, -10, -123, -109, -108, 111, -40, 118, 82, -18, -46, -4, 106, 43, 41, -29, 108, -75, 34, 122, -20, -11, -102, 17, -93, 90, -80, 85, -20, 116, 70, -85, -30, -88, 12, 106, 3, -42, 52, -8, 41, 9, -70, 47, 62, 127, 3, -63, 74, -11, -67, 121, -8, -86, -116, 104, -105, -17, -76, -49, 18, 116, 72, 124, -117, -107, 101, -12, 42, 118, -120, -67, -45, -30, 71, 34, 11, 93, -6, 120, -108, 20, 75, 60, 39, 70, 65, -53, 87, -49, -58, 81, 122, 63, 2, -64, 54, 115, -87, 126, 125, 107, -105, -118, -21, 118, -35, 84, 28, -25, -98, -84, 97, 82, -109, 67, 85, -31, 26, 45, 59, -77, -90, 16, 41, -39, -121, 76, 24, -48, -22, -53, 98, -90, -9, -12, 110, -82, -92, -26, 120, 44, 34, 44, 32, 115, 93, 102, 112, 107, 78, 81, 57, -14, 2, -119, 86, -25, 55, 56, 4, 43, -59, 32, 126, -29, 11};

        PrivateKey privateKey = null;
        try {
            JCEPrivateKeyFactory.PrivateKeyType keyType = JCEPrivateKeyFactory.getPrivateKeyType(PKCS8EncKeyBytes);
            assertEquals(JCEPrivateKeyFactory.PrivateKeyType.PRIVATE_KEY_TYPE_PKCS8_ENCRYPTED, keyType);

            privateKey = JCEPrivateKeyFactory.getJCEPrivateKey(PKCS8EncKeyBytes, passwordProvider);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyParsingException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyDecryptionException e) {
            e.printStackTrace();
        }
        assertNotNull(privateKey);
    }

    public void testPKCS1PEMKeyIdentification() {
        String PKCS1PEMKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICWwIBAAKBgQDGnZk/UT68fQx++W5vE9MruC+1X9ct0W6Sp/kEJyg/WzijCRdx\n" +
                "KsU5JtF49MuwMGBC1mnlsMBWJdcmdLBIJNqFj8UlVXhA27jSAk3xrpUyPw2xY706\n" +
                "TqfOVh4yDCEL1tnWBaqEAkr4ozAf4kmow21COtQnVRQGhRLQbfm8AYhy4QIDAQAB\n" +
                "AoGARhtJBaWK7IODTqqCxaiMyIjaJj5vONgNHK0347Riq4JqinniEWsUdKj0Farq\n" +
                "3wUkZVNDy/TI31+6AvP7aWvAyfaeKfYpXDWI1t6dMU5WhEIEO3diqLOH4eueccG8\n" +
                "OUPhS5jFqt56vT//fjRX5mdLkmav92GSZOmDly2sJgXTLnUCQQDzgTIGqRFDFQnD\n" +
                "97Dn1m6Re/D44JNuabZ5DCEFjx8H0W0C8QAcgaDLhMlLdrTp51A5n4G5it5CzSlt\n" +
                "UgC/Azw3AkEA0M63mc2TwoDrHrKA94cryQI5wQ6a1WQXI4Ei37Rzy8jAMPq+q3tT\n" +
                "5QeCJgL2KRGvRW0bbQ8ny4u00lapf52tpwJAE9z8GbL853311/iCg8boKhH0LDkV\n" +
                "jbIt4l3s66krHNYmkFDcc3bXiQKB8Rfz1gi6cJjkWiBL1SMrN/GygeJfrQJAL61D\n" +
                "lsat2ld9WAECGYKvqLHtZftjtx2net/dip61Ye5wk75tEtKSEVVpjixW8IGtN3j2\n" +
                "LiyrtXosy2omQZFLOQJAJswpfv9oVedfa0LPscqpRLEdgMKqZw8vLgwE8rOE+ypv\n" +
                "SVu3IbO2xxWSQlLOZvdak1621e9/+p1qjgCBk6+iBw==\n" +
                "-----END RSA PRIVATE KEY-----";
        PrivateKey privateKey = null;
        try {
            JCEPrivateKeyFactory.PrivateKeyType keyType = JCEPrivateKeyFactory.getPrivateKeyType(PKCS1PEMKey);
            assertEquals(JCEPrivateKeyFactory.PrivateKeyType.PRIVATE_KEY_TYPE_PKCS1, keyType);

            privateKey = JCEPrivateKeyFactory.getJCEPrivateKey(PKCS1PEMKey, null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyParsingException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyDecryptionException e) {
            e.printStackTrace();
        }
        assertNotNull(privateKey);
    }

    public void testPKCS1PEMEncKeyIdentification() {
        String PKCS1PEMKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "Proc-Type: 4,ENCRYPTED\n" +
                "DEK-Info: AES-128-CBC,BE43B1CFC64239661DABEA159588F247\n" +
                "\n" +
                "E1Fo3ECRiNvarlplS5dwbU8tUJVly7e66A5r/GJbqlkzthuFueu4H05AQ0lYxNlK\n" +
                "aDqlWE9fdDynqdIb8R1xfaXeFCl8Og7RwReN4n1mCpjJxNR7D2XAiG6+Yc5aratw\n" +
                "JIiaapWf+gjOTg2jUj/kjXStVxe83wwwmqqyZxESJ7Rqi5HtWesCEzbqlakptAWV\n" +
                "Cbvpu5KCnSt/iF7k/c/36KLLcU8KOx6tAN3utAy7tECKIJvi+kstGn9FN60cNfVC\n" +
                "apWXOencPdQUW+jyUlqr9wdcD4K267/YE9KpfenWJRIP4tu9BXzqNXG3rKrSM9bB\n" +
                "nOwNot5nlr8F4MAHWXpb5cJPvG1HiAT61e5IeNj9jqega1figy4DBYvzhpDBb78b\n" +
                "t8uWgqIA7TcEuTTx6yeMoUdhBmh3p93QGn5ec219rmnrdnsmn+m+o1Os3ww1udFm\n" +
                "wdiAf2YaqqBtnYDFpbnNJ5rZOtv302Oe6ViVPBXYn9HaIwWO8tUhWAHQ5EVfgjvr\n" +
                "vtKJtsVa+MRCZAkjwPfCQkyRdCEenuhc1XNisx2VaX8Yv27mJmoJc1eZ44ZC/N5r\n" +
                "/IbmsM4GcpU4VZ9mjeWhMuF1SZBqq2L7iPRkrtkHzc94kjcuaDv9C+N2NRSXxVr/\n" +
                "AoVcmm2D7TSvUVYGtZGZulESXs6IylE7Xziy2aCIFFi73Av6u6C7lmOvf120PcxF\n" +
                "vy9x2p/XsLE3kC6isf8B9xwPUAnWlSm4SfUNqnHz+Euye3yjWL1oSaSd7cdPLqw+\n" +
                "9j/w2qu0W6cYE2rSZnccyHumUMFdgzLkJBUD99rxQtc=\n" +
                "-----END RSA PRIVATE KEY-----";
        PrivateKey privateKey = null;
        try {
            JCEPrivateKeyFactory.PrivateKeyType keyType = JCEPrivateKeyFactory.getPrivateKeyType(PKCS1PEMKey);
            assertEquals(JCEPrivateKeyFactory.PrivateKeyType.PRIVATE_KEY_TYPE_PKCS1_ENCRYPTED, keyType);

            privateKey = JCEPrivateKeyFactory.getJCEPrivateKey(PKCS1PEMKey, passwordProvider);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyParsingException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyDecryptionException e) {
            e.printStackTrace();
        }
        assertNotNull(privateKey);
    }

    public void testPKCS8PEMKeyIdentification() {
        String PKCS8PEMKey = "-----BEGIN PRIVATE KEY-----\n" +
                "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMadmT9RPrx9DH75\n" +
                "bm8T0yu4L7Vf1y3RbpKn+QQnKD9bOKMJF3EqxTkm0Xj0y7AwYELWaeWwwFYl1yZ0\n" +
                "sEgk2oWPxSVVeEDbuNICTfGulTI/DbFjvTpOp85WHjIMIQvW2dYFqoQCSvijMB/i\n" +
                "SajDbUI61CdVFAaFEtBt+bwBiHLhAgMBAAECgYBGG0kFpYrsg4NOqoLFqIzIiNom\n" +
                "Pm842A0crTfjtGKrgmqKeeIRaxR0qPQVqurfBSRlU0PL9MjfX7oC8/tpa8DJ9p4p\n" +
                "9ilcNYjW3p0xTlaEQgQ7d2Kos4fh655xwbw5Q+FLmMWq3nq9P/9+NFfmZ0uSZq/3\n" +
                "YZJk6YOXLawmBdMudQJBAPOBMgapEUMVCcP3sOfWbpF78Pjgk25ptnkMIQWPHwfR\n" +
                "bQLxAByBoMuEyUt2tOnnUDmfgbmK3kLNKW1SAL8DPDcCQQDQzreZzZPCgOsesoD3\n" +
                "hyvJAjnBDprVZBcjgSLftHPLyMAw+r6re1PlB4ImAvYpEa9FbRttDyfLi7TSVql/\n" +
                "na2nAkAT3PwZsvznffXX+IKDxugqEfQsORWNsi3iXezrqSsc1iaQUNxzdteJAoHx\n" +
                "F/PWCLpwmORaIEvVIys38bKB4l+tAkAvrUOWxq3aV31YAQIZgq+ose1l+2O3Had6\n" +
                "392KnrVh7nCTvm0S0pIRVWmOLFbwga03ePYuLKu1eizLaiZBkUs5AkAmzCl+/2hV\n" +
                "519rQs+xyqlEsR2AwqpnDy8uDATys4T7Km9JW7chs7bHFZJCUs5m91qTXrbV73/6\n" +
                "nWqOAIGTr6IH\n" +
                "-----END PRIVATE KEY-----";

        PrivateKey privateKey = null;
        try {
            JCEPrivateKeyFactory.PrivateKeyType keyType = JCEPrivateKeyFactory.getPrivateKeyType(PKCS8PEMKey);
            assertEquals(JCEPrivateKeyFactory.PrivateKeyType.PRIVATE_KEY_TYPE_PKCS8, keyType);

            privateKey = JCEPrivateKeyFactory.getJCEPrivateKey(PKCS8PEMKey, null);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyParsingException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyDecryptionException e) {
            e.printStackTrace();
        }
        assertNotNull(privateKey);
    }

    public void testPKCS8PEMEncryptedKeyIdentification() {
        String PKCS8EncPEMKey = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
                "MIICoTAbBgkqhkiG9w0BBQMwDgQI3JUEdRSbVckCAggABIICgLnAVcbbPzf6Wmxz\n" +
                "TFGNkHNOQpIwR68C1Hna2/f/MA6PMmqQzi25nDdSPfOVfAJ6oBot8z7s2OFXITfk\n" +
                "wACPWxxfcU0e/4gxF11btHoZUDi51dg+0IE+/UC4RaDzRodwSmkXF2K4vczXUDbL\n" +
                "0DpOXP0y/vS2nJvzUYWDZA89zxNM476psTSBMOrolgwekgl2YQ11cBCS5PQDSAQa\n" +
                "EaSO1/DPMSL7HDFhckGtGcQFcwrIS5ni2HQ0eLmJ6Oi4VUqQwKwnHUTEoQVhkds/\n" +
                "arA8s5MSyKLb6r4H2/G8PG9wY5n1xnzhCQizvb/sI7K//jn3V1KC4wngLAictF7C\n" +
                "+mXiR/QjF2rBpDwYCANkW4phN7TpjlTGsdwnvw02r+N6c5ZjjhGyOLsHVOH1Vtd3\n" +
                "JzCijPiLMQBkPsBIQGhH+5qsusnxseb2kTZdk1gM6iQNQ1DQtBpeXqtf69HmT5Px\n" +
                "/H4Jqra435SwZr+n1GY9KF3ynDxpX8S/pf36M5AwFufBGlTrNXdqT+qeNqBJJsVU\n" +
                "90xBkxOWW6zefELOxqdrg3rYylJ1lmrHtyXGrWoMqE7h6z0hEzmDNx4Hg836PC7J\n" +
                "mg9wl3O52LreZW3S+SryiJea/SOSHqIXJpa018lDffaFk5Rv2HZS7tL8aisp42y1\n" +
                "Inrs9ZoRo1qwVex0RqviqAxqA9Y0+CkJui8+fwPBSvW9efiqjGiX77TPEnRIfIuV\n" +
                "ZfQqdoi90+JHIgtd+niUFEs8J0ZBy1fPxlF6PwLANnOpfn1rl4rrdt1UHOeerGFS\n" +
                "k0NV4RotO7OmECnZh0wY0OrLYqb39G6upOZ4LCIsIHNdZnBrTlE58gKJVuc3OAQr\n" +
                "xSB+4ws=\n" +
                "-----END ENCRYPTED PRIVATE KEY-----";

        PrivateKey privateKey = null;
        try {
            JCEPrivateKeyFactory.PrivateKeyType keyType = JCEPrivateKeyFactory.getPrivateKeyType(PKCS8EncPEMKey);
            assertEquals(JCEPrivateKeyFactory.PrivateKeyType.PRIVATE_KEY_TYPE_PKCS8_ENCRYPTED, keyType);

            privateKey = JCEPrivateKeyFactory.getJCEPrivateKey(PKCS8EncPEMKey, passwordProvider);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyParsingException e) {
            e.printStackTrace();
        } catch (JCEPrivateKeyFactory.PrivateKeyDecryptionException e) {
            e.printStackTrace();
        }
        assertNotNull(privateKey);
    }
}
