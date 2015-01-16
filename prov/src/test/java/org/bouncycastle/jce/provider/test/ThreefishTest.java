package org.bouncycastle.jce.provider.test;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

public class ThreefishTest
    extends SimpleTest
{

    private static final byte[] SECRET_KEY_1024 =
        {
            -15, -32, 56, 110, 22, -42, -26, 34, 25, 17, -83, -2, -78, 112, 49, 127, -4, 70, -110, -21, -10, -114, -82, -122,
            78, 53, -105, -44, 34, 45, -102, -19, -30, 73, 87, 19, 25, -92, -64, -72, 11, 125, -92, -124, -126, -70, -92, 54,
            46, 3, 86, -108, 71, -42, 44, -110, -36, -31, -48, -84, -19, 102, 124, -118, 17, -84, -119, 126, 37, -8, -13, 21,
            -4, 86, 104, -85, -44, 82, 60, -61, -95, -9, -92, 68, -123, -111, -53, -36, -47, 36, -92, 121, 95, 25, 73, 124,
            -13, -7, -106, -32, 75, -30, -25, -95, 120, 88, 2, 55, 68, -113, -60, 104, 59, 57, -86, -79, -110, -126, -44,
            -18, 73, -37, -128, -40, -62, -15, 23, 87
        };

    private static final byte[] TEST_BYTES = new byte[1536];

    public String getName()
    {
        return "Threefish";
    }

    public void performTest()
        throws Exception
    {
        // padding test at 128 pad bytes.

        final SecretKey secretKey = new SecretKeySpec(SECRET_KEY_1024, "Threefish-1024");

        Cipher cipher = Cipher.getInstance("Threefish-1024/CBC/ISO10126Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[128]));

        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(TEST_BYTES);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        byte[] cleartext = cipher.doFinal(ciphertext);

        if (!Arrays.areEqual(TEST_BYTES, cleartext))
        {
            fail("Invalid cleartext - ISO10126Padding.");
        }

        cipher = Cipher.getInstance("Threefish-1024/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        iv = cipher.getIV();
        ciphertext = cipher.doFinal(TEST_BYTES);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        cleartext = cipher.doFinal(ciphertext);

        if (!Arrays.areEqual(TEST_BYTES, cleartext))
        {
            fail("Invalid cleartext - PKCS7.");
        }
    }

    public static void main(final String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ThreefishTest());
    }
}
