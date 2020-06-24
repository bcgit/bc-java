package org.bouncycastle.mime.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.mime.encoding.Base64InputStream;
import org.bouncycastle.mime.encoding.Base64OutputStream;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;

public class Base64TransferEncodingTest
    extends TestCase
{
    private SecureRandom random = new SecureRandom();

    /**
     * Test the decoding of some base64 arranged in lines of
     * 64 byte base 64 encoded rows terminated CRLF.
     *
     * @throws Exception
     */
    public void testDecodeWellFormed()
        throws Exception
    {
        byte[][] original = new byte[4][48];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        //
        // Create 4 lines of 64bytes of base64 encoded data.
        //
        for (int i = 0; i != original.length; i++)
        {
            byte[] row = original[i];
            
            random.nextBytes(row);
            bos.write(Base64.encode(row));
            bos.write('\r');
            bos.write('\n');
        }

        verifyDecode(original, bos);
    }


    /**
     * Test decode without CR only LF.
     *
     * @throws Exception
     */
    public void testDecodeWithoutCR()
        throws Exception
    {
        byte[][] original = new byte[4][48];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        //
        // Create 4 lines of 64bytes of base64 encoded data.
        //
        for (int i = 0; i != original.length; i++)
        {
            byte[] row = original[i];

            random.nextBytes(row);
            bos.write(Base64.encode(row));
            bos.write('\n');
        }

        verifyDecode(original, bos);
    }


    /**
     * Test decode with long lines past the length in the spec.
     *
     * @throws Exception
     */
    public void testDecodeLongLines()
        throws Exception
    {
        byte[][] original = new byte[4][765];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        //
        // Create 4 lines of 1023 bytes of base64 encoded data.
        //
        for (int i = 0; i != original.length; i++)
        {
            byte[] row = original[i];
            random.nextBytes(row);
            bos.write(Base64.encode(row));
            bos.write('\n');
        }

        verifyDecode(original, bos);
    }


    /**
     * Test decode with long lines past the length in the spec.
     *
     * @throws Exception
     */
    public void testExcessiveLongLine()
        throws Exception
    {
        byte[][] original = new byte[4][766];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        //
        // Create 4 lines of 1023 bytes of base64 encoded data.
        //
        for (int i = 0; i != original.length; i++)
        {
            byte[] row = original[i];

            random.nextBytes(row);
            bos.write(Base64.encode(row));
            bos.write('\n');
        }

        try
        {
            verifyDecode(original, bos);
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("End of line of base64 not reached before line buffer overflow.", ex.getMessage());
        }
    }


    /**
     * Test decode of empty data.
     *
     * @throws Exception
     */
    public void testEmpty()
        throws Exception
    {
        // Assertions in verifyDecode()
        verifyDecode(new byte[0][0], new ByteArrayOutputStream());
    }

    public void testEncode()
        throws Exception
    {
        String[] b64Data = new String[] {
            "a1D4qBB8l3wR/r8Y6bXDJfSlMkTWzPUZzQ==",
            "MC47oxxB77T86ueJyw60uFbaCWBuwU7KHUg=",
            "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"};

        String[] processed = new String[]{
            "a1D4qBB8l3wR/r8Y6bXDJfSlMkTWzPUZzQ==\r\n",
            "MC47oxxB77T86ueJyw60uFbaCWBuwU7KHUg=\r\n",
            "FuOBuA/bsPuFwfT5OeOYQhvZMJ+i3/cJxouDzJCekL2L2UTsXjpQ4V3IAx5rfAYhMl40OO63\r\n" +
            "KzyFle11APcVPt41KyUmiC6cQKC0qMDVZnuiViZ18rTHZZAJ/CtidniQU2U7NDsLkJKO+8eC\r\n" +
            "MhIhVBuZSyAIxJA2sixp/167gY6OqPeQnnsoFOJJO7t2H5/C6nXPXri0lX6I/RrKxjgsv8a9\r\n" +
            "fQ292n01cOeC/bufYyJadcYXv1Mt4enlUZnOHIrUrsg2XG4CFv68vpSLUPngFAQTRNs6YVj6\r\n" +
            "OcxOGFlWCCPlI0a51T6HqVehKF5O/InlQa8lOQcCGJtFYw==\r\n"
        };

        for (int i = 0; i != b64Data.length; i++)
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            Base64OutputStream b64Strm = new Base64OutputStream(bOut);
            b64Strm.write(Base64.decode(b64Data[i]));
            b64Strm.close();

            String recovered = Strings.fromByteArray(bOut.toByteArray());
            if (i < processed.length)
            {
                assertEquals(processed[i], recovered);
            }
            assertEquals(b64Data[i], recovered.replaceAll("\r\n", ""));
        }
    }

    private void verifyDecode(byte[][] original, ByteArrayOutputStream bos)
        throws IOException
    {
        Base64InputStream bte = new Base64InputStream(new ByteArrayInputStream(bos.toByteArray()));

        for (int i = 0; i != original.length; i++)
        {
            byte[] row = original[i];
            for (int j = 0; j != row.length; j++)
            {
                TestCase.assertEquals(row[j] & 0xFF, bte.read());
            }
        }

        TestCase.assertEquals(-1, bte.read());
    }

    /**
     * This test causes the final line of base64 to not be a multiple of 64.
     *
     * @throws Exception
     */
    public void testDecodeLengths()
        throws Exception
    {
        byte[][] original = new byte[4][48];
        original[original.length - 1] = new byte[22];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        //
        // Create 4 lines of 64bytes of base64 encoded data.
        //
        for (int i = 0; i != original.length; i++)
        {
            byte[] row = original[i];

            random.nextBytes(row);
            bos.write(Base64.encode(row));
            bos.write('\r');
            bos.write('\n');
        }

        verifyDecode(original, bos);
    }


    /**
     * This test causes the final line of base64 to not be a multiple of 64.
     *
     * @throws Exception
     */
    public void testPartialLineEnding()
        throws Exception
    {
        byte[][] original = new byte[4][48];
        original[original.length - 1] = new byte[22];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        //
        // Create 4 lines of 64bytes of base64 encoded data.
        //
        for (int i = 0; i != original.length; i++)
        {
            byte[] row = original[i];

            random.nextBytes(row);
            bos.write(Base64.encode(row));
            bos.write('\r');
            bos.write('\n');
        }

        verifyDecode(original, bos);
    }


    public void testMultilined()
        throws Exception
    {
        String b64 = "MIAGCSqGSIb3DQEHA6CAMIACAQAxggFOMIIBSgIBADCBsjCBrDELMAkGA1UEBhMCQVQxEDAOBgNV\n" +
            "BAgTB0F1c3RyaWExDzANBgNVBAcTBlZpZW5uYTEaMBgGA1UEChMRVGlhbmkgU3Bpcml0IEdtYkgx\n" +
            "GTAXBgNVBAsTEERlbW8gRW52aXJvbm1lbnQxEDAOBgNVBAMTB1Rlc3QgQ0ExMTAvBgkqhkiG9w0B\n" +
            "CQEWIm1hc3NpbWlsaWFuby5tYXNpQHRpYW5pLXNwaXJpdC5jb20CAQkwDQYJKoZIhvcNAQEBBQAE\n" +
            "gYALxKaiVW43jHjDiJ4kC6N90lpyG0jxeJ7nynWaR4YkDiUQ/jE8cJwRX0jBQeWKRvf3Y+XhRuB3\n" +
            "B76cKxBGTgMh6pCuLoIvgBJq54kqql/xz3hO7QRvvuHnEljlw2uhd0PQqQYe8oLdu1Yqyo9+9Jsx\n" +
            "I7QX43E2H5b3nNGND24djDCABgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBD+UNge0S52HEPuFBEq\n" +
            "IEvYoIAEggHAcOET1XS7H/OZALZ0cyns3p6kxgAlblE4BvMQnAen8VlhDehp130WdDF4jC+zRjza\n" +
            "ZftPatKq/Hlhu0wuj+FZESjy2d2hR7FT8qCqGda70IyyOhloG7Ym+17E0MyYQsH38i+uC8NjcSeo\n" +
            "egggsQoidePpg/9BNFMA4j6vORFcNBvnwj71mV2icx7mUud97cXobJnrfm3hmEmYkm7wL413cibH\n" +
            "b8K3yNu/hMqJViT0GvlhQdR9hDgu5i2WhiE2UTaFu3xL2xNhzXBvhOwj/gikzFIWva4S/2JfK3M8\n" +
            "A0lYu6f1vYUF2jazi81wQFEF7qKyp7zx7X2iZjn8DDSCY73izHafF1JJijDFaHrD5245kaSJ7MKP\n" +
            "jJ/HWk9lbed0ay8f96QuvWEEKSy4xejy6w7DKxKr4icN7KDE5Nyc2ZAJxmCm50B7yHpNZfKQ38E+\n" +
            "e/bCgvAESFcnw9pRJz9mXmwazxEvCpoO/ezgmgro+59CCRKqdUeOyyLQg6d7xqUcgeY1SoDxzEre\n" +
            "i4IBlig6+HWLs+9OPMa2fuYYIVZvg7mpeM4lEfdhRssWBWwTTmrtwRbAaT7BTCtlvfqzpHrycp5O\n" +
            "zgAAAAAAAAAAAAA=";


        byte[] data = Base64.decode(b64);

//
//        MimeParserInputStream mpin = new MimeParserInputStream(new ByteArrayInputStream(b64.getBytes()), 1024);
//        Base64TransferDecoder btd = new Base64TransferDecoder(mpin, 1024);
//
//
//        for (int t = 0; t < data.length; t++)
//        {
//            TestCase.assertEquals("Position: " + t, data[t] & 0xFF, btd.read());
//        }
//
//        TestCase.assertEquals(-1, btd.read());

    }

}


