package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class PGPArmoredTest
    extends SimpleTest
{
    byte[] sample = Base64.decode(
            "mQGiBEA83v0RBADzKVLVCnpWQxX0LCsevw/3OLs0H7MOcLBQ4wMO9sYmzGYn"
          + "xpVj+4e4PiCP7QBayWyy4lugL6Lnw7tESvq3A4v3fefcxaCTkJrryiKn4+Cg"
          + "y5rIBbrSKNtCEhVi7xjtdnDjP5kFKgHYjVOeIKn4Cz/yzPG3qz75kDknldLf"
          + "yHxp2wCgwW1vAE5EnZU4/UmY7l8kTNkMltMEAJP4/uY4zcRwLI9Q2raPqAOJ"
          + "TYLd7h+3k/BxI0gIw96niQ3KmUZDlobbWBI+VHM6H99vcttKU3BgevNf8M9G"
          + "x/AbtW3SS4De64wNSU3189XDG8vXf0vuyW/K6Pcrb8exJWY0E1zZQ1WXT0gZ"
          + "W0kH3g5ro//Tusuil9q2lVLF2ovJA/0W+57bPzi318dWeNs0tTq6Njbc/GTG"
          + "FUAVJ8Ss5v2u6h7gyJ1DB334ExF/UdqZGldp0ugkEXaSwBa2R7d3HBgaYcoP"
          + "Ck1TrovZzEY8gm7JNVy7GW6mdOZuDOHTxyADEEP2JPxh6eRcZbzhGuJuYIif"
          + "IIeLOTI5Dc4XKeV32a+bWrQidGVzdCAoVGVzdCBrZXkpIDx0ZXN0QHViaWNh"
          + "bGwuY29tPohkBBMRAgAkBQJAPN79AhsDBQkB4TOABgsJCAcDAgMVAgMDFgIB"
          + "Ah4BAheAAAoJEJh8Njfhe8KmGDcAoJWr8xgPr75y/Cp1kKn12oCCOb8zAJ4p"
          + "xSvk4K6tB2jYbdeSrmoWBZLdMLACAAC5AQ0EQDzfARAEAJeUAPvUzJJbKcc5"
          + "5Iyb13+Gfb8xBWE3HinQzhGr1v6A1aIZbRj47UPAD/tQxwz8VAwJySx82ggN"
          + "LxCk4jW9YtTL3uZqfczsJngV25GoIN10f4/j2BVqZAaX3q79a3eMiql1T0oE"
          + "AGmD7tO1LkTvWfm3VvA0+t8/6ZeRLEiIqAOHAAQNBACD0mVMlAUgd7REYy/1"
          + "mL99Zlu9XU0uKyUex99sJNrcx1aj8rIiZtWaHz6CN1XptdwpDeSYEOFZ0PSu"
          + "qH9ByM3OfjU/ya0//xdvhwYXupn6P1Kep85efMBA9jUv/DeBOzRWMFG6sC6y"
          + "k8NGG7Swea7EHKeQI40G3jgO/+xANtMyTIhPBBgRAgAPBQJAPN8BAhsMBQkB"
          + "4TOAAAoJEJh8Njfhe8KmG7kAn00mTPGJCWqmskmzgdzeky5fWd7rAKCNCp3u"
          + "ZJhfg0htdgAfIy8ppm05vLACAAA=");

    byte[] marker = Hex.decode("2d2d2d2d2d454e4420504750205055424c4943204b455920424c4f434b2d2d2d2d2d");

    // Contains "Hello World!" as an armored message
    // The 'blank line' after the headers contains (legal) whitespace - see RFC2440 6.2
    private static final String blankLineData =
          "-----BEGIN PGP MESSAGE-----\n"
        + "Version: BCPG v1.32\n"
        + "Comment: A dummy message\n"
        + " \t \t\n"
        + "SGVsbG8gV29ybGQh\n"
        + "=d9Xi\n"
        + "-----END PGP MESSAGE-----\n";

    private int markerCount(
        byte[] data)
    {
        int ind = 0;
        int matches = 0;

        while (ind < data.length)
        {
            if (data[ind] == 0x2d)
            {
                int count = 0;
                while (count < marker.length)
                {
                    if (data[ind + count] != marker[count])
                    {
                        break;
                    }
                    count++;
                }

                if (count == marker.length)
                {
                    matches++;
                }

                ind += count;
            }
            else
            {
                ind++;
            }
        }

        return matches;
    }

    private void pgpUtilTest()
        throws Exception
    {
        // check decoder exception isn't escaping.
        ByteArrayInputStream bIn = new ByteArrayInputStream(Strings.toByteArray("abcde"));

        try
        {
            PGPUtil.getDecoderStream(bIn);
            fail("no exception");
        }
        catch (IOException e)
        {
            // expected: ignore.
        }
    }

    private void blankLineTest()
        throws Exception
    {
        byte[] blankLineBytes = Strings.toByteArray(blankLineData);
        ByteArrayInputStream bIn = new ByteArrayInputStream(blankLineBytes);
        ArmoredInputStream aIn = new ArmoredInputStream(bIn, true);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        int c;
        while ((c = aIn.read()) >= 0)
        {
            bOut.write(c);
        }

        byte[] expected = Strings.toByteArray("Hello World!");

        if (!Arrays.areEqual(expected, bOut.toByteArray()))
        {
            fail("Incorrect message retrieved in blank line test.");
        }
    }

    private void repeatHeaderTest()
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);

        aOut.setHeader("Comment", "Line 1");
        aOut.addHeader("Comment", "Line 2");

        aOut.write(sample);

        aOut.close();

        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        ArmoredInputStream aIn = new ArmoredInputStream(bIn, true);

        String[] hdrs = aIn.getArmorHeaders();
        int count = 0;

        for (int i = 0; i != hdrs.length; i++)
        {
            if (hdrs[i].indexOf("Comment: ") == 0)
            {
                count++;
            }
        }

        isEquals(2, count);
    }

    public void performTest()
        throws Exception
    {
        //
        // test immediate close
        //
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);

        aOut.close();

        byte[] data = bOut.toByteArray();

        if (data.length != 0)
        {
            fail("No data should have been written");
        }

        //
        // multiple close
        //
        bOut = new ByteArrayOutputStream();
        aOut = new ArmoredOutputStream(bOut);

        aOut.write(sample);

        aOut.close();

        aOut.close();

        int mc = markerCount(bOut.toByteArray());

        if (mc < 1)
        {
            fail("No end marker found");
        }

        if (mc > 1)
        {
            fail("More than one end marker found");
        }

        //
        // writing and reading single objects
        //
        bOut = new ByteArrayOutputStream();
        aOut = new ArmoredOutputStream(bOut);

        aOut.write(sample);

        aOut.close();

        ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        JcaPGPObjectFactory fact = new JcaPGPObjectFactory(aIn);
        int count = 0;

        while (fact.nextObject() != null)
        {
            count++;
        }

        if (count != 1)
        {
            fail("wrong number of objects found: " + count);
        }

        //
        // writing and reading multiple objects  - in single block
        //
        bOut = new ByteArrayOutputStream();
        aOut = new ArmoredOutputStream(bOut);

        aOut.write(sample);
        aOut.write(sample);

        aOut.close();

        aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        fact = new JcaPGPObjectFactory(aIn);
        count = 0;

        while (fact.nextObject() != null)
        {
            count++;
        }

        if (count != 2)
        {
            fail("wrong number of objects found: " + count);
        }

        //
        // writing and reading multiple objects  - in single block
        //
        bOut = new ByteArrayOutputStream();
        aOut = new ArmoredOutputStream(bOut);

        aOut.write(sample);

        aOut.close();     // does not close underlying stream

        aOut = new ArmoredOutputStream(bOut);

        aOut.write(sample);

        aOut.close();

        aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        count = 0;
        boolean atLeastOne;
        do
        {
            atLeastOne = false;
            fact = new JcaPGPObjectFactory(aIn);

            while (fact.nextObject() != null)
            {
                atLeastOne = true;
                count++;
            }
        }
        while (atLeastOne);

        if (count != 2)
        {
            fail("wrong number of objects found: " + count);
        }

        blankLineTest();
        pgpUtilTest();
        repeatHeaderTest();
    }

    public String getName()
    {
        return "PGPArmoredTest";
    }

    public static void main(
        String[]    args)
    {
        runTest(new PGPArmoredTest());
    }
}
