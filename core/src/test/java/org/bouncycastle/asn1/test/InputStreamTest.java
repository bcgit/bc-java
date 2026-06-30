package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class InputStreamTest
    extends SimpleTest
{
    private static final byte[] outOfBoundsLength = new byte[]{(byte)0x30, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff};
    private static final byte[] negativeLength = new byte[]{(byte)0x30, (byte)0x84, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff};
    private static final byte[] outsideLimitLength = new byte[]{(byte)0x30, (byte)0x83, (byte)0x0f, (byte)0xff, (byte)0xff};

    private static final byte[] classCast1 = Base64.decode("p1AkHmYAvfOEIrL4ESfrNg==");
    private static final byte[] classCast2 = Base64.decode("JICNbaBUTTq7uxj5mg==");
    private static final byte[] classCast3 = Base64.decode("JAKzADNCxhrrBSVS");
    private static final byte[] memoryError1 = Base64.decode("vm66gOiEe+FV/NvujMwSkUp5Lffw5caQlaRU5sdMPC70IGWmyK2/");
    private static final byte[] memoryError2 = Base64.decode("vm4ogOSEfVGsS3w+KTzb2A0ALYR8VBOQqQeuRwnsPC4AAGWEDLjd");

    public String getName()
    {
        return "InputStream";
    }

    public void performTest()
        throws Exception
    {
        ASN1InputStream aIn = new ASN1InputStream(outOfBoundsLength);

        try
        {
            aIn.readObject();
            fail("out of bounds length not detected.");
        }
        catch (IOException e)
        {
            if (!e.getMessage().equals("invalid long form definite-length 0xFF"))
            {
                fail("wrong exception: " + e.getMessage());
            }
        }

        // NOTE: Not really a "negative" length, but 32 bits
        aIn = new ASN1InputStream(negativeLength);

        try
        {
            aIn.readObject();
            fail("negative length not detected.");
        }
        catch (IOException e)
        {
            if (!e.getMessage().equals("long form definite-length more than 31 bits"))
            {
                fail("wrong exception: " + e.getMessage());
            }
        }

        aIn = new ASN1InputStream(outsideLimitLength);

        try
        {
            aIn.readObject();
            fail("outside limit length not detected.");
        }
        catch (IOException e)
        {
            if (!e.getMessage().equals("corrupted stream - out of bounds length found: 1048575 > 5"))
            {
                fail("wrong exception: " + e.getMessage());
            }
        }

        /*
         * The arrays below are fuzzer-generated inputs that originally provoked ClassCastException
         * or OutOfMemoryError. They are preserved byte-for-byte (several also contain out-of-bounds
         * lengths, so e.g. classCast1 fails on a length check before reaching the cast it is named
         * for); the requirement is that each fails cleanly with an IOException.
         */
        testWithByteArray(classCast1, "corrupted stream - out of bounds length found: 80 > 16");
        testWithByteArray(classCast2, "unknown object encountered: class org.bouncycastle.asn1.DLTaggedObjectParser");
        testWithByteArray(classCast3, "unknown object encountered in constructed OCTET STRING: class org.bouncycastle.asn1.DLTaggedObject");

        // the point of failure (and so the message) for these depends on parser implementation
        // choices, so only require the clean IOException
        testWithByteArray(memoryError1, null);
        testWithByteArray(memoryError2, null);
    }

    private void testWithByteArray(byte[] data, String message)
    {
        try
        {
            ASN1InputStream input = new ASN1InputStream(data);

            ASN1Primitive p;
            while ((p = input.readObject()) != null)
            {
                ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
                for (int i = 0; i < asn1.size(); i++)
                {
                    asn1.getObjectAt(i);
                }
            }

            fail("malformed input accepted without exception");
        }
        catch (java.io.IOException e)
        {
            if (message != null)
            {
                isEquals(e.getMessage(), message, e.getMessage());
            }
        }
    }

    public static void main(
        String[] args)
    {
        runTest(new InputStreamTest());
    }
}
