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
            if (!e.getMessage().startsWith("DER length more than 4 bytes"))
            {
                fail("wrong exception: " + e.getMessage());
            }
        }

        aIn = new ASN1InputStream(negativeLength);

        try
        {
            aIn.readObject();
            fail("negative length not detected.");
        }
        catch (IOException e)
        {
            if (!e.getMessage().equals("corrupted stream - negative length found"))
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
            if (!e.getMessage().equals("corrupted stream - out of bounds length found: 1048575 >= 5"))
            {
                fail("wrong exception: " + e.getMessage());
            }
        }

        testWithByteArray(classCast1, "unknown object encountered: class org.bouncycastle.asn1.DLApplicationSpecific");
        testWithByteArray(classCast2, "unknown object encountered: class org.bouncycastle.asn1.BERTaggedObjectParser");
        testWithByteArray(classCast3, "unknown object encountered in constructed OCTET STRING: class org.bouncycastle.asn1.DLTaggedObject");

        testWithByteArray(memoryError1, "corrupted stream - out of bounds length found: 2078365180 >= 39");
        testWithByteArray(memoryError2, "corrupted stream - out of bounds length found: 2102504523 >= 39");
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
        }
        catch (java.io.IOException e)
        {
            isEquals(e.getMessage(), message, e.getMessage());
        }
    }

    public static void main(
        String[] args)
    {
        runTest(new InputStreamTest());
    }
}
