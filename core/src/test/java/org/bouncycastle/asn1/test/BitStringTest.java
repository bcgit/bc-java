package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

public class BitStringTest
    extends SimpleTest
{
    private void testRandomPadBits()
        throws Exception
    {
        byte[] test = Hex.decode("030206c0");

        byte[] test1 = Hex.decode("030206f0");
        byte[] test2 = Hex.decode("030206c1");
        byte[] test3 = Hex.decode("030206c7");
        byte[] test4 = Hex.decode("030206d1");

        encodingCheck(test, test1);
        encodingCheck(test, test2);
        encodingCheck(test, test3);
        encodingCheck(test, test4);
    }

    private void encodingCheck(byte[] derData, byte[] dlData)
        throws IOException
    {
        if (Arrays.areEqual(derData, ASN1Primitive.fromByteArray(dlData).getEncoded()))
        {
            fail("failed DL check");
        }
        if (!Arrays.areEqual(derData, ASN1Primitive.fromByteArray(dlData).getEncoded(ASN1Encoding.DER)))
        {
            fail("failed DER check");
        }
    }

    public void performTest()
        throws Exception
    {
        KeyUsage k = new KeyUsage(KeyUsage.digitalSignature);
        if ((k.getBytes()[0] != (byte)KeyUsage.digitalSignature) || (k.getPadBits() != 7))
        {
            fail("failed digitalSignature");
        }
        
        k = new KeyUsage(KeyUsage.nonRepudiation);
        if ((k.getBytes()[0] != (byte)KeyUsage.nonRepudiation) || (k.getPadBits() != 6))
        {
            fail("failed nonRepudiation");
        }
        
        k = new KeyUsage(KeyUsage.keyEncipherment);
        if ((k.getBytes()[0] != (byte)KeyUsage.keyEncipherment) || (k.getPadBits() != 5))
        {
            fail("failed keyEncipherment");
        }
        
        k = new KeyUsage(KeyUsage.cRLSign);
        if ((k.getBytes()[0] != (byte)KeyUsage.cRLSign)  || (k.getPadBits() != 1))
        {
            fail("failed cRLSign");
        }
        
        k = new KeyUsage(KeyUsage.decipherOnly);
        if ((k.getBytes()[1] != (byte)(KeyUsage.decipherOnly >> 8))  || (k.getPadBits() != 7))
        {
            fail("failed decipherOnly");
        }

        // test for zero length bit string
        try
        {
            ASN1Primitive.fromByteArray(new DERBitString(new byte[0], 0).getEncoded());
        }
        catch (IOException e)
        {
            fail(e.toString());
        }

        testRandomPadBits();
    }

    public String getName()
    {
        return "BitString";
    }

    public static void main(
        String[] args)
    {
        BitStringTest    test = new BitStringTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
