package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.util.test.SimpleTest;

public class KeyUsageTest
    extends SimpleTest
{
    public String getName()
    {
        return "KeyUsage";
    }

    public void performTest()
        throws IOException
    {
        BitStringConstantTester.testFlagValueCorrect(0, KeyUsage.digitalSignature); 
        BitStringConstantTester.testFlagValueCorrect(1, KeyUsage.nonRepudiation);
        BitStringConstantTester.testFlagValueCorrect(2, KeyUsage.keyEncipherment);
        BitStringConstantTester.testFlagValueCorrect(3, KeyUsage.dataEncipherment);
        BitStringConstantTester.testFlagValueCorrect(4, KeyUsage.keyAgreement);
        BitStringConstantTester.testFlagValueCorrect(5, KeyUsage.keyCertSign);
        BitStringConstantTester.testFlagValueCorrect(6, KeyUsage.cRLSign);
        BitStringConstantTester.testFlagValueCorrect(7, KeyUsage.encipherOnly);
        BitStringConstantTester.testFlagValueCorrect(8, KeyUsage.decipherOnly);
    }

    public static void main(
        String[]    args)
    {
        runTest(new KeyUsageTest());
    }
}
