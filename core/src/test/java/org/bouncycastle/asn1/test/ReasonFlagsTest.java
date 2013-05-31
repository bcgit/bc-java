package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.util.test.SimpleTest;

public class ReasonFlagsTest
    extends SimpleTest
{
    public String getName()
    {
        return "ReasonFlags";
    }

    public void performTest()
        throws IOException
    {
        BitStringConstantTester.testFlagValueCorrect(0, ReasonFlags.unused);
        BitStringConstantTester.testFlagValueCorrect(1, ReasonFlags.keyCompromise);
        BitStringConstantTester.testFlagValueCorrect(2, ReasonFlags.cACompromise);
        BitStringConstantTester.testFlagValueCorrect(3, ReasonFlags.affiliationChanged);
        BitStringConstantTester.testFlagValueCorrect(4, ReasonFlags.superseded);
        BitStringConstantTester.testFlagValueCorrect(5, ReasonFlags.cessationOfOperation);
        BitStringConstantTester.testFlagValueCorrect(6, ReasonFlags.certificateHold);
        BitStringConstantTester.testFlagValueCorrect(7, ReasonFlags.privilegeWithdrawn);
        BitStringConstantTester.testFlagValueCorrect(8, ReasonFlags.aACompromise);
    }

    public static void main(
        String[]    args)
    {
        runTest(new ReasonFlagsTest());
    }
}
