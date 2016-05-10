package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;

import com.github.gv2011.bcasn.asn1.misc.NetscapeCertType;
import com.github.gv2011.bcasn.util.test.SimpleTest;

public class NetscapeCertTypeTest
    extends SimpleTest
{
    public String getName()
    {
        return "NetscapeCertType";
    }

    public void performTest()
        throws IOException
    {
        BitStringConstantTester.testFlagValueCorrect(0, NetscapeCertType.sslClient);
        BitStringConstantTester.testFlagValueCorrect(1, NetscapeCertType.sslServer);
        BitStringConstantTester.testFlagValueCorrect(2, NetscapeCertType.smime);
        BitStringConstantTester.testFlagValueCorrect(3, NetscapeCertType.objectSigning);
        BitStringConstantTester.testFlagValueCorrect(4, NetscapeCertType.reserved);
        BitStringConstantTester.testFlagValueCorrect(5, NetscapeCertType.sslCA);
        BitStringConstantTester.testFlagValueCorrect(6, NetscapeCertType.smimeCA);
        BitStringConstantTester.testFlagValueCorrect(7, NetscapeCertType.objectSigningCA);
    }

    public static void main(
        String[]    args)
    {
        runTest(new NetscapeCertTypeTest());
    }
}
