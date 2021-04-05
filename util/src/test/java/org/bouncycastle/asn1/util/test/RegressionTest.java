package org.bouncycastle.asn1.util.test;

import org.bouncycastle.asn1.isismtt.test.AdditionalInformationSyntaxUnitTest;
import org.bouncycastle.asn1.isismtt.test.AdmissionsUnitTest;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;

public class RegressionTest
{
    public static Test[]    tests = {
        new AdditionalInformationSyntaxUnitTest(),
        new AdmissionsUnitTest()
    };

    public static void main(String[] args)
    {
        SimpleTest.runTests(tests);
    }
}
