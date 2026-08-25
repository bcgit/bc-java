package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsSLHDSASigGen
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight SLH-DSA Tests (ACVP sigGen file)");

        // see AllTestsSLHDSA.
        suite.addTest(TestSuite.createTest(SLHDSATest.class, "testSigGenSingleFile"));

        return new AllTests.BCTestSetup(suite);
    }
}
