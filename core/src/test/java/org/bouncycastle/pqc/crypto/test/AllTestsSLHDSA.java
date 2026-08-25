package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsSLHDSA
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight SLH-DSA Tests");

        // testSigGenSingleFile, the longest SLHDSATest method, runs from AllTestsSLHDSASigGen
        // so the two halves run as separate (parallel) forks.
        TestSuite slhdsa = new TestSuite(SLHDSATest.class);
        for (java.util.Enumeration en = slhdsa.tests(); en.hasMoreElements();)
        {
            TestCase test = (TestCase)en.nextElement();
            if (!"testSigGenSingleFile".equals(test.getName()))
            {
                suite.addTest(test);
            }
        }

        return new AllTests.BCTestSetup(suite);
    }
}
