package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsCMCE
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight Classic McEliece Tests");   // ISO/IEC 18033-2 KEM vectors

        suite.addTestSuite(CMCEKEMVectorTest.class);

        return new AllTests.BCTestSetup(suite);
    }
}
