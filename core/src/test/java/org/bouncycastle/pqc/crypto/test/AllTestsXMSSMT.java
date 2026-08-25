package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsXMSSMT
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight XMSS^MT Tests");

        suite.addTestSuite(XMSSMTPrivateKeyTest.class);
        suite.addTestSuite(XMSSMTPublicKeyTest.class);
        suite.addTestSuite(XMSSMTSignatureTest.class);
        suite.addTestSuite(XMSSMTTest.class);

        return new AllTests.BCTestSetup(suite);
    }
}
