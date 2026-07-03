package org.bouncycastle.pqc.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTestsXMSS
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight XMSS Tests");

        suite.addTestSuite(XMSSMTPrivateKeyTest.class);
        suite.addTestSuite(XMSSMTPublicKeyTest.class);
        suite.addTestSuite(XMSSMTSignatureTest.class);
        suite.addTestSuite(XMSSMTTest.class);
        suite.addTestSuite(XMSSOidTest.class);
        suite.addTestSuite(XMSSPrivateKeyTest.class);
        suite.addTestSuite(XMSSPublicKeyTest.class);
        suite.addTestSuite(XMSSReducedSignatureTest.class);
        suite.addTestSuite(XMSSSignatureTest.class);
        suite.addTestSuite(XMSSTest.class);
        suite.addTestSuite(XMSSUtilTest.class);
        suite.addTestSuite(XMSSPublicKeyParseTest.class);
        suite.addTestSuite(XMSSPrivateKeyEncodingTest.class);

        return new AllTests.BCTestSetup(suite);
    }
}
