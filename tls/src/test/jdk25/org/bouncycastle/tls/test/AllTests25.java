package org.bouncycastle.tls.test;

import org.bouncycastle.test.PrintTestResult;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests25
    extends TestCase
{
    public static void main(String[] args) throws Exception
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite() throws Exception
    {
        TestSuite suite = new TestSuite("JDK25 TLS tests");
        suite.addTestSuite(JdkTlsProtocolHybridTest.class);
        suite.addTestSuite(JdkTlsProtocolKemTest.class);
        return suite;
    }
}
