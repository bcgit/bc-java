package org.bouncycastle.tls.keylog.test;

import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.tls.test.TlsKeyLogTest;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("TLS key log tests");

        suite.addTestSuite(TlsKeyLogTest.class);

        return new BCTestSetup(suite);
    }

    static class BCTestSetup
        extends TestSetup
    {
        BCTestSetup(Test test)
        {
            super(test);
        }
    }
}
