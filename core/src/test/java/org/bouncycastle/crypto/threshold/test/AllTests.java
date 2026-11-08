package org.bouncycastle.crypto.threshold.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.crypto.threshold.ShamirSplitSecretTest;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Secret Sharing Tests");
        suite.addTestSuite(ShamirSecretSplitterTest.class);
        suite.addTestSuite(ShamirSplitSecretTest.class);
        return new AllTests.BCTestSetup(suite);
    }

    static class BCTestSetup
        extends TestSetup
    {
        public BCTestSetup(Test test)
        {
            super(test);
        }

        protected void setUp()
        {

        }

        protected void tearDown()
        {

        }
    }
}
