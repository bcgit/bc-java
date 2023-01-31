package org.bouncycastle.mls.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("MLS tests");

        suite.addTestSuite(TreeMathTest.class);
        suite.addTestSuite(CodecTest.class);
        suite.addTestSuite(CipherSuiteTest.class);
        suite.addTestSuite(SecretTest.class);
        suite.addTestSuite(GroupKeySetTest.class);
        suite.addTestSuite(KeyScheduleTest.class);

        return new BCTestSetup(suite);
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
