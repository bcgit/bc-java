package org.bouncycastle.crypto.agreement.owl.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.crypto.agreement.owl.OwlUtilTest;
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
        TestSuite suite = new TestSuite("Owl Engine Tests");

        suite.addTestSuite(OwlCurveTest.class);
        suite.addTestSuite(OwlUtilTest.class);
        suite.addTestSuite(OwlClientRegistrationTest.class);
        suite.addTestSuite(OwlServerRegistrationTest.class);
        suite.addTestSuite(OwlClientTest.class);
        suite.addTestSuite(OwlServerTest.class);

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
