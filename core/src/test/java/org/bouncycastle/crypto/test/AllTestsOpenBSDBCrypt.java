package org.bouncycastle.crypto.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.test.SimpleTestResult;

public class AllTestsOpenBSDBCrypt
    extends TestCase
{
    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight OpenBSD BCrypt Tests");

        suite.addTestSuite(AllTestsOpenBSDBCrypt.RegressionTestTest.class);

        return new AllTests.BCTestSetup(suite);
    }

    public static class RegressionTestTest
        extends TestCase
    {
        public void testOpenBSDBCrypt()
        {
            runTests(RegressionTest.openBSDBCryptTests);
        }
    }

    private static void runTests(org.bouncycastle.util.test.Test[] tests)
    {
        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult result = (SimpleTestResult)tests[i].perform();

            if (!result.isSuccessful())
            {
                if (result.getException() != null)
                {
                    result.getException().printStackTrace();
                }
                fail(i + " -> " + result.toString());
            }
        }
    }
}
