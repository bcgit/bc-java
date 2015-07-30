package org.bouncycastle.crypto.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.util.test.SimpleTestResult;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight Crypto Tests");
        
        suite.addTestSuite(SimpleTestTest.class);
        suite.addTestSuite(GCMReorderTest.class);
        
        return new BCTestSetup(suite);
    }

    public static class SimpleTestTest
       extends TestCase
    {
        public void testCrypto()
        {
            org.bouncycastle.util.test.Test[] tests = RegressionTest.tests;

            for (int i = 0; i != tests.length; i++)
            {
                SimpleTestResult  result = (SimpleTestResult)tests[i].perform();

                if (!result.isSuccessful())
                {
                    if (result.getException() != null)
                    {
                        result.getException().printStackTrace();
                    }
                    fail(result.toString());
                }
            }
        }
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
