package org.bouncycastle.crypto.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
       PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("Lightweight Crypto Tests");
        
        suite.addTestSuite(SimpleTestTest.class);
        suite.addTestSuite(GCMReorderTest.class);
        suite.addTestSuite(HPKETestVectors.class);
        
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
