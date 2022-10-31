package org.bouncycastle.openpgp.test;

import java.security.Security;
import java.util.Enumeration;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestFailure;
import junit.framework.TestResult;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTestResult;

public class AllTests
    extends TestCase
{
    public void testPGP()
    {   
        Security.addProvider(new BouncyCastleProvider());
        
        org.bouncycastle.util.test.Test[] tests = RegressionTest.tests;
        
        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult  result = (SimpleTestResult)tests[i].perform();
            
            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }
    
    public static void main (String[] args)
    {
        TestResult tr = junit.textui.TestRunner.run(suite());
        Enumeration<TestFailure> e = tr.errors();
        while(e.hasMoreElements()) {
            System.out.println(e.nextElement());
        }

        e = tr.failures();
        while(e.hasMoreElements()) {
            System.out.println(e.nextElement());
        }

        if (!tr.wasSuccessful())
        {
            System.exit(1);
        }
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("OpenPGP Tests");
        
        suite.addTestSuite(AllTests.class);
        suite.addTestSuite(DSA2Test.class);
        suite.addTestSuite(PGPUnicodeTest.class);

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
            Security.addProvider(new BouncyCastleProvider());
        }

        protected void tearDown()
        {
            Security.removeProvider("BC");
        }
    }
}
