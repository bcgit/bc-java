package org.bouncycastle.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import java.security.Security;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {

        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("JVM Version Tests");
        suite.addTestSuite(JVMVersionTest.class);


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
//            Security.addProvider(new BouncyCastleProvider());
        }

        protected void tearDown()
        {
 //           Security.removeProvider("BC");
        }
    }
}
