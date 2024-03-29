package org.bouncycastle.test;


import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTest extends TestCase
{
    public static void main(String[] args)
            throws Exception
    {
        PrintTestResult.printResult( junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
            throws Exception
    {
        TestSuite suite = new TestSuite("JVM Version test");

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

        }

        protected void tearDown()
        {

        }
    }

}
