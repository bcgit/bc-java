package org.bouncycastle.util.encoders.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
{
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run (suite());

        UTF8Test.main(null);
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("encoder tests");
        suite.addTestSuite(Base64Test.class);
        suite.addTestSuite(UrlBase64Test.class);
        suite.addTestSuite(HexTest.class);
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
