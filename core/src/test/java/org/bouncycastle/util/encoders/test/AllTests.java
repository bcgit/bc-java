package org.bouncycastle.util.encoders.test;

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
        junit.textui.TestRunner.run (suite());
    }

    public void testUTF8()
    {
        SimpleTestResult result = (SimpleTestResult)new UTF8Test().perform();

        if (!result.isSuccessful())
        {
            fail(result.toString());
        }
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("encoder tests");
        suite.addTestSuite(Base64Test.class);
        suite.addTestSuite(UrlBase64Test.class);
        suite.addTestSuite(HexTest.class);
        suite.addTestSuite(Base32Test.class);
        suite.addTestSuite(NonASCIIDecodeTest.class);
        suite.addTestSuite(AllTests.class);
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
