package org.bouncycastle.util.encoders.test;

import junit.framework.*;

public class AllTests
{
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run (suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("encoder tests");
        suite.addTestSuite(Base64Test.class);
        suite.addTestSuite(UrlBase64Test.class);
        suite.addTestSuite(HexTest.class);
        return suite;
    }
}
