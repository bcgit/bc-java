package org.bouncycastle.cades.test;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AllTests
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("CAdES tests");

        suite.addTestSuite(CAdESBESTest.class);
        suite.addTestSuite(CAdESTTest.class);
        suite.addTestSuite(CAdESLTTest.class);
        suite.addTestSuite(CAdESLTATest.class);

        return suite;
    }
}
