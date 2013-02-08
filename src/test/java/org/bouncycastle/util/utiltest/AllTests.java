package org.bouncycastle.util.utiltest;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AllTests
{
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run (suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("util tests");
        suite.addTestSuite(IPTest.class);
        suite.addTestSuite(BigIntegersTest.class);
        return suite;
    }
}
