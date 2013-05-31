package org.bouncycastle.crypto.tls.test;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AllTests
{
    public static void main(String[] args)
        throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("TLS tests");

        suite.addTest(BasicTlsTest.suite());

        return suite;
    }
}
