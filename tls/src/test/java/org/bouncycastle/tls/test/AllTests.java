package org.bouncycastle.tls.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests
    extends TestCase
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

        suite.addTestSuite(BasicTlsTest.class);
        suite.addTestSuite(DTLSProtocolTest.class);
        suite.addTestSuite(DTLSTestCase.class);
        suite.addTestSuite(TlsProtocolTest.class);
        suite.addTestSuite(TlsPSKProtocolTest.class);
        suite.addTestSuite(TlsSRPProtocolTest.class);
        suite.addTestSuite(TlsTestCase.class);
        suite.addTest(TlsTestSuite.suite());

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
