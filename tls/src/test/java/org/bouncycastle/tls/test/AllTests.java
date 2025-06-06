package org.bouncycastle.tls.test;

import org.bouncycastle.test.PrintTestResult;

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
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("TLS tests");

        suite.addTestSuite(BasicTlsTest.class);
        suite.addTestSuite(BcTlsProtocolHybridTest.class);
        suite.addTestSuite(BcTlsProtocolKemTest.class);
        suite.addTestSuite(ByteQueueInputStreamTest.class);
        suite.addTestSuite(DTLSAggregatedHandshakeRetransmissionTest.class);
        suite.addTestSuite(DTLSHandshakeRetransmissionTest.class);
        suite.addTestSuite(DTLSProtocolTest.class);
        suite.addTestSuite(DTLSPSKProtocolTest.class);
        suite.addTestSuite(DTLSRawKeysProtocolTest.class);
        suite.addTestSuite(JcaTlsProtocolHybridTest.class);
        suite.addTestSuite(JcaTlsProtocolKemTest.class);
        suite.addTestSuite(OCSPTest.class);
        suite.addTestSuite(PRFTest.class);
        suite.addTestSuite(Tls13PSKProtocolTest.class);
        suite.addTestSuite(TlsProtocolNonBlockingTest.class);
        suite.addTestSuite(TlsProtocolTest.class);
        suite.addTestSuite(TlsPSKProtocolTest.class);
        suite.addTestSuite(TlsRawKeysProtocolTest.class);
        suite.addTestSuite(TlsSRPProtocolTest.class);
        suite.addTestSuite(TlsUtilsTest.class);

        suite.addTest(DTLSTestSuite.suite());
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
