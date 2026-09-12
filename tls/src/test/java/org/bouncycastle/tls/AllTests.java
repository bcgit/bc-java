package org.bouncycastle.tls;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

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

        suite.addTestSuite(AbstractTlsServerResetTest.class);
        suite.addTestSuite(Add13CertificateStatusTest.class);
        suite.addTestSuite(CheckTlsFeaturesExtensionTest.class);
        suite.addTestSuite(DTLS13AckGenerationTest.class);
        suite.addTestSuite(DTLS13FlightTrackerTest.class);
        suite.addTestSuite(DTLS13KeyScheduleLabelTest.class);
        suite.addTestSuite(DTLS13RetransmissionTest.class);
        suite.addTestSuite(DTLS13UnifiedHeaderTest.class);
        suite.addTestSuite(DTLSAckTest.class);
        suite.addTestSuite(DTLSAckTransportTest.class);
        suite.addTestSuite(DTLSReassemblerTest.class);
        suite.addTestSuite(DTLSRecordLayer13Test.class);
        suite.addTestSuite(DTLSRecordLayerAggregationTest.class);
        suite.addTestSuite(DTLSRecordNumberMaskTest.class);
        suite.addTestSuite(SpreadCertificateStatusTest.class);
        suite.addTestSuite(TlsAEADCipherDTLS13Test.class);

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
