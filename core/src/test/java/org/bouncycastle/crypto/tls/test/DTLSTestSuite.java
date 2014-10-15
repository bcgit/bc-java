package org.bouncycastle.crypto.tls.test;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.ProtocolVersion;

public class DTLSTestSuite extends TestSuite
{
    // Make the access to constants less verbose 
    static abstract class C extends TlsTestConfig {}

    public static Test suite()
    {
        DTLSTestSuite testSuite = new DTLSTestSuite();

        addFallbackTests(testSuite);
        addVersionTests(testSuite, ProtocolVersion.DTLSv10);
        addVersionTests(testSuite, ProtocolVersion.DTLSv12);

        return testSuite;
    }

    private static void addFallbackTests(TestSuite testSuite)
    {
        {
            TlsTestConfig c = createDTLSTestConfig(ProtocolVersion.DTLSv12);
            c.clientFallback = true;

            testSuite.addTest(new DTLSTestCase(c, "FallbackGood"));
        }

        /*
         * NOTE: Temporarily disabled automatic test runs because of problems getting a clean exit
         * of the DTLS server after a fatal alert. As of writing, manual runs show the correct
         * alerts being raised
         */

//        {
//            TlsTestConfig c = createDTLSTestConfig(ProtocolVersion.DTLSv12);
//            c.clientOfferVersion = ProtocolVersion.DTLSv10;
//            c.clientFallback = true;
//            c.expectServerFatalAlert(AlertDescription.inappropriate_fallback);
//
//            testSuite.addTest(new DTLSTestCase(c, "FallbackBad"));
//        }

        {
            TlsTestConfig c = createDTLSTestConfig(ProtocolVersion.DTLSv12);
            c.clientOfferVersion = ProtocolVersion.DTLSv10;

            testSuite.addTest(new DTLSTestCase(c, "FallbackNone"));
        }
    }

    private static void addVersionTests(TestSuite testSuite, ProtocolVersion version)
    {
        String prefix = version.toString().replaceAll("[ \\.]", "") + "_";

        /*
         * NOTE: Temporarily disabled automatic test runs because of problems getting a clean exit
         * of the DTLS server after a fatal alert. As of writing, manual runs show the correct
         * alerts being raised
         */

//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
//            c.expectServerFatalAlert(AlertDescription.decrypt_error);
//
//            testSuite.addTest(new DTLSTestCase(c, prefix + "BadCertificateVerify"));
//        }
//
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
//            c.expectServerFatalAlert(AlertDescription.bad_certificate);
//
//            testSuite.addTest(new DTLSTestCase(c, prefix + "BadClientCertificate"));
//        }
//
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_NONE;
//            c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
//            c.expectServerFatalAlert(AlertDescription.handshake_failure);
//
//            testSuite.addTest(new DTLSTestCase(c, prefix + "BadMandatoryCertReqDeclined"));
//        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);

            testSuite.addTest(new DTLSTestCase(c, prefix + "GoodDefault"));
        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.serverCertReq = C.SERVER_CERT_REQ_NONE;

            testSuite.addTest(new DTLSTestCase(c, prefix + "GoodNoCertReq"));
        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_NONE;

            testSuite.addTest(new DTLSTestCase(c, prefix + "GoodOptionalCertReqDeclined"));
        }
    }

    private static TlsTestConfig createDTLSTestConfig(ProtocolVersion version)
    {
        TlsTestConfig c = new TlsTestConfig();
        c.clientMinimumVersion = ProtocolVersion.DTLSv10;
        /*
         * TODO We'd like to just set the offer version to DTLSv12, but there is a known issue with
         * overly-restrictive version checks b/w BC DTLS 1.2 client, BC DTLS 1.0 server
         */
        c.clientOfferVersion = version;
        c.serverMaximumVersion = version;
        c.serverMinimumVersion = ProtocolVersion.DTLSv10;
        return c;
    }
}
