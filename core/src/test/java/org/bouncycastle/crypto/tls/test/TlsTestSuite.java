package org.bouncycastle.crypto.tls.test;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.ProtocolVersion;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TlsTestSuite extends TestSuite
{
    // Make the access to constants less verbose 
    static abstract class C extends TlsTestConfig {}

    public static Test suite()
    {
        TlsTestSuite testSuite = new TlsTestSuite();

        addVersionTests(testSuite, ProtocolVersion.TLSv10);
        addVersionTests(testSuite, ProtocolVersion.TLSv11);
        addVersionTests(testSuite, ProtocolVersion.TLSv12);

        return testSuite;
    }

    private static void addVersionTests(TestSuite testSuite, ProtocolVersion version)
    {
        String prefix = version.toString().replaceAll("[ \\.]", "") + "_";

        {
            TlsTestConfig c = new TlsTestConfig();
            c.serverMaximumVersion = version;

            testSuite.addTest(new TlsTestCase(c, prefix + "GoodDefault"));
        }

        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
            c.serverMaximumVersion = version;
            c.expectServerFatalAlert(AlertDescription.decrypt_error);

            testSuite.addTest(new TlsTestCase(c, prefix + "BadCertificateVerify"));
        }

        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
            c.serverMaximumVersion = version;
            c.expectServerFatalAlert(AlertDescription.bad_certificate);

            testSuite.addTest(new TlsTestCase(c, prefix + "BadClientCertificate"));
        }

        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientAuth = C.CLIENT_AUTH_NONE;
            c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
            c.serverMaximumVersion = version;
            c.expectServerFatalAlert(AlertDescription.handshake_failure);

            testSuite.addTest(new TlsTestCase(c, prefix + "BadMandatoryCertReqDeclined"));
        }

        {
            TlsTestConfig c = new TlsTestConfig();
            c.serverCertReq = C.SERVER_CERT_REQ_NONE;
            c.serverMaximumVersion = version;

            testSuite.addTest(new TlsTestCase(c, prefix + "GoodNoCertReq"));
        }

        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientAuth = C.CLIENT_AUTH_NONE;
            c.serverMaximumVersion = version;

            testSuite.addTest(new TlsTestCase(c, prefix + "GoodOptionalCertReqDeclined"));
        }
    }
}
