package org.bouncycastle.crypto.tls.test;

import org.bouncycastle.crypto.tls.AlertDescription;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TlsTestSuite extends TestSuite
{
    // Make the access to constants less verbose 
    static abstract class C extends TlsTestConfig {}

    public static Test suite()
    {
        TlsTestSuite testSuite = new TlsTestSuite();

        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
            c.expectServerFatalAlert(AlertDescription.decrypt_error);

            testSuite.addTest(new TlsTestCase(c, "BadCertificateVerify"));
        }

        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
            c.expectServerFatalAlert(AlertDescription.bad_certificate);

            testSuite.addTest(new TlsTestCase(c, "BadClientCertificate"));
        }

        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientAuth = C.CLIENT_AUTH_NONE;
            c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
            c.expectServerFatalAlert(AlertDescription.handshake_failure);

            testSuite.addTest(new TlsTestCase(c, "BadMandatoryCertReqDeclined"));
        }

        {
            TlsTestConfig c = new TlsTestConfig();

            testSuite.addTest(new TlsTestCase(c, "GoodDefault"));
        }

        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientAuth = C.CLIENT_AUTH_NONE;

            testSuite.addTest(new TlsTestCase(c, "GoodOptionalCertReqDeclined"));
        }

        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientAuth = C.CLIENT_AUTH_NONE;
            c.serverCertReq = C.SERVER_CERT_REQ_NONE;

            testSuite.addTest(new TlsTestCase(c, "GoodServerOnlyAuthentication"));
        }

        return testSuite;
    }
}
