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

        addFallbackTests(testSuite);
        addVersionTests(testSuite, ProtocolVersion.TLSv10);
        addVersionTests(testSuite, ProtocolVersion.TLSv11);
        addVersionTests(testSuite, ProtocolVersion.TLSv12);

        return testSuite;
    }

    private static void addFallbackTests(TestSuite testSuite)
    {
        {
            TlsTestConfig c = createTlsTestConfig(ProtocolVersion.TLSv12);
            c.clientFallback = true;

            testSuite.addTest(new TlsTestCase(c, "FallbackGood"));
        }

        {
            TlsTestConfig c = createTlsTestConfig(ProtocolVersion.TLSv12);
            c.clientOfferVersion = ProtocolVersion.TLSv11;
            c.clientFallback = true;
            c.expectServerFatalAlert(AlertDescription.inappropriate_fallback);

            testSuite.addTest(new TlsTestCase(c, "FallbackBad"));
        }

        {
            TlsTestConfig c = createTlsTestConfig(ProtocolVersion.TLSv12);
            c.clientOfferVersion = ProtocolVersion.TLSv11;

            testSuite.addTest(new TlsTestCase(c, "FallbackNone"));
        }
    }

    private static void addVersionTests(TestSuite testSuite, ProtocolVersion version)
    {
        String prefix = version.toString().replaceAll("[ \\.]", "") + "_";

        {
            TlsTestConfig c = createTlsTestConfig(version);

            testSuite.addTest(new TlsTestCase(c, prefix + "GoodDefault"));
        }

        {
            TlsTestConfig c = createTlsTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
            c.expectServerFatalAlert(AlertDescription.decrypt_error);

            testSuite.addTest(new TlsTestCase(c, prefix + "BadCertificateVerify"));
        }

        {
            TlsTestConfig c = createTlsTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
            c.expectServerFatalAlert(AlertDescription.bad_certificate);

            testSuite.addTest(new TlsTestCase(c, prefix + "BadClientCertificate"));
        }

        {
            TlsTestConfig c = createTlsTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_NONE;
            c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
            c.expectServerFatalAlert(AlertDescription.handshake_failure);

            testSuite.addTest(new TlsTestCase(c, prefix + "BadMandatoryCertReqDeclined"));
        }

        {
            TlsTestConfig c = createTlsTestConfig(version);
            c.serverCertReq = C.SERVER_CERT_REQ_NONE;

            testSuite.addTest(new TlsTestCase(c, prefix + "GoodNoCertReq"));
        }

        {
            TlsTestConfig c = createTlsTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_NONE;

            testSuite.addTest(new TlsTestCase(c, prefix + "GoodOptionalCertReqDeclined"));
        }
    }

    private static TlsTestConfig createTlsTestConfig(ProtocolVersion version)
    {
        TlsTestConfig c = new TlsTestConfig();
        c.clientMinimumVersion = ProtocolVersion.TLSv10;
        c.clientOfferVersion = ProtocolVersion.TLSv12;
        c.serverMaximumVersion = version;
        c.serverMinimumVersion = ProtocolVersion.TLSv10;
        return c;
    }
}
