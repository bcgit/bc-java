package org.bouncycastle.crypto.tls.test;

import org.bouncycastle.crypto.tls.ProtocolVersion;

import junit.framework.Test;
import junit.framework.TestSuite;

public class DTLSTestSuite extends TestSuite
{
    // Make the access to constants less verbose 
    static abstract class C extends TlsTestConfig {}

    public DTLSTestSuite()
    {
        super("DTLS");
    }

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

            addTestCase(testSuite, c, "FallbackGood");
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
//            addTestCase(testSuite, c, "FallbackBad");
//        }

        {
            TlsTestConfig c = createDTLSTestConfig(ProtocolVersion.DTLSv12);
            c.clientOfferVersion = ProtocolVersion.DTLSv10;

            addTestCase(testSuite, c, "FallbackNone");
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

//        /*
//         * Server only declares support for SHA1/RSA, client selects MD5/RSA. Since the client is
//         * NOT actually tracking MD5 over the handshake, we expect fatal alert from the client.
//         */
//        if (TlsUtils.isTLSv12(version))
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_VALID;
//            c.clientAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.md5, SignatureAlgorithm.rsa);
//            c.serverCertReqSigAlgs = TlsUtils.getDefaultRSASignatureAlgorithms();
//            c.expectClientFatalAlert(AlertDescription.internal_error);
//
//            addTestCase(testSuite, c, prefix + "BadCertificateVerifyHashAlg");
//        }
//
//        /*
//         * Server only declares support for SHA1/ECDSA, client selects SHA1/RSA. Since the client is
//         * actually tracking SHA1 over the handshake, we expect fatal alert to come from the server
//         * when it verifies the selected algorithm against the CertificateRequest supported
//         * algorithms.
//         */
//        if (TlsUtils.isTLSv12(version))
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_VALID;
//            c.clientAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.rsa);
//            c.serverCertReqSigAlgs = TlsUtils.getDefaultECDSASignatureAlgorithms();
//            c.expectServerFatalAlert(AlertDescription.illegal_parameter);
//
//            addTestCase(testSuite, c, prefix + "BadCertificateVerifySigAlg");
//        }
//
//        /*
//         * Server only declares support for SHA1/ECDSA, client signs with SHA1/RSA, but sends
//         * SHA1/ECDSA in the CertificateVerify. Since the client is actually tracking SHA1 over the
//         * handshake, and the claimed algorithm is in the CertificateRequest supported algorithms,
//         * we expect fatal alert to come from the server when it finds the claimed algorithm
//         * doesn't match the client certificate.
//         */
//        if (TlsUtils.isTLSv12(version))
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_VALID;
//            c.clientAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.rsa);
//            c.clientAuthSigAlgClaimed = new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa);
//            c.serverCertReqSigAlgs = TlsUtils.getDefaultECDSASignatureAlgorithms();
//            c.expectServerFatalAlert(AlertDescription.decrypt_error);
//
//            addTestCase(testSuite, c, prefix + "BadCertificateVerifySigAlgMismatch");
//        }
//
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
//            c.expectServerFatalAlert(AlertDescription.decrypt_error);
//
//            addTestCase(testSuite, c, prefix + "BadCertificateVerifySignature");
//        }
//
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
//            c.expectServerFatalAlert(AlertDescription.bad_certificate);
//
//            addTestCase(testSuite, c, prefix + "BadClientCertificate");
//        }
//
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientAuth = C.CLIENT_AUTH_NONE;
//            c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
//            c.expectServerFatalAlert(AlertDescription.handshake_failure);
//
//            addTestCase(testSuite, c, prefix + "BadMandatoryCertReqDeclined");
//        }
//
//        /*
//         * Server selects MD5/RSA for ServerKeyExchange signature, which is not in the default
//         * supported signature algorithms that the client sent. We expect fatal alert from the
//         * client when it verifies the selected algorithm against the supported algorithms.
//         */
//        if (TlsUtils.isTLSv12(version))
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.serverAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.md5, SignatureAlgorithm.rsa);
//            c.expectClientFatalAlert(AlertDescription.illegal_parameter);
//
//            addTestCase(testSuite, c, prefix + "BadServerKeyExchangeSigAlg");
//        }
//
//        /*
//         * Server selects MD5/RSA for ServerKeyExchange signature, which is not the default {sha1,rsa}
//         * implied by the absent signature_algorithms extension. We expect fatal alert from the
//         * client when it verifies the selected algorithm against the implicit default.
//         */
//        if (TlsUtils.isTLSv12(version))
//        {
//            TlsTestConfig c = createDTLSTestConfig(version);
//            c.clientSendSignatureAlgorithms = false;
//            c.serverAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.md5, SignatureAlgorithm.rsa);
//            c.expectClientFatalAlert(AlertDescription.illegal_parameter);
//
//            addTestCase(testSuite, c, prefix + "BadServerKeyExchangeSigAlg2");
//        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);

            addTestCase(testSuite, c, prefix + "GoodDefault");
        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.serverCertReq = C.SERVER_CERT_REQ_NONE;

            addTestCase(testSuite, c, prefix + "GoodNoCertReq");
        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_NONE;

            addTestCase(testSuite, c, prefix + "GoodOptionalCertReqDeclined");
        }
    }

    private static void addTestCase(TestSuite testSuite, TlsTestConfig config, String name)
    {
        testSuite.addTest(new DTLSTestCase(config, name));
    }

    private static TlsTestConfig createDTLSTestConfig(ProtocolVersion version)
    {
        TlsTestConfig c = new TlsTestConfig();
        c.clientMinimumVersion = ProtocolVersion.DTLSv10;
        c.clientOfferVersion = ProtocolVersion.DTLSv12;
        c.serverMaximumVersion = version;
        c.serverMinimumVersion = ProtocolVersion.DTLSv10;
        return c;
    }
}
