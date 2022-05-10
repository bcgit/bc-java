package org.bouncycastle.tls.test;

import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsUtils;

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
//            c.clientFallback = true;
//            c.clientSupportedVersions = ProtocolVersion.DTLSv10.only();
//            c.expectServerFatalAlert(AlertDescription.inappropriate_fallback);
//
//            addTestCase(testSuite, c, "FallbackBad");
//        }

        {
            TlsTestConfig c = createDTLSTestConfig(ProtocolVersion.DTLSv12);
            c.clientSupportedVersions = ProtocolVersion.DTLSv10.only();

            addTestCase(testSuite, c, "FallbackNone");
        }
    }

    private static void addVersionTests(TestSuite testSuite, ProtocolVersion version)
    {
        String prefix = version.toString().replaceAll("[ \\.]", "") + "_";

        /*
         * Server only declares support for SHA256/ECDSA, client selects SHA256/RSA, so we expect fatal alert
         * from the client validation of the CertificateVerify algorithm.
         */
        if (TlsUtils.isTLSv12(version))
        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_VALID;
            c.clientAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
            c.serverCertReqSigAlgs = TlsUtils.vectorOfOne(
                new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa));
            c.expectClientFatalAlert(AlertDescription.internal_error);

            addTestCase(testSuite, c, prefix + "BadCertVerifySigAlgClient");
        }

        /*
         * Server only declares support for rsa_pss_rsae_sha256, client selects rsa_pss_rsae_sha256 but claims
         * ecdsa_secp256r1_sha256, so we expect fatal alert from the server validation of the
         * CertificateVerify algorithm.
         */
        if (TlsUtils.isTLSv12(version))
        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_VALID;
            c.clientAuthSigAlg = SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
            c.clientAuthSigAlgClaimed = SignatureScheme.getSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256);
            c.serverCertReqSigAlgs = TlsUtils.vectorOfOne(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
            c.serverCheckSigAlgOfClientCerts = false;
            c.expectServerFatalAlert(AlertDescription.illegal_parameter);

            addTestCase(testSuite, c, prefix + "BadCertVerifySigAlgServer1");
        }

        /*
         * Server declares support for rsa_pss_rsae_sha256 and ecdsa_secp256r1_sha256, client selects
         * rsa_pss_rsae_sha256 but claims ecdsa_secp256r1_sha256, so we expect fatal alert from the server
         * validation of the client certificate.
         */
        if (TlsUtils.isTLSv12(version))
        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_VALID;
            c.clientAuthSigAlg = SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
            c.clientAuthSigAlgClaimed = SignatureScheme.getSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256);
            c.serverCertReqSigAlgs = new Vector(2);
            c.serverCertReqSigAlgs.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
            c.serverCertReqSigAlgs.addElement(
                SignatureScheme.getSignatureAndHashAlgorithm(SignatureScheme.ecdsa_secp256r1_sha256));
            c.expectServerFatalAlert(AlertDescription.bad_certificate);

            addTestCase(testSuite, c, prefix + "BadCertVerifySigAlgServer2");
        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
            c.expectServerFatalAlert(AlertDescription.decrypt_error);

            addTestCase(testSuite, c, prefix + "BadCertVerifySignature");
        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
            c.expectServerFatalAlert(AlertDescription.bad_certificate);

            addTestCase(testSuite, c, prefix + "BadClientCertificate");
        }

        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientAuth = C.CLIENT_AUTH_NONE;
            c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
            c.expectServerFatalAlert(AlertDescription.handshake_failure);

            addTestCase(testSuite, c, prefix + "BadMandatoryCertReqDeclined");
        }

        /*
         * Server sends SHA-256/RSA certificate, which is not the default {sha1,rsa} implied by the
         * absent signature_algorithms extension. We expect fatal alert from the client when it
         * verifies the certificate's 'signatureAlgorithm' against the implicit default signature_algorithms.
         */
        if (TlsUtils.isTLSv12(version))
        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientSendSignatureAlgorithms = false;
            c.clientSendSignatureAlgorithmsCert = false;
            c.serverAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
            c.expectClientFatalAlert(AlertDescription.bad_certificate);

            addTestCase(testSuite, c, prefix + "BadServerCertSigAlg");
        }

        /*
         * Client declares support for SHA256/RSA, server selects SHA384/RSA, so we expect fatal alert from the
         * client validation of the ServerKeyExchange algorithm.
         */
        if (TlsUtils.isTLSv12(version))
        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientCHSigAlgs = TlsUtils.vectorOfOne(
                new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa));
            c.serverAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha384, SignatureAlgorithm.rsa);
            c.expectClientFatalAlert(AlertDescription.illegal_parameter);

            addTestCase(testSuite, c, prefix + "BadServerKeyExchangeSigAlg");
        }

        /*
         * Server selects SHA256/RSA for ServerKeyExchange signature, which is not the default {sha1,rsa} implied by
         * the absent signature_algorithms extension. We expect fatal alert from the client when it verifies the
         * selected algorithm against the implicit default.
         */
        if (TlsUtils.isTLSv12(version))
        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.clientCheckSigAlgOfServerCerts = false;
            c.clientSendSignatureAlgorithms = false;
            c.clientSendSignatureAlgorithmsCert = false;
            c.serverAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
            c.expectClientFatalAlert(AlertDescription.illegal_parameter);

            addTestCase(testSuite, c, prefix + "BadServerKeyExchangeSigAlg2");
        }

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

        /*
         * Server generates downgraded (RFC 8446) ServerHello. We expect fatal alert
         * (illegal_parameter) from the client.
         */
        if (!TlsUtils.isTLSv12(version))
        {
            TlsTestConfig c = createDTLSTestConfig(version);
            c.serverNegotiateVersion = version;
            c.serverSupportedVersions = ProtocolVersion.DTLSv12.downTo(version);
            c.expectClientFatalAlert(AlertDescription.illegal_parameter);

            addTestCase(testSuite, c, prefix + "BadDowngrade");
        }
    }

    private static void addTestCase(TestSuite testSuite, TlsTestConfig config, String name)
    {
        testSuite.addTest(new DTLSTestCase(config, name));
    }

    private static TlsTestConfig createDTLSTestConfig(ProtocolVersion serverMaxVersion)
    {
        TlsTestConfig c = new TlsTestConfig();
        c.clientSupportedVersions = ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10);
        c.serverSupportedVersions = serverMaxVersion.downTo(ProtocolVersion.DTLSv10);
        return c;
    }
}
