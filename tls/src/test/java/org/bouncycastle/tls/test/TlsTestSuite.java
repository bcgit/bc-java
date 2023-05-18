package org.bouncycastle.tls.test;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Vector;

import junit.framework.Test;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

public class TlsTestSuite extends TestSuite
{
    static TlsCrypto BC_CRYPTO = new BcTlsCrypto(); 
    static TlsCrypto JCA_CRYPTO = new JcaTlsCryptoProvider().setProvider(new BouncyCastleProvider()).create(new SecureRandom());

    static TlsCrypto getCrypto(TlsTestConfig config)
    {
        switch (config.clientCrypto)
        {
        case TlsTestConfig.CRYPTO_JCA:
            return JCA_CRYPTO;
        case TlsTestConfig.CRYPTO_BC:
        default:
            return BC_CRYPTO;
        }
    }

    // Make the access to constants less verbose 
    static abstract class C extends TlsTestConfig {}

    public TlsTestSuite()
    {
        super("TLS");
    }

    public static Test suite()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        else
        {
            // remove the old one.
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);

            // make sure BC provider is at the end
            Security.addProvider(new BouncyCastleProvider());
        }

        TlsTestSuite testSuite = new TlsTestSuite();
        addAllTests(testSuite, TlsTestConfig.CRYPTO_BC, TlsTestConfig.CRYPTO_BC);
        addAllTests(testSuite, TlsTestConfig.CRYPTO_JCA, TlsTestConfig.CRYPTO_BC);
        addAllTests(testSuite, TlsTestConfig.CRYPTO_BC, TlsTestConfig.CRYPTO_JCA);
        addAllTests(testSuite, TlsTestConfig.CRYPTO_JCA, TlsTestConfig.CRYPTO_JCA);
        return testSuite;
    }

    private static void addAllTests(TestSuite testSuite, int clientCrypto, int serverCrypto)
    {
        addFallbackTests(testSuite, clientCrypto, serverCrypto);
        addVersionTests(testSuite, ProtocolVersion.SSLv3, clientCrypto, serverCrypto);
        addVersionTests(testSuite, ProtocolVersion.TLSv10, clientCrypto, serverCrypto);
        addVersionTests(testSuite, ProtocolVersion.TLSv11, clientCrypto, serverCrypto);
        addVersionTests(testSuite, ProtocolVersion.TLSv12, clientCrypto, serverCrypto);
        addVersionTests(testSuite, ProtocolVersion.TLSv13, clientCrypto, serverCrypto);
    }

    private static void addFallbackTests(TestSuite testSuite, int clientCrypto, int serverCrypto)
    {
        String prefix = getCryptoName(clientCrypto) + "_" + getCryptoName(serverCrypto) + "_";

        {
            TlsTestConfig c = createTlsTestConfig(ProtocolVersion.TLSv12, clientCrypto, serverCrypto);
            c.clientFallback = true;

            addTestCase(testSuite, c, prefix + "FallbackGood");
        }

        {
            TlsTestConfig c = createTlsTestConfig(ProtocolVersion.TLSv12, clientCrypto, serverCrypto);
            c.clientFallback = true;
            c.clientSupportedVersions = ProtocolVersion.TLSv11.downTo(ProtocolVersion.TLSv10);
            c.expectServerFatalAlert(AlertDescription.inappropriate_fallback);

            addTestCase(testSuite, c, prefix + "FallbackBad");
        }

        {
            TlsTestConfig c = createTlsTestConfig(ProtocolVersion.TLSv12, clientCrypto, serverCrypto);
            c.clientSupportedVersions = ProtocolVersion.TLSv11.downTo(ProtocolVersion.TLSv10);

            addTestCase(testSuite, c, prefix + "FallbackNone");
        }
    }

    private static void addVersionTests(TestSuite testSuite, ProtocolVersion version, int clientCrypto, int serverCrypto)
    {
        String prefix = getCryptoName(clientCrypto) + "_" + getCryptoName(serverCrypto) + "_"
            + version.toString().replaceAll("[ \\.]", "") + "_";

        final boolean isTLSv12 = TlsUtils.isTLSv12(version);
        final boolean isTLSv13 = TlsUtils.isTLSv13(version);
        final boolean isTLSv12Exactly = isTLSv12 && !isTLSv13;

        final short certReqDeclinedAlert = TlsUtils.isTLSv13(version)
            ?   AlertDescription.certificate_required
            :   AlertDescription.handshake_failure;

        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);

            addTestCase(testSuite, c, prefix + "GoodDefault");
        }

        if (isTLSv13)
        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
            c.clientEmptyKeyShare = true;

            addTestCase(testSuite, c, prefix + "GoodEmptyKeyShare");
        }

        /*
         * Server only declares support for SHA256/ECDSA, client selects SHA256/RSA, so we expect fatal alert
         * from the client validation of the CertificateVerify algorithm.
         */
        if (isTLSv12Exactly)
        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
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
        if (isTLSv12)
        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
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
        if (isTLSv12)
        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
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
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
            c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
            c.expectServerFatalAlert(AlertDescription.decrypt_error);

            addTestCase(testSuite, c, prefix + "BadCertVerifySignature");
        }

        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
            c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
            c.expectServerFatalAlert(AlertDescription.bad_certificate);

            addTestCase(testSuite, c, prefix + "BadClientCertificate");
        }

        if (isTLSv13)
        {
            /*
             * For TLS 1.3 the supported_algorithms extension is required in ClientHello when the
             * server authenticates via a certificate.
             */
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
            c.clientSendSignatureAlgorithms = false;
            c.clientSendSignatureAlgorithmsCert = false;
            c.expectServerFatalAlert(AlertDescription.missing_extension);

            addTestCase(testSuite, c, prefix + "BadClientSigAlgs");
        }

        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
            c.clientAuth = C.CLIENT_AUTH_NONE;
            c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
            c.expectServerFatalAlert(certReqDeclinedAlert);

            addTestCase(testSuite, c, prefix + "BadMandatoryCertReqDeclined");
        }

        /*
         * Server sends SHA-256/RSA certificate, which is not the default {sha1,rsa} implied by the
         * absent signature_algorithms extension. We expect fatal alert from the client when it
         * verifies the certificate's 'signatureAlgorithm' against the implicit default signature_algorithms.
         */
        if (isTLSv12Exactly)
        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
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
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
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
        if (isTLSv12Exactly)
        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
            c.clientCheckSigAlgOfServerCerts = false;
            c.clientSendSignatureAlgorithms = false;
            c.clientSendSignatureAlgorithmsCert = false;
            c.serverAuthSigAlg = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);
            c.expectClientFatalAlert(AlertDescription.illegal_parameter);

            addTestCase(testSuite, c, prefix + "BadServerKeyExchangeSigAlg2");
        }

        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
            c.serverCertReq = C.SERVER_CERT_REQ_NONE;

            addTestCase(testSuite, c, prefix + "GoodNoCertReq");
        }

        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
            c.clientAuth = C.CLIENT_AUTH_NONE;

            addTestCase(testSuite, c, prefix + "GoodOptionalCertReqDeclined");
        }

        /*
         * Server generates downgraded (RFC 8446) 1.1 ServerHello. We expect fatal alert
         * (illegal_parameter) from the client.
         */
        if (!isTLSv13)
        {
            TlsTestConfig c = createTlsTestConfig(version, clientCrypto, serverCrypto);
            c.serverNegotiateVersion = version;
            c.serverSupportedVersions = ProtocolVersion.TLSv13.downTo(version);
            c.expectClientFatalAlert(AlertDescription.illegal_parameter);

            addTestCase(testSuite, c, prefix + "BadDowngrade");
        }
    }

    private static void addTestCase(TestSuite testSuite, TlsTestConfig config, String name)
    {
        testSuite.addTest(new TlsTestCase(config, name));
    }

    private static TlsTestConfig createTlsTestConfig(ProtocolVersion serverMaxVersion, int clientCrypto, int serverCrypto)
    {
        TlsTestConfig c = new TlsTestConfig();
        c.clientCrypto = clientCrypto;
        c.clientSupportedVersions = ProtocolVersion.TLSv13.downTo(ProtocolVersion.SSLv3);
        c.serverCrypto = serverCrypto;
        c.serverSupportedVersions = serverMaxVersion.downTo(ProtocolVersion.SSLv3);
        return c;
    }

    private static String getCryptoName(int crypto)
    {
        switch (crypto)
        {
        case TlsTestConfig.CRYPTO_JCA:
            return "JCA";
        case TlsTestConfig.CRYPTO_BC:
        default:
            return "BC";
        }
    }
}
