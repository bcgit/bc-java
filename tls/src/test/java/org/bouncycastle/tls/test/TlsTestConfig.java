package org.bouncycastle.tls.test;

import java.util.Vector;

import org.bouncycastle.tls.ConnectionEnd;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsPeer;

public class TlsTestConfig
{
    public static final boolean DEBUG = false;

    /**
     * Client does not authenticate, ignores any certificate request
     */
    public static final int CLIENT_AUTH_NONE = 0;

    /**
     * Client will authenticate if it receives a certificate request
     */
    public static final int CLIENT_AUTH_VALID = 1;

    /**
     * Client will authenticate if it receives a certificate request, with an invalid certificate
     */
    public static final int CLIENT_AUTH_INVALID_CERT = 2;

    /**
     * Client will authenticate if it receives a certificate request, with an invalid CertificateVerify signature
     */
    public static final int CLIENT_AUTH_INVALID_VERIFY = 3;

    public static final int CRYPTO_BC = 0;

    public static final int CRYPTO_JCA = 1;

    /**
     * Server will not request a client certificate
     */
    public static final int SERVER_CERT_REQ_NONE = 0;

    /**
     * Server will request a client certificate but receiving one is optional
     */
    public static final int SERVER_CERT_REQ_OPTIONAL = 1;

    /**
     * Server will request a client certificate and receiving one is mandatory
     */
    public static final int SERVER_CERT_REQ_MANDATORY = 2;

    /**
     * Configures the client authentication behaviour of the test client. Use CLIENT_AUTH_* constants.
     */
    public int clientAuth = CLIENT_AUTH_VALID;

    /**
     * If not null, and TLS 1.2 or higher is negotiated, selects a fixed signature/hash algorithm to
     * be used for the CertificateVerify signature (if one is sent).
     */
    public SignatureAndHashAlgorithm clientAuthSigAlg = null;

    /**
     * If not null, and TLS 1.2 or higher is negotiated, selects a fixed signature/hash algorithm to
     * be _claimed_ in the CertificateVerify (if one is sent), independently of what was actually used.
     */
    public SignatureAndHashAlgorithm clientAuthSigAlgClaimed = null;

    /**
     * Control the result the client will return from {@link TlsPeer#shouldCheckSigAlgOfPeerCerts()}.
     */
    public boolean clientCheckSigAlgOfServerCerts = true;

    public int clientCrypto = CRYPTO_BC;

    /**
     * Configures whether the client will send an empty key_share extension in initial ClientHello.
     */
    public boolean clientEmptyKeyShare = false;

    /**
     * Configures whether the client will indicate version fallback via TLS_FALLBACK_SCSV.
     */
    public boolean clientFallback = false;

    /**
     * Configures whether a (TLS 1.2+) client may send the signature_algorithms extension in ClientHello.
     */
    public boolean clientSendSignatureAlgorithms = true;

    /**
     * Configures whether a (TLS 1.2+) client may send the signature_algorithms_cert extension in ClientHello.
     */
    public boolean clientSendSignatureAlgorithmsCert = true;

    /**
     * Configures the supported protocol versions for the client. If null, uses the library's default.
     */
    public ProtocolVersion[] clientSupportedVersions = null;

    /**
     * If not null, and TLS 1.2 or higher is negotiated, selects a fixed signature/hash algorithm to
     * be used for the ServerKeyExchange signature (if one is sent).
     */
    public SignatureAndHashAlgorithm serverAuthSigAlg = null;

    /**
     * Configures whether the test server will send a certificate request.
     */
    public int serverCertReq = SERVER_CERT_REQ_OPTIONAL;

    /**
     * If TLS 1.2 or higher is negotiated, configures the set of supported signature algorithms in the
     * CertificateRequest (if one is sent). If null, uses a default set.
     */
    public Vector serverCertReqSigAlgs = null;

    /**
     * Control the result the server will return from {@link TlsPeer#shouldCheckSigAlgOfPeerCerts()}.
     */
    public boolean serverCheckSigAlgOfClientCerts = true;

    public int serverCrypto = CRYPTO_BC;

    /**
     * Configures a protocol version the server will unconditionally negotiate. Ignored if null.
     */
    public ProtocolVersion serverNegotiateVersion = null;

    /**
     * Configures the supported protocol versions for the server. If null, uses the library's default.
     */
    public ProtocolVersion[] serverSupportedVersions = null;

    /**
     * Configures the connection end that a fatal alert is expected to be raised. Use ConnectionEnd.* constants.
     */
    public int expectFatalAlertConnectionEnd = -1;

    /**
     * Configures the type of fatal alert expected to be raised. Use AlertDescription.* constants.
     */
    public short expectFatalAlertDescription = -1;

    public void expectClientFatalAlert(short alertDescription)
    {
        this.expectFatalAlertConnectionEnd = ConnectionEnd.client;
        this.expectFatalAlertDescription = alertDescription;
    }

    public void expectServerFatalAlert(short alertDescription)
    {
        this.expectFatalAlertConnectionEnd = ConnectionEnd.server;
        this.expectFatalAlertDescription = alertDescription;
    }
}
