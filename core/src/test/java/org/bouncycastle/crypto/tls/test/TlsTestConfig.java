package org.bouncycastle.crypto.tls.test;

import org.bouncycastle.crypto.tls.ConnectionEnd;
import org.bouncycastle.crypto.tls.ProtocolVersion;

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
     * Configures the minimum protocol version the client will accept. If null, uses the library's default.
     */
    public ProtocolVersion clientMinimumVersion = null;

    /**
     * Configures the protocol version the client will offer. If null, uses the library's default.
     */
    public ProtocolVersion clientOfferVersion = null;

    /**
     * Configures whether the client will indicate version fallback via TLS_FALLBACK_SCSV.
     */
    public boolean clientFallback = false;

    /**
     * Configures whether the test server will send a certificate request.
     */
    public int serverCertReq = SERVER_CERT_REQ_OPTIONAL;

    /**
     * Configures the maximum protocol version the server will accept. If null, uses the library's default.
     */
    public ProtocolVersion serverMaximumVersion = null;

    /**
     * Configures the minimum protocol version the server will accept. If null, uses the library's default.
     */
    public ProtocolVersion serverMinimumVersion = null;

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
