package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.crypto.prng.ThreadedSeedGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;

public class TlsClientProtocol extends TlsProtocol {

    private Hashtable clientExtensions;
    private TlsClientContextImpl tlsClientContext = null;
    private TlsClient tlsClient = null;
    private int[] offeredCipherSuites = null;
    private short[] offeredCompressionMethods = null;
    private TlsKeyExchange keyExchange = null;
    private TlsAuthentication authentication = null;
    private CertificateRequest certificateRequest = null;

    private static SecureRandom createSecureRandom() {
        /*
         * We use our threaded seed generator to generate a good random seed. If the user has a
         * better random seed, he should use the constructor with a SecureRandom.
         */
        ThreadedSeedGenerator tsg = new ThreadedSeedGenerator();
        SecureRandom random = new SecureRandom();

        /*
         * Hopefully, 20 bytes in fast mode are good enough.
         */
        random.setSeed(tsg.generateSeed(20, true));

        return random;
    }

    public TlsClientProtocol(InputStream is, OutputStream os) {
        this(is, os, createSecureRandom());
    }

    public TlsClientProtocol(InputStream is, OutputStream os, SecureRandom sr) {
        super(is, os, sr);
    }

    /**
     * Initiates a TLS handshake in the role of client
     * 
     * @param tlsClient
     * @throws IOException
     *             If handshake was not successful.
     */
    public void connect(TlsClient tlsClient) throws IOException {
        if (tlsClient == null) {
            throw new IllegalArgumentException("'tlsClient' cannot be null");
        }
        if (this.tlsClient != null) {
            throw new IllegalStateException("connect can only be called once");
        }

        this.tlsClient = tlsClient;

        this.securityParameters = new SecurityParameters();
        this.securityParameters.clientRandom = new byte[32];
        random.nextBytes(securityParameters.clientRandom);
        TlsUtils.writeGMTUnixTime(securityParameters.clientRandom, 0);

        this.tlsClientContext = new TlsClientContextImpl(random, securityParameters);
        this.tlsClient.init(tlsClientContext);
        this.rs.init(tlsClientContext);

        sendClientHelloMessage();
        this.connection_state = CS_CLIENT_HELLO;

        /*
         * We will now read data, until we have completed the handshake.
         */
        while (this.connection_state != CS_SERVER_FINISHED) {
            safeReadData();
        }

        enableApplicationData();
    }

    protected TlsContext getContext() {
        return tlsClientContext;
    }

    protected void processChangeCipherSpecMessage() throws IOException {
        /*
         * Check if we are in the correct connection state.
         */
        if (this.connection_state != CS_CLIENT_FINISHED) {
            this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
        }

        rs.receivedReadCipherSpec();

        this.connection_state = CS_SERVER_CHANGE_CIPHER_SPEC;
    }

    protected void processHandshakeMessage(short type, byte[] data) throws IOException {
        ByteArrayInputStream buf = new ByteArrayInputStream(data);

        switch (type) {
        case HandshakeType.certificate: {
            switch (this.connection_state) {
            case CS_SERVER_HELLO: {
                // Parse the Certificate message and send to cipher suite

                Certificate serverCertificate = Certificate.parse(buf);

                assertEmpty(buf);

                this.keyExchange.processServerCertificate(serverCertificate);

                this.authentication = tlsClient.getAuthentication();
                this.authentication.notifyServerCertificate(serverCertificate);

                break;
            }
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }

            this.connection_state = CS_SERVER_CERTIFICATE;
            break;
        }
        case HandshakeType.finished:
            switch (this.connection_state) {
            case CS_SERVER_CHANGE_CIPHER_SPEC:
                processFinishedMessage(buf);
                this.connection_state = CS_SERVER_FINISHED;
                break;
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            break;
        case HandshakeType.server_hello:
            switch (this.connection_state) {
            case CS_CLIENT_HELLO:
                /*
                 * Read the server hello message
                 */
                ProtocolVersion server_version = TlsUtils.readVersion(buf);

                // Check that this matches what the server is sending in the record layer
                if (!server_version.equals(rs.getDiscoveredPeerVersion())) {
                    this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
                }

                ProtocolVersion client_version = this.tlsClientContext.getClientVersion();

                // TODO[DTLS] This comparison needs to allow for DTLS (with decreasing minor version
                // numbers)
                if (server_version.getFullVersion() > client_version.getFullVersion()) {
                    this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
                }

                this.tlsClientContext.setServerVersion(server_version);
                this.tlsClient.notifyServerVersion(server_version);

                /*
                 * Read the server random
                 */
                securityParameters.serverRandom = new byte[32];
                TlsUtils.readFully(securityParameters.serverRandom, buf);

                byte[] sessionID = TlsUtils.readOpaque8(buf);
                if (sessionID.length > 32) {
                    this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
                }

                this.tlsClient.notifySessionID(sessionID);

                /*
                 * Find out which CipherSuite the server has chosen and check that it was one of the
                 * offered ones.
                 */
                int selectedCipherSuite = TlsUtils.readUint16(buf);
                if (!arrayContains(offeredCipherSuites, selectedCipherSuite)
                    || selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
                    this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
                }

                this.tlsClient.notifySelectedCipherSuite(selectedCipherSuite);

                /*
                 * Find out which CompressionMethod the server has chosen and check that it was one
                 * of the offered ones.
                 */
                short selectedCompressionMethod = TlsUtils.readUint8(buf);
                if (!arrayContains(offeredCompressionMethods, selectedCompressionMethod)) {
                    this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
                }

                this.tlsClient.notifySelectedCompressionMethod(selectedCompressionMethod);

                /*
                 * RFC3546 2.2 The extended server hello message format MAY be sent in place of the
                 * server hello message when the client has requested extended functionality via the
                 * extended client hello message specified in Section 2.1. ... Note that the
                 * extended server hello message is only sent in response to an extended client
                 * hello message. This prevents the possibility that the extended server hello
                 * message could "break" existing TLS 1.0 clients.
                 */

                /*
                 * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST
                 * ignore extensions appearing in the client hello, and send a server hello
                 * containing no extensions.
                 */

                // Integer -> byte[]
                Hashtable serverExtensions = new Hashtable();

                /*
                 * RFC 3546 2.2 Note that the extended server hello message is only sent in response
                 * to an extended client hello message. However, see RFC 5746 exception below. We
                 * always include the SCSV, so an Extended Server Hello is always allowed.
                 */
                if (buf.available() > 0) {
                    // Process extensions from extended server hello
                    byte[] extBytes = TlsUtils.readOpaque16(buf);

                    ByteArrayInputStream ext = new ByteArrayInputStream(extBytes);
                    while (ext.available() > 0) {
                        Integer extType = Integers.valueOf(TlsUtils.readUint16(ext));
                        byte[] extValue = TlsUtils.readOpaque16(ext);

                        /*
                         * RFC 5746 Note that sending a "renegotiation_info" extension in response
                         * to a ClientHello containing only the SCSV is an explicit exception to the
                         * prohibition in RFC 5246, Section 7.4.1.4, on the server sending
                         * unsolicited extensions and is only allowed because the client is
                         * signaling its willingness to receive the extension via the
                         * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. TLS implementations MUST continue
                         * to comply with Section 7.4.1.4 for all other extensions.
                         */

                        if (!extType.equals(EXT_RenegotiationInfo)
                            && clientExtensions.get(extType) == null) {
                            /*
                             * RFC 3546 2.3 Note that for all extension types (including those
                             * defined in future), the extension type MUST NOT appear in the
                             * extended server hello unless the same extension type appeared in the
                             * corresponding client hello. Thus clients MUST abort the handshake if
                             * they receive an extension type in the extended server hello that they
                             * did not request in the associated (extended) client hello.
                             */
                            this.failWithError(AlertLevel.fatal,
                                AlertDescription.unsupported_extension);
                        }

                        if (serverExtensions.containsKey(extType)) {
                            /*
                             * RFC 3546 2.3 Also note that when multiple extensions of different
                             * types are present in the extended client hello or the extended server
                             * hello, the extensions may appear in any order. There MUST NOT be more
                             * than one extension of the same type.
                             */
                            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
                        }

                        serverExtensions.put(extType, extValue);
                    }
                }

                assertEmpty(buf);

                /*
                 * RFC 5746 3.4. When a ServerHello is received, the client MUST check if it
                 * includes the "renegotiation_info" extension:
                 */
                {
                    boolean secure_negotiation = serverExtensions
                        .containsKey(EXT_RenegotiationInfo);

                    /*
                     * If the extension is present, set the secure_renegotiation flag to TRUE. The
                     * client MUST then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
                     * handshake_failure alert).
                     */
                    if (secure_negotiation) {
                        byte[] renegExtValue = (byte[]) serverExtensions.get(EXT_RenegotiationInfo);

                        if (!Arrays.constantTimeAreEqual(renegExtValue,
                            createRenegotiationInfo(emptybuf))) {
                            this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
                        }
                    }

                    tlsClient.notifySecureRenegotiation(secure_negotiation);
                }

                if (clientExtensions != null) {
                    tlsClient.processServerExtensions(serverExtensions);
                }

                this.keyExchange = tlsClient.getKeyExchange();

                this.connection_state = CS_SERVER_HELLO;
                break;
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            break;
        case HandshakeType.server_hello_done:
            switch (this.connection_state) {
            case CS_SERVER_HELLO:

                // There was no server certificate message; check it's OK
                this.keyExchange.skipServerCertificate();
                this.authentication = null;

                // NB: Fall through to next case label

            case CS_SERVER_CERTIFICATE:

                // There was no server key exchange message; check it's OK
                this.keyExchange.skipServerKeyExchange();

                // NB: Fall through to next case label

            case CS_SERVER_KEY_EXCHANGE:
            case CS_CERTIFICATE_REQUEST:

                assertEmpty(buf);

                this.connection_state = CS_SERVER_HELLO_DONE;

                TlsCredentials clientCreds = null;
                if (certificateRequest == null) {
                    this.keyExchange.skipClientCredentials();
                } else {
                    clientCreds = this.authentication.getClientCredentials(certificateRequest);

                    if (clientCreds == null) {
                        this.keyExchange.skipClientCredentials();

                        if (tlsClientContext.getServerVersion().isSSL()) {
                            sendAlert(AlertLevel.warning, AlertDescription.no_certificate);
                        } else {
                            sendCertificateMessage(Certificate.EMPTY_CHAIN);
                        }
                    } else {
                        this.keyExchange.processClientCredentials(clientCreds);

                        sendCertificateMessage(clientCreds.getCertificate());
                    }
                }

                this.connection_state = CS_CLIENT_CERTIFICATE;

                /*
                 * Send the client key exchange message, depending on the key exchange we are using
                 * in our CipherSuite.
                 */
                sendClientKeyExchangeMessage();

                this.connection_state = CS_CLIENT_KEY_EXCHANGE;

                /*
                 * Calculate the master_secret
                 */
                {
                    byte[] pms = this.keyExchange.generatePremasterSecret();

                    try {
                        securityParameters.masterSecret = TlsUtils.calculateMasterSecret(
                            this.tlsClientContext, pms);
                    } finally {
                        // TODO Is there a way to ensure the data is really overwritten?
                        /*
                         * RFC 2246 8.1. The pre_master_secret should be deleted from memory once
                         * the master_secret has been computed.
                         */
                        if (pms != null) {
                            Arrays.fill(pms, (byte) 0);
                        }
                    }
                }

                if (clientCreds != null && clientCreds instanceof TlsSignerCredentials) {
                    TlsSignerCredentials signerCreds = (TlsSignerCredentials) clientCreds;
                    byte[] md5andsha1 = rs.getCurrentHash(null);
                    byte[] clientCertificateSignature = signerCreds
                        .generateCertificateSignature(md5andsha1);
                    sendCertificateVerifyMessage(clientCertificateSignature);

                    this.connection_state = CS_CERTIFICATE_VERIFY;
                }

                sendChangeCipherSpecMessage();
                this.connection_state = CS_CLIENT_CHANGE_CIPHER_SPEC;

                /*
                 * Initialize our cipher suite
                 */
                rs.decidedWriteCipherSpec(tlsClient.getCompression(), tlsClient.getCipher());

                sendFinishedMessage();
                this.connection_state = CS_CLIENT_FINISHED;
                break;
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
            }
            break;
        case HandshakeType.server_key_exchange: {
            switch (this.connection_state) {
            case CS_SERVER_HELLO:

                // There was no server certificate message; check it's OK
                this.keyExchange.skipServerCertificate();
                this.authentication = null;

                // NB: Fall through to next case label

            case CS_SERVER_CERTIFICATE:

                this.keyExchange.processServerKeyExchange(buf);

                assertEmpty(buf);
                break;

            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }

            this.connection_state = CS_SERVER_KEY_EXCHANGE;
            break;
        }
        case HandshakeType.certificate_request: {
            switch (this.connection_state) {
            case CS_SERVER_CERTIFICATE:

                // There was no server key exchange message; check it's OK
                this.keyExchange.skipServerKeyExchange();

                // NB: Fall through to next case label

            case CS_SERVER_KEY_EXCHANGE: {
                if (this.authentication == null) {
                    /*
                     * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server
                     * to request client identification.
                     */
                    this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
                }

                this.certificateRequest = CertificateRequest.parse(buf);

                assertEmpty(buf);

                this.keyExchange.validateCertificateRequest(this.certificateRequest);

                break;
            }
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }

            this.connection_state = CS_CERTIFICATE_REQUEST;
            break;
        }
        case HandshakeType.hello_request:
            /*
             * RFC 2246 7.4.1.1 Hello request This message will be ignored by the client if the
             * client is currently negotiating a session. This message may be ignored by the client
             * if it does not wish to renegotiate a session, or the client may, if it wishes,
             * respond with a no_renegotiation alert.
             */
            if (this.connection_state == CS_SERVER_FINISHED) {
                // Renegotiation not supported yet
                sendAlert(AlertLevel.warning, AlertDescription.no_renegotiation);
            }
            break;
        case HandshakeType.client_key_exchange:
        case HandshakeType.certificate_verify:
        case HandshakeType.client_hello:
        case HandshakeType.hello_verify_request:
        default:
            // We do not support this!
            this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            break;
        }
    }

    protected void sendCertificateVerifyMessage(byte[] data) throws IOException {
        /*
         * Send signature of handshake messages so far to prove we are the owner of the cert See RFC
         * 2246 sections 4.7, 7.4.3 and 7.4.8
         */
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HandshakeType.certificate_verify, bos);
        TlsUtils.writeUint24(data.length + 2, bos);
        TlsUtils.writeOpaque16(data, bos);
        byte[] message = bos.toByteArray();

        safeWriteMessage(ContentType.handshake, message, 0, message.length);
    }

    protected void sendClientHelloMessage() throws IOException {

        ByteArrayOutputStream os = new ByteArrayOutputStream();

        ProtocolVersion client_version = this.tlsClient.getClientVersion();
        this.tlsClientContext.setClientVersion(client_version);
        TlsUtils.writeVersion(client_version, os);

        os.write(securityParameters.clientRandom);

        /*
         * Length of Session id
         */
        TlsUtils.writeUint8((short) 0, os);

        /*
         * Cipher suites
         */
        this.offeredCipherSuites = this.tlsClient.getCipherSuites();

        // Integer -> byte[]
        this.clientExtensions = this.tlsClient.getClientExtensions();

        // Cipher Suites (and SCSV)
        {
            /*
             * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
             * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
             * ClientHello. Including both is NOT RECOMMENDED.
             */
            boolean noRenegExt = clientExtensions == null
                || clientExtensions.get(EXT_RenegotiationInfo) == null;

            int count = offeredCipherSuites.length;
            if (noRenegExt) {
                // Note: 1 extra slot for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                ++count;
            }

            TlsUtils.writeUint16(2 * count, os);
            TlsUtils.writeUint16Array(offeredCipherSuites, os);

            if (noRenegExt) {
                TlsUtils.writeUint16(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV, os);
            }
        }

        // Compression methods
        this.offeredCompressionMethods = this.tlsClient.getCompressionMethods();

        TlsUtils.writeUint8((short) offeredCompressionMethods.length, os);
        TlsUtils.writeUint8Array(offeredCompressionMethods, os);

        // Extensions
        if (clientExtensions != null) {
            ByteArrayOutputStream ext = new ByteArrayOutputStream();

            Enumeration keys = clientExtensions.keys();
            while (keys.hasMoreElements()) {
                Integer extType = (Integer) keys.nextElement();
                writeExtension(ext, extType, (byte[]) clientExtensions.get(extType));
            }

            TlsUtils.writeOpaque16(ext.toByteArray(), os);
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HandshakeType.client_hello, bos);
        TlsUtils.writeUint24(os.size(), bos);
        bos.write(os.toByteArray());
        byte[] message = bos.toByteArray();

        safeWriteMessage(ContentType.handshake, message, 0, message.length);
    }

    protected void sendClientKeyExchangeMessage() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        TlsUtils.writeUint8(HandshakeType.client_key_exchange, bos);

        // Reserve space for length
        TlsUtils.writeUint24(0, bos);

        this.keyExchange.generateClientKeyExchange(bos);
        byte[] message = bos.toByteArray();

        // Patch actual length back in
        TlsUtils.writeUint24(message.length - 4, message, 1);

        safeWriteMessage(ContentType.handshake, message, 0, message.length);
    }
}
