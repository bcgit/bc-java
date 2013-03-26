package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.util.Arrays;

public class TlsServerProtocol extends TlsProtocol {

    protected TlsServer tlsServer = null;
    protected TlsServerContextImpl tlsServerContext = null;

    protected int selectedCipherSuite = -1;
    protected short selectedCompressionMethod = -1;
    protected Hashtable serverExtensions = null;
    protected TlsKeyExchange keyExchange = null;
    protected CertificateRequest certificateRequest = null;

    public TlsServerProtocol(InputStream is, OutputStream os, SecureRandom sr) {
        super(is, os, sr);
    }

    /**
     * Receives a TLS handshake in the role of server
     * 
     * @param tlsServer
     * @throws IOException
     *             If handshake was not successful.
     */
    public void accept(TlsServer tlsServer) throws IOException {

        if (tlsServer == null) {
            throw new IllegalArgumentException("'tlsServer' cannot be null");
        }
        if (this.tlsServer != null) {
            throw new IllegalStateException("accept can only be called once");
        }

        this.tlsServer = tlsServer;

        this.securityParameters = new SecurityParameters();
        this.securityParameters.serverRandom = createRandomBlock(secureRandom);
        this.tlsServerContext = new TlsServerContextImpl(secureRandom, securityParameters);
        this.tlsServer.init(tlsServerContext);
        this.recordStream.init(tlsServerContext);

        this.recordStream.setRestrictReadVersion(false);

        completeHandshake();
    }

    protected TlsContext getContext() {
        return tlsServerContext;
    }

    protected void handleChangeCipherSpecMessage() throws IOException {

        switch (this.connection_state) {
        case CS_CLIENT_KEY_EXCHANGE: {
            // TODO Check whether the client Certificate has signing capability
            skipCertificateVerifyMessage();
            // NB: Fall through to next case label
        }
        case CS_CERTIFICATE_VERIFY: {
            this.connection_state = CS_CLIENT_CHANGE_CIPHER_SPEC;
            break;
        }
        default: {
            this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
        }
        }
    }

    protected void handleHandshakeMessage(short type, byte[] data) throws IOException {

        ByteArrayInputStream buf = new ByteArrayInputStream(data);

        switch (type) {
        case HandshakeType.client_hello: {
            switch (this.connection_state) {
            case CS_START: {
                receiveClientHelloMessage(buf);
                this.connection_state = CS_CLIENT_HELLO;

                sendServerHelloMessage();
                this.connection_state = CS_SERVER_HELLO;

                Vector serverSupplementalData = tlsServer.getServerSupplementalData();
                if (serverSupplementalData != null) {
                    sendSupplementalDataMessage(serverSupplementalData);
                }
                this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;

                this.keyExchange = tlsServer.getKeyExchange();
                this.keyExchange.init(this.tlsServerContext);

                TlsCredentials serverCredentials = tlsServer.getCredentials();
                if (serverCredentials == null) {
                    this.keyExchange.skipServerCredentials();
                } else {
                    this.keyExchange.processServerCredentials(serverCredentials);
                    sendCertificateMessage(serverCredentials.getCertificate());
                }
                this.connection_state = CS_SERVER_CERTIFICATE;

                byte[] serverKeyExchange = this.keyExchange.generateServerKeyExchange();
                if (serverKeyExchange != null) {
                    sendServerKeyExchangeMessage(serverKeyExchange);
                }
                this.connection_state = CS_SERVER_KEY_EXCHANGE;

                if (serverCredentials != null) {
                    this.certificateRequest = tlsServer.getCertificateRequest();
                    if (this.certificateRequest != null) {
                        this.keyExchange.validateCertificateRequest(certificateRequest);
                        sendCertificateRequestMessage(certificateRequest);
                    }
                }
                this.connection_state = CS_CERTIFICATE_REQUEST;

                sendServerHelloDoneMessage();
                this.connection_state = CS_SERVER_HELLO_DONE;

                break;
            }
            default: {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            }
            break;
        }
        case HandshakeType.supplemental_data: {
            switch (this.connection_state) {
            case CS_SERVER_HELLO_DONE: {
                tlsServer.processClientSupplementalData(readSupplementalDataMessage(buf));
                this.connection_state = CS_CLIENT_SUPPLEMENTAL_DATA;
                break;
            }
            default: {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            }
            break;
        }
        case HandshakeType.certificate: {
            switch (this.connection_state) {
            case CS_SERVER_HELLO_DONE: {
                tlsServer.processClientSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_CLIENT_SUPPLEMENTAL_DATA: {
                if (this.certificateRequest == null) {
                    this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
                }
                receiveCertificateMessage(buf);
                this.connection_state = CS_CLIENT_CERTIFICATE;
                break;
            }
            default: {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            }
            break;
        }
        case HandshakeType.client_key_exchange: {
            switch (this.connection_state) {
            case CS_SERVER_HELLO_DONE: {
                tlsServer.processClientSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_CLIENT_SUPPLEMENTAL_DATA: {
                this.keyExchange.skipClientCredentials();
                // NB: Fall through to next case label
            }
            case CS_CLIENT_CERTIFICATE: {
                receiveClientKeyExchangeMessage(buf);
                this.connection_state = CS_CLIENT_KEY_EXCHANGE;
                break;
            }
            default: {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            }
            break;
        }
        case HandshakeType.certificate_verify: {
            switch (this.connection_state) {
            case CS_CLIENT_KEY_EXCHANGE: {
                // TODO Check whether the client Certificate has signing capability
                receiveCertificateVerifyMessage(buf);
                this.connection_state = CS_CERTIFICATE_VERIFY;
                break;
            }
            default: {
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            }
            break;
        }
        case HandshakeType.finished: {
            switch (this.connection_state) {
            case CS_CLIENT_CHANGE_CIPHER_SPEC:
                processFinishedMessage(buf);
                this.connection_state = CS_CLIENT_FINISHED;

                sendChangeCipherSpecMessage();
                this.connection_state = CS_SERVER_CHANGE_CIPHER_SPEC;

                sendFinishedMessage();
                this.connection_state = CS_SERVER_FINISHED;
                break;
            default:
                this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.hello_request:
        case HandshakeType.hello_verify_request:
        case HandshakeType.server_hello:
        case HandshakeType.server_key_exchange:
        case HandshakeType.certificate_request:
        case HandshakeType.server_hello_done:
        case HandshakeType.session_ticket:
        default:
            // We do not support this!
            this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            break;
        }
    }

    protected void handleWarningMessage(short description) {
        switch (description) {
        case AlertDescription.no_certificate: {
            if (tlsServerContext.getServerVersion().isSSL()) {
                // TODO In SSLv3, this is an alternative to client Certificate message
            }
            break;
        }
        default: {
            super.handleWarningMessage(description);
        }
        }
    }

    protected void receiveCertificateMessage(ByteArrayInputStream buf) throws IOException {

        Certificate clientCertificate = Certificate.parse(buf);

        assertEmpty(buf);

        this.keyExchange.processClientCertificate(clientCertificate);
    }

    protected void receiveCertificateVerifyMessage(ByteArrayInputStream buf) throws IOException {
        // TODO

        assertEmpty(buf);
    }

    protected void receiveClientHelloMessage(ByteArrayInputStream buf) throws IOException {

        ProtocolVersion client_version = TlsUtils.readVersion(buf);
        if (client_version.isDTLS()) {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        /*
         * Read the client random
         */
        byte[] random = new byte[32];
        TlsUtils.readFully(random, buf);

        byte[] sessionID = TlsUtils.readOpaque8(buf);
        if (sessionID.length > 32) {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        int cipher_suites_length = TlsUtils.readUint16(buf);
        if (cipher_suites_length < 2 || (cipher_suites_length & 1) != 0) {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        /*
         * NOTE: "If the session_id field is not empty (implying a session resumption request) this
         * vector must include at least the cipher_suite from that session."
         */
        int[] cipher_suites = TlsUtils.readUint16Array(cipher_suites_length / 2, buf);

        int compression_methods_length = TlsUtils.readUint8(buf);
        if (cipher_suites_length < 1) {
            this.failWithError(AlertLevel.fatal, AlertDescription.illegal_parameter);
        }

        short[] compression_methods = TlsUtils.readUint8Array(compression_methods_length, buf);

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        Hashtable clientExtensions = readExtensions(buf);

        /*
         * TODO RFC 5746 3.4. The client MUST include either an empty "renegotiation_info"
         * extension, or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
         * ClientHello. Including both is NOT RECOMMENDED.
         */

        tlsServerContext.setClientVersion(client_version);

        ProtocolVersion server_version = tlsServer.selectVersion(client_version);
        if (!server_version.isEqualOrEarlierVersionOf(client_version)) {
            this.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
        }

        recordStream.setReadVersion(server_version);
        recordStream.setWriteVersion(server_version);
        recordStream.setRestrictReadVersion(true);
        tlsServerContext.setServerVersion(server_version);

        securityParameters.clientRandom = random;

        this.selectedCipherSuite = tlsServer.selectCipherSuite(cipher_suites);
        if (!arrayContains(cipher_suites, this.selectedCipherSuite)
            || selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
            this.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
        }

        this.selectedCompressionMethod = tlsServer.selectCompressionMethod(compression_methods);
        if (!arrayContains(compression_methods, this.selectedCompressionMethod)) {
            this.failWithError(AlertLevel.fatal, AlertDescription.internal_error);
        }

        /*
         * RFC 5746 3.6. Server Behavior: Initial Handshake
         */
        {
            /*
             * When a ClientHello is received, the server MUST check if it includes the
             * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. If it does, set the secure_renegotiation flag
             * to TRUE.
             */
            if (arrayContains(cipher_suites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)) {
                this.secure_renegotiation = true;
            }

            /*
             * The server MUST check if the "renegotiation_info" extension is included in the
             * ClientHello.
             */
            if (clientExtensions != null) {
                byte[] renegExtValue = (byte[]) clientExtensions.get(EXT_RenegotiationInfo);
                if (renegExtValue != null) {
                    /*
                     * If the extension is present, set secure_renegotiation flag to TRUE. The
                     * server MUST then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, MUST abort the handshake.
                     */
                    this.secure_renegotiation = true;

                    if (!Arrays.constantTimeAreEqual(renegExtValue,
                        createRenegotiationInfo(emptybuf))) {
                        this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
                    }
                }
            }
        }

        tlsServer.notifySecureRenegotiation(this.secure_renegotiation);

        if (clientExtensions != null) {
            this.serverExtensions = tlsServer.processClientExtensions(clientExtensions);
        }
    }

    protected void receiveClientKeyExchangeMessage(ByteArrayInputStream buf) throws IOException {

        this.keyExchange.processClientKeyExchange(buf);

        assertEmpty(buf);

        establishMasterSecret(tlsServerContext, keyExchange);

        /*
         * Initialize our cipher suite
         */
        recordStream.setPendingConnectionState(tlsServer.getCompression(), tlsServer.getCipher());
    }

    protected void sendCertificateRequestMessage(CertificateRequest certificateRequest)
        throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HandshakeType.certificate_request, buf);

        // Reserve space for length
        TlsUtils.writeUint24(0, buf);

        certificateRequest.encode(buf);
        byte[] message = buf.toByteArray();

        // Patch actual length back in
        TlsUtils.writeUint24(message.length - 4, message, 1);

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected void sendServerHelloMessage() throws IOException {

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        TlsUtils.writeUint8(HandshakeType.server_hello, buf);

        // Reserve space for length
        TlsUtils.writeUint24(0, buf);

        TlsUtils.writeVersion(this.tlsServerContext.getServerVersion(), buf);

        buf.write(this.securityParameters.serverRandom);

        /*
         * The server may return an empty session_id to indicate that the session will not be cached
         * and therefore cannot be resumed.
         */
        TlsUtils.writeUint8((short) 0, buf);

        TlsUtils.writeUint16(this.selectedCipherSuite, buf);
        TlsUtils.writeUint8(this.selectedCompressionMethod, buf);

        /*
         * RFC 5746 3.6. Server Behavior: Initial Handshake
         */
        if (this.secure_renegotiation) {

            boolean noRenegExt = this.serverExtensions == null
                || !this.serverExtensions.containsKey(EXT_RenegotiationInfo);

            if (noRenegExt) {
                /*
                 * Note that sending a "renegotiation_info" extension in response to a ClientHello
                 * containing only the SCSV is an explicit exception to the prohibition in RFC 5246,
                 * Section 7.4.1.4, on the server sending unsolicited extensions and is only allowed
                 * because the client is signaling its willingness to receive the extension via the
                 * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                 */
                if (this.serverExtensions == null) {
                    this.serverExtensions = new Hashtable();
                }

                /*
                 * If the secure_renegotiation flag is set to TRUE, the server MUST include an empty
                 * "renegotiation_info" extension in the ServerHello message.
                 */
                this.serverExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(emptybuf));
            }
        }

        if (this.serverExtensions != null) {
            writeExtensions(buf, this.serverExtensions);
        }

        byte[] message = buf.toByteArray();

        // Patch actual length back in
        TlsUtils.writeUint24(message.length - 4, message, 1);

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected void sendServerHelloDoneMessage() throws IOException {

        byte[] message = new byte[4];
        TlsUtils.writeUint8(HandshakeType.server_hello_done, message, 0);
        TlsUtils.writeUint24(0, message, 1);

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected void sendServerKeyExchangeMessage(byte[] serverKeyExchange) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        TlsUtils.writeUint8(HandshakeType.server_key_exchange, bos);
        TlsUtils.writeUint24(serverKeyExchange.length, bos);
        bos.write(serverKeyExchange);
        byte[] message = bos.toByteArray();

        safeWriteRecord(ContentType.handshake, message, 0, message.length);
    }

    protected void skipCertificateVerifyMessage() {
        // TODO Inform tlsServer that there's no CertificateVerify
    }
}
