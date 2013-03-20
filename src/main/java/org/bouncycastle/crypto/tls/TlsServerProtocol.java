package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;

public class TlsServerProtocol extends TlsProtocol {

    protected TlsServer tlsServer = null;
    protected TlsServerContextImpl tlsServerContext = null;

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
        this.securityParameters.serverRandom = new byte[32];
        random.nextBytes(securityParameters.serverRandom);
        TlsUtils.writeGMTUnixTime(securityParameters.serverRandom, 0);

        this.tlsServerContext = new TlsServerContextImpl(random, securityParameters);
        this.rs.init(tlsServerContext);
        this.tlsServer.init(tlsServerContext);

        /*
         * We will now read data, until we have completed the handshake.
         */
        while (this.connection_state != CS_SERVER_FINISHED) {
            safeReadData();
        }

        enableApplicationData();
    }

    protected TlsContext getContext() {
        return tlsServerContext;
    }

    protected void processChangeCipherSpecMessage() throws IOException {

        switch (this.connection_state) {
        case CS_CLIENT_KEY_EXCHANGE: {
            skipCertificateVerifyMessage();
            // NB: Fall through to next case label
        }
        case CS_CERTIFICATE_VERIFY: {

            // TODO Make sure that rs.decidedWriteCipherSpec is called before this
            rs.receivedReadCipherSpec();

            this.connection_state = CS_SERVER_CHANGE_CIPHER_SPEC;
            break;
        }
        default: {
            this.failWithError(AlertLevel.fatal, AlertDescription.handshake_failure);
        }
        }
    }

    protected void processHandshakeMessage(short type, byte[] data) throws IOException {

        ByteArrayInputStream buf = new ByteArrayInputStream(data);

        switch (type) {
        case HandshakeType.client_hello: {
            switch (this.connection_state) {
            case CS_START: {
                processClientHelloMessage(buf);
                this.connection_state = CS_CLIENT_HELLO;

                // TODO Send ServerHello
                this.connection_state = CS_SERVER_HELLO;
                
                // TODO Send Certificate
                this.connection_state = CS_SERVER_CERTIFICATE;
                
                // TODO Send ServerKeyExchange
                this.connection_state = CS_SERVER_KEY_EXCHANGE;
                
                // TODO Send CertificateRequest
                this.connection_state = CS_CERTIFICATE_REQUEST;

                sendServerHelloDone();
                this.connection_state = CS_SERVER_HELLO_DONE;

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
                processCertificateMessage(buf);
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
                skipCertificateMessage();
                // NB: Fall through to next case label
            }
            case CS_CLIENT_CERTIFICATE: {
                processClientKeyExchangeMessage(buf);
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
                processCertificateVerifyMessage(buf);
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

                sendChangeCipherSpec();
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
        default:
            // We do not support this!
            this.failWithError(AlertLevel.fatal, AlertDescription.unexpected_message);
            break;
        }
    }

    protected void processCertificateMessage(ByteArrayInputStream buf) throws IOException {

        Certificate clientCertificate = Certificate.parse(buf);

        assertEmpty(buf);

        // TODO
    }

    protected void processCertificateVerifyMessage(ByteArrayInputStream buf) throws IOException {
        // TODO

        assertEmpty(buf);
    }

    protected void processClientHelloMessage(ByteArrayInputStream buf) throws IOException {
        // TODO

        assertEmpty(buf);
    }

    protected void processClientKeyExchangeMessage(ByteArrayInputStream buf) throws IOException {
        // TODO

        assertEmpty(buf);
    }

    protected void sendServerHelloDone() throws IOException {

        byte[] message = new byte[4];
        TlsUtils.writeUint8(HandshakeType.server_hello_done, message, 0);
        TlsUtils.writeUint24(0, message, 1);

        rs.writeMessage(ContentType.handshake, message, 0, message.length);
    }

    protected void skipCertificateMessage() {
        // TODO
    }

    protected void skipCertificateVerifyMessage() {
        // TODO
    }
}
