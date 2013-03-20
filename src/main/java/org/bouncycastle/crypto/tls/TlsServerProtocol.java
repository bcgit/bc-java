package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class TlsServerProtocol extends TlsProtocol {

    private TlsServer tlsServer = null;
    private TlsServerContextImpl tlsServerContext = null;

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
        while (connection_state != CS_SERVER_FINISHED) {
            safeReadData();
        }

        enableApplicationData();
    }

    protected void processChangeCipherSpecMessage() throws IOException {

        switch (this.connection_state) {
        case CS_CLIENT_KEY_EXCHANGE: {
            // TODO Indicate to TlsServer that the certificate verify was skipped

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

    protected void processHandshakeMessage(short type, byte[] buf) throws IOException {
        // TODO
    }
}
