package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class TlsServerProtocol extends TlsProtocol {

    public TlsServerProtocol(InputStream is, OutputStream os, SecureRandom sr) {
        super(is, os, sr);
    }

    public void accept(TlsServer tlsServer) throws IOException {
        // TODO

        enableApplicationData();
    }

    protected void processChangeCipherSpecMessage() throws IOException {
        // TODO
    }

    protected void processHandshakeMessage(short type, byte[] buf) throws IOException {
        // TODO
    }
}
