package org.bouncycastle.crypto.tls;

import java.io.IOException;

public abstract class DefaultTlsServer extends AbstractTlsServer {

    public DefaultTlsServer() {
        super();
    }

    public DefaultTlsServer(TlsCipherFactory cipherFactory) {
        super(cipherFactory);
    }

    protected int[] getCipherSuites() {
        return new int[] { CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA, };
    }

    public TlsCredentials getCredentials() {
        // TODO Auto-generated method stub
        return null;
    }

    public TlsKeyExchange getKeyExchange() throws IOException {
        // TODO Auto-generated method stub
        return null;
    }

    public TlsCipher getCipher() throws IOException {
        // TODO Auto-generated method stub
        return null;
    }
}
