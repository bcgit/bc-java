package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.security.SecureRandom;

public class DTLSServerProtocol extends DTLSProtocol {

    protected boolean verifyRequests = true;

    public DTLSServerProtocol(SecureRandom secureRandom) {
        super(secureRandom);
    }

    public boolean getVerifyRequests() {
        return verifyRequests;
    }

    public void setVerifyRequests(boolean verifyRequests) {
        this.verifyRequests = verifyRequests;
    }

    public DTLSTransport connect(TlsServer server, DatagramTransport transport) throws IOException {
        // TODO
        return null;
    }
}
