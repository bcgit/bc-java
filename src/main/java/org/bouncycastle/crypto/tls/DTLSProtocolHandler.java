package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

public class DTLSProtocolHandler {

    private final SecureRandom secureRandom;

    public DTLSProtocolHandler(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    public DTLSTransport connect(DatagramTransport transport) {
        return new DTLSTransport(transport);
    }
}
