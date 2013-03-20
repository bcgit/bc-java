package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

public class DTLSClientProtocol extends DTLSProtocol {

    public DTLSClientProtocol(SecureRandom secureRandom) {
        super(secureRandom);
    }
}
