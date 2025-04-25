package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

public interface AEADNonceGenerator
{
    public void generateNonce(byte[] nonce) throws IOException;
}
