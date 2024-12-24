package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.TlsFatalAlert;

public interface AEADNonceGenerator
{
    public void generateNonce(byte[] nonce)
        throws TlsFatalAlert;
}
