package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.crypto.TlsNonceGenerator;

public interface AEADNonceGeneratorFactory
{
    AEADNonceGenerator create(byte[] baseNonce, int counterSizeInBits);
}
