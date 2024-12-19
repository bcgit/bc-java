package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.crypto.TlsNonceGenerator;

public interface TlsNonceGeneratorFactory
{
    TlsNonceGenerator create(byte[] baseNonce, int counterSizeInBits);
}
