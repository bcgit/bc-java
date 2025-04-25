package org.bouncycastle.tls.crypto.impl;

public interface AEADNonceGeneratorFactory
{
    AEADNonceGenerator create(byte[] baseNonce, int counterSizeInBits);
}
