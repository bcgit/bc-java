package org.bouncycastle.tls.crypto;

public interface TlsSecret
{
    TlsSecret deriveSSLKeyBlock(byte[] seed, int length);

    TlsSecret deriveSSLMasterSecret(byte[] seed);

    void destroy();

    byte[] extract();

    TlsSecret prf(int prfAlgorithm, byte[] labelSeed, int length);
}
