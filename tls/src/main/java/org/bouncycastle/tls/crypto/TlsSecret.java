package org.bouncycastle.tls.crypto;

public interface TlsSecret
{
    byte[] extract();

    TlsSecret prf(int prfAlgorithm, byte[] seed, int length);
}
