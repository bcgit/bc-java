package org.bouncycastle.tls;

public interface TlsHash
{
    void update(byte[] data, int offSet, int length);

    int doFinal(byte[] out, int offSet);
}
