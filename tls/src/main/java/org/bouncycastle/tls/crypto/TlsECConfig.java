package org.bouncycastle.tls.crypto;

public interface TlsECConfig
{
    int getNamedCurve();

    boolean compressPoints();
}
