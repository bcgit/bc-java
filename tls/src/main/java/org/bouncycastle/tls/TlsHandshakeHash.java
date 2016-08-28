package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsHash;

public interface TlsHandshakeHash
    extends TlsHash
{
    TlsHandshakeHash notifyPRFDetermined();

    void trackHashAlgorithm(short hashAlgorithm);

    void sealHashAlgorithms();

    TlsHandshakeHash stopTracking();

    TlsHash forkPRFHash();

    byte[] getFinalHash(short hashAlgorithm);
}
