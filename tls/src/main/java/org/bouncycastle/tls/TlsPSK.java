package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsSecret;

public interface TlsPSK
{
    byte[] getIdentity();

    TlsSecret getKey();

    int getPRFAlgorithm();
}
