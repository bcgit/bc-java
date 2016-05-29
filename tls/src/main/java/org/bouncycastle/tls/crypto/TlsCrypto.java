package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.TlsContext;

public interface TlsCrypto
{
    void init(TlsContext context);

    byte[] calculateDigest(short hashAlgorithm, byte[] buf, int off, int len) throws IOException;

    TlsECDomain createECDomain(TlsECConfig ecConfig);
    
}
