package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.TlsContext;

public interface TlsCrypto
{
    void init(TlsContext context);

    byte[] calculateDigest(short hashAlgorithm, byte[] buf, int off, int len) throws IOException;

    TlsCertificate createCertificate(byte[] encoding);

    TlsECDomain createECDomain(TlsECConfig ecConfig);

    TlsDHDomain createDHDomain(TlsDHConfig dhConfig);

    TlsSecret createSecret(byte[] data);

    TlsSecret generateRandomSecret(int length);
}
