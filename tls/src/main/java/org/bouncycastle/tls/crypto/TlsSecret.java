package org.bouncycastle.tls.crypto;

import java.io.IOException;

public interface TlsSecret
{
    TlsSecret deriveSSLKeyBlock(byte[] seed, int length);

    TlsSecret deriveSSLMasterSecret(byte[] seed);

    void destroy();

    byte[] encryptRSA(TlsCertificate certificate) throws IOException;

    byte[] extract();

    TlsSecret prf(int prfAlgorithm, byte[] labelSeed, int length);

    void replace(int pos, byte[] buf, int bufPos, int bufLen);
}
