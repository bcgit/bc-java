package org.bouncycastle.tls.crypto;

import java.io.IOException;

import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;

public interface TlsSigner
{
    TlsContext getContext();

    byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        throws IOException;
}
