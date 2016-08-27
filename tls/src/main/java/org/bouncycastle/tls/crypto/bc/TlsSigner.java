package org.bouncycastle.tls.crypto.bc;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;

public interface TlsSigner
{
    void init(TlsContext context);

    byte[] generateRawSignature(SignatureAndHashAlgorithm algorithm, AsymmetricKeyParameter privateKey, byte[] hash)
        throws CryptoException;
}
