package org.bouncycastle.tls.crypto;

import java.io.OutputStream;

import org.bouncycastle.tls.SignatureAndHashAlgorithm;

public interface TlsStreamSigner
{
    OutputStream getOutputStream(SignatureAndHashAlgorithm algorithm);

    byte[] getSignature();
}
