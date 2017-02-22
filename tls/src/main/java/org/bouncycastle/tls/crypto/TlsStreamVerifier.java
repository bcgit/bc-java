package org.bouncycastle.tls.crypto;

import java.io.OutputStream;

import org.bouncycastle.tls.SignatureAndHashAlgorithm;

public interface TlsStreamVerifier
{
    OutputStream getOutputStream(SignatureAndHashAlgorithm algorithm);

    boolean isVerified();
}
