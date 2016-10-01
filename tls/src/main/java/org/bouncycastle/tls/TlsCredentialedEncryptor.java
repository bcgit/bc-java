package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsSecret;

public interface TlsCredentialedEncryptor
    extends TlsCredentials
{
    TlsSecret decrypt(byte[] ciphertext) throws IOException;
}
