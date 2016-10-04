package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsSecret;

public interface TlsCredentialedDecryptor
    extends TlsCredentials
{
    TlsSecret decrypt(TlsContext context, byte[] ciphertext) throws IOException;
}
