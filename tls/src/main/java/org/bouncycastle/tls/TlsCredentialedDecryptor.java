package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;

public interface TlsCredentialedDecryptor
    extends TlsCredentials
{
    TlsSecret decrypt(TlsCryptoParameters cryptoParams, byte[] ciphertext) throws IOException;
}
