package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsSecret;

public interface TlsEncryptionCredentials
    extends TlsCredentials
{
    TlsSecret decryptPreMasterSecret(byte[] encryptedPreMasterSecret) throws IOException;
}
