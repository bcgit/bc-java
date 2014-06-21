package org.bouncycastle.crypto.tls;

import java.io.IOException;

public interface TlsEncryptionCredentials
    extends TlsCredentials
{
    byte[] decryptPreMasterSecret(byte[] encryptedPreMasterSecret, byte[] fallback)
        throws IOException;
}
