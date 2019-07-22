package org.bouncycastle.crypto.tls;

import java.io.IOException;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public interface TlsEncryptionCredentials extends TlsCredentials
{
    byte[] decryptPreMasterSecret(byte[] encryptedPreMasterSecret)
        throws IOException;
}
