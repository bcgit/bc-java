package org.bouncycastle.crypto.tls;

import java.io.IOException;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public interface TlsCipherFactory
{
    /**
     * See enumeration classes EncryptionAlgorithm, MACAlgorithm for appropriate argument values
     */
    TlsCipher createCipher(TlsContext context, int encryptionAlgorithm, int macAlgorithm)
        throws IOException;
}
