package org.bouncycastle.crypto.threshold;

import java.io.IOException;

public interface SplitSecret
{
    SecretShare[] getSecretShares();

    /**
     * Recombines secret shares to reconstruct the original secret.
     *
     * @return A byte array containing the reconstructed secret.
     */
    byte[] getSecret()
        throws IOException;
}
