package org.bouncycastle.crypto.threshold;

public interface SplitSecret
{
    SecretShare[] getSecretShare();

    /**
     * Recombines secret shares to reconstruct the original secret.
     *
     * @return A byte array containing the reconstructed secret.
     */
    byte[] recombine();
}
