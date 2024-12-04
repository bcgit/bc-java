package org.bouncycastle.crypto.threshold;

/**
 * Secret sharing (also called secret splitting) refers to methods for distributing a secret among a group.
 * In this process, no individual holds any intelligible information about the secret.
 * However, when a sufficient number of individuals combine their 'shares', the secret can be reconstructed.
 */
public interface SecretSplitter
{
    /**
     * Creates secret shares from a given secret. The secret will be divided into shares, where the secret has a length of L bytes.
     *
     * @return An array of {@code byte[][]} representing the generated secret shares for m users with l bytes each.
     */
    SplitSecret split();

    /**
     * Recombines secret shares to reconstruct the original secret.
     *
     * @param rr The threshold number of shares required for recombination.
     * @param splits A vector of byte arrays representing the shares, where each share is l bytes long.
     * @return A byte array containing the reconstructed secret.
     */
    byte[] recombineShares(int[] rr, byte[]... splits);
}
