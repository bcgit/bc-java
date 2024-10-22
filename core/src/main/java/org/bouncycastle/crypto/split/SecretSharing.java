package org.bouncycastle.crypto.split;

import java.security.SecureRandom;

/**
 * Secret sharing (also called secret splitting) refers to methods for distributing a secret among a group.
 * In this process, no individual holds any intelligible information about the secret.
 * However, when a sufficient number of individuals combine their 'shares', the secret can be reconstructed.
 */
public interface SecretSharing
{
    /**
     * Creates secret shares from a given secret. The secret will be divided into shares, where the secret has a length of L bytes.
     *
     * @param random the source of secure random
     * @return An array of {@code byte[][]} representing the generated secret shares for m users with l bytes each.
     */
    byte[][] createShares(SecureRandom random);

    /**
     * Recombines secret shares to reconstruct the original secret.
     *
     * @param rr The threshold number of shares required for recombination.
     * @param splits A vector of byte arrays representing the shares, where each share is l bytes long.
     * @return A byte array containing the reconstructed secret.
     */
    byte[] recombineShares(int[] rr, byte[]... splits);
}
