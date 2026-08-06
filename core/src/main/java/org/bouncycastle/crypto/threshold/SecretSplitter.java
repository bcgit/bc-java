package org.bouncycastle.crypto.threshold;

import java.io.IOException;

/**
 * Secret sharing (also called secret splitting) refers to methods for distributing a secret among a group.
 * In this process, no individual holds any intelligible information about the secret.
 * However, when a sufficient number of individuals combine their 'shares', the secret can be reconstructed.
 */
public interface SecretSplitter
{
    /**
     * Creates secret shares. The secret will be divided into shares, where the secret has a length of L bytes.
     * @param m A threshold number of shares
     * @param n Total number of shares
     * @return the n generated secret shares, each L bytes long, any m of which recover the secret.
     */
    SplitSecret split(int m, int n);

    /**
     * Creates secret shares from a given secret share. The secret will be divided into shares, where the secret has a length of L bytes.
     * @param m A threshold number of shares
     * @param n Total number of shares
     * @return the n generated secret shares, each L bytes long, any m of which recover the secret. The first of them is s.
     */
    SplitSecret splitAround(SecretShare s, int m, int n)
        throws IOException;

    /**
     * Creates secret shares from a given secret. The secret will be divided into shares, where the secret has a length of L bytes.
     * @param m A threshold number of shares
     * @param n Total number of shares
     * @return the n generated secret shares, each L bytes long, any m of which recover the secret.
     */
    SplitSecret resplit(byte[] secret, int m, int n);
}
