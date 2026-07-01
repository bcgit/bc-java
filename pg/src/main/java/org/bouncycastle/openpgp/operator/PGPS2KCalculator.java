package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;

/**
 * Derives a key from a passphrase for a memory-hard {@link S2K} specifier (currently
 * {@link S2K#ARGON_2 Argon2}, RFC 9580 sec. 3.7.1.4).
 * <p>
 * This is the operator-level abstraction for the one part of the OpenPGP string-to-key process that is
 * not expressible through a {@link PGPDigestCalculator}: a memory-hard KDF. Concrete implementations live
 * in the {@code .bc} and {@code .jcajce} operator subpackages so that the top-level operator package does
 * not depend on a particular crypto provider.
 * </p>
 */
public interface PGPS2KCalculator
{
    /**
     * Return the algorithm type
     */
    int getType();

    /**
     * Derive {@code keyLen} bytes from the supplied passphrase using the parameters carried by the given
     * {@link S2K#ARGON_2 Argon2} S2K specifier.
     *
     * @param passPhrase the passphrase.
     * @param s2k        an {@link S2K#ARGON_2} S2K carrying the salt, passes, parallelism and memory size.
     * @param keyLen     the number of key bytes to produce.
     * @return the derived key.
     * @throws PGPException on error.
     */
    byte[] makeKey(char[] passPhrase, S2K s2k, int keyLen)
        throws PGPException;
}
