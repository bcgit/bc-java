package org.bouncycastle.gpg;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.BigIntegers;

/**
 * Compute the GnuPG-style "keygrip" for a public key. The keygrip is a 20-byte
 * SHA-1 identifier used by GnuPG 2.x to look up a key without exposing the
 * fingerprint, and is documented in {@code agent/keyformat.txt} of the GnuPG
 * source tree.
 * <p>
 * The supplied {@link PGPDigestCalculator} must wrap SHA-1; the keygrip
 * algorithm is fixed by the GnuPG specification.
 * </p>
 * <p>
 * Currently RSA public keys are supported; the algorithm matches libgcrypt's
 * {@code _gcry_rsa_compute_keygrip} (SHA-1 of the canonical unsigned big-endian
 * encoding of the modulus n).
 * </p>
 */
public class KeyGripCalculator
{
    private final PGPDigestCalculator digestCalculator;

    /**
     * @param digestCalculator a SHA-1 digest calculator used to compute the keygrip.
     */
    public KeyGripCalculator(PGPDigestCalculator digestCalculator)
    {
        if (digestCalculator.getAlgorithm() != HashAlgorithmTags.SHA1)
        {
            throw new IllegalArgumentException("keygrip calculator requires SHA-1");
        }
        this.digestCalculator = digestCalculator;
    }

    /**
     * Compute the keygrip for the supplied PGP public-key material.
     *
     * @param key the BCPGKey to be hashed.
     * @return 20 bytes of SHA-1 output.
     * @throws IOException if writing to the digest calculator fails.
     * @throws IllegalArgumentException if no keygrip algorithm is registered for the key type.
     */
    public byte[] calculateKeygrip(BCPGKey key)
        throws IOException
    {
        if (!(key instanceof RSAPublicBCPGKey))
        {
            throw new IllegalArgumentException(
                "keygrip calculation not yet supported for " + key.getClass().getName());
        }

        digestCalculator.reset();

        OutputStream out = digestCalculator.getOutputStream();
        byte[] n = BigIntegers.asUnsignedByteArray(((RSAPublicBCPGKey)key).getModulus());
        out.write(n);
        out.close();

        return digestCalculator.getDigest();
    }
}
