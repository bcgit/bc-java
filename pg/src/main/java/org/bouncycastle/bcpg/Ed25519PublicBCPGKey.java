package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Public key of type {@link PublicKeyAlgorithmTags#Ed25519}.
 * This type was introduced with Crypto-Refresh and can be used with v4, v6 keys.
 * Note however, that legacy implementations might not understand this key type yet.
 * For a key type compatible with legacy v4 implementations, see {@link EdDSAPublicBCPGKey} with
 * {@link PublicKeyAlgorithmTags#EDDSA_LEGACY}.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-ed2">
 *     Crypto-Refresh - Algorithm-Specific Part for Ed25519 Keys</a>
 */
public class Ed25519PublicBCPGKey
        extends OctetArrayBCPGKey
{
    // 32 octets of the native public key
    public static final int LENGTH = 32;

    public Ed25519PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public Ed25519PublicBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
