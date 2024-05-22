package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Public key of type {@link PublicKeyAlgorithmTags#X25519}.
 * This type was introduced with Crypto-Refresh and can be used with v4, v6 keys.
 * Note however, that legacy implementations might not understand this key type yet.
 * For a key type compatible with legacy v4 implementations, see {@link ECDHPublicBCPGKey} with
 * {@link PublicKeyAlgorithmTags#ECDH}.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-x">
 *     Crypto-Refresh - Algorithm-Specific Part for X25519 Keys</a>
 */
public class X25519PublicBCPGKey
        extends OctetArrayBCPGKey
{
    // 32 octets of the native public key
    public static final int LENGTH = 32;

    public X25519PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public X25519PublicBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
