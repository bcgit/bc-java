package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Secret key of type {@link PublicKeyAlgorithmTags#X448}.
 * This type was introduced with Crypto-Refresh and can be used with v4, v6 keys.
 * Note however, that legacy implementations might not understand this key type yet.
 * For a key type compatible with legacy v4 implementations, see {@link ECDHPublicBCPGKey} with
 * {@link PublicKeyAlgorithmTags#ECDH}.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-x4">
 *     Crypto-Refresh - Algorithm-Specific Part for X448 Keys</a>
 */
public class X448SecretBCPGKey
    extends OctetArrayBCPGKey
{
    // 56 octets of the native secret key
    public static final int LENGTH = 56;

    public X448SecretBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public X448SecretBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
