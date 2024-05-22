package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Secret key of type {@link PublicKeyAlgorithmTags#Ed448}.
 * This type was introduced with Crypto-Refresh and can be used with v4, v6 keys.
 * Note however, that legacy implementations might not understand this key type yet.
 * For a key type compatible with legacy v4 implementations, see {@link EdDSAPublicBCPGKey} with
 * {@link PublicKeyAlgorithmTags#EDDSA_LEGACY}.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-ed4">
 *     Crypto-Refresh - Algorithm-Specific Part for Ed448 Keys</a>
 */
public class Ed448SecretBCPGKey
        extends OctetArrayBCPGKey
{
    // 57 octets of the native secret key
    public static final int LENGTH = 57;

    public Ed448SecretBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public Ed448SecretBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
