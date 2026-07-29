package org.bouncycastle.jcajce.interfaces;

import java.security.KeyPair;

/**
 * A master private key capable of the KGC user-key extraction for an
 * identity-based encryption-family scheme: deriving a user's key pair from the
 * user's identity and the private-key generation function identifier hid the
 * KGC chose (GM/T 0044.3/0044.4-2016 for SM9, where one encryption master key
 * serves key exchange, KEM and public-key encryption, distinguished by hid).
 *
 * @see SM9SigUserKeyGenerator
 */
public interface SM9EncUserKeyGenerator
{
    /**
     * Generate the key pair of the user identified by {@code identity} under the given
     * hid. This derivation is a KGC operation and is deterministic - the same
     * master key, identity and hid always yield the same pair.
     *
     * @param identity  the user's identity.
     * @param hid the private-key generation function identifier the KGC chose:
     *            {@code 0x03} for KEM / public-key encryption, {@code 0x02} for
     *            key exchange.
     * @return the user's key pair.
     */
    KeyPair generateUserKeyPair(byte[] identity, byte hid);
}
