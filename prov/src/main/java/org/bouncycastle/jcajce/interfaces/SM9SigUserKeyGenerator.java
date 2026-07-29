package org.bouncycastle.jcajce.interfaces;

import java.security.KeyPair;

/**
 * A master private key capable of the KGC user-key extraction for an
 * identity-based signature scheme: deriving a user's key pair from the user's
 * identity (GM/T 0044.2-2016 for SM9, where the signature private-key
 * generation function identifier hid is applied internally).
 *
 * @see SM9EncUserKeyGenerator
 */
public interface SM9SigUserKeyGenerator
{
    /**
     * Generate the key pair of the user identified by {@code identity}: the private key
     * that signs and the public key a verifier checks against. This derivation is
     * a KGC operation and is deterministic - the same master key and identity
     * always yield the same pair.
     *
     * @param identity the user's identity.
     * @return the user's key pair.
     */
    KeyPair generateUserKeyPair(byte[] identity);
}
