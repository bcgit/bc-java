package org.bouncycastle.crypto.params;

/**
 * A master key capable of the KGC user-key extraction for an identity-based
 * signature scheme: deriving a user's signature private key from the user's
 * identity (GM/T 0044.2-2016 for SM9, where the signature private-key
 * generation function identifier hid is applied internally).
 *
 * @see SM9EncUserKeyParametersGenerator
 */
public interface SM9SigUserKeyParametersGenerator
{
    /**
     * Derive the signature private key of the user identified by {@code identity}, a
     * deterministic KGC operation - the same master key and identity always
     * yield the same user key.
     *
     * @param identity the user's identity.
     * @return the user's signature private key.
     */
    SM9SigPrivateKeyParameters generateUserKey(byte[] identity);
}
