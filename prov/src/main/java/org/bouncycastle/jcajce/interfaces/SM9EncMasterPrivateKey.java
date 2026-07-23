package org.bouncycastle.jcajce.interfaces;

import java.security.KeyPair;
import java.security.PrivateKey;

/**
 * Interface for an SM9 (GM/T 0044) encryption master private key, the KGC-held
 * root of the identity-based scheme.
 */
public interface SM9EncMasterPrivateKey
    extends PrivateKey
{
    /**
     * Generate the key pair of the user identified by {@code id}: the public key to
     * encapsulate to and the private key that decapsulates. This derivation is a KGC
     * operation (hid = 0x03, GM/T 0044.4) and is deterministic - the same master key
     * and identity always yield the same pair.
     *
     * @param id the user's identity.
     * @return the user's key pair.
     */
    KeyPair generateUserKeyPair(byte[] id);
}
