package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

/**
 * Interface for an SM9 (GM/T 0044) signature master public key, the published
 * root of the identity-based scheme.
 */
public interface SM9SigMasterPublicKey
    extends PublicKey
{
    /**
     * Return the public key of the user identified by {@code identity}: the key a signature
     * from that user verifies against. It is derived from the master public key and the
     * identity alone, so any verifier holding the published master public key can
     * construct it - no certificate or KGC interaction is needed.
     *
     * @param identity the user's identity.
     * @return the user's public key.
     */
    PublicKey getUserPublicKey(byte[] identity);
}
