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
     * <p>
     * The key returned is always an {@link SM9SigUserPublicKey}, which gives back the identity
     * and the master public key it was formed from, and a caller may rely on the cast; the
     * declared type stays {@code PublicKey} so that code compiled against it keeps linking.
     *
     * @param identity the user's identity.
     * @return the user's public key, an {@link SM9SigUserPublicKey}.
     */
    PublicKey getUserPublicKey(byte[] identity);
}
