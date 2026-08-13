package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

/**
 * Interface for a user's SM9 (GM/T 0044.2) signature public key: the signature master
 * public key bound to the user's identity, the key an {@code SM9} {@link java.security.Signature}
 * verifies against. Obtained from {@link SM9SigMasterPublicKey#getUserPublicKey(byte[])}.
 */
public interface SM9SigUserPublicKey
    extends PublicKey
{
    /**
     * The identity this key was derived for.
     *
     * @return the user's identity.
     */
    byte[] getIdentity();

    /**
     * The signature master public key this key was derived from.
     *
     * @return the signature master public key.
     */
    SM9SigMasterPublicKey getMasterPublicKey();
}
