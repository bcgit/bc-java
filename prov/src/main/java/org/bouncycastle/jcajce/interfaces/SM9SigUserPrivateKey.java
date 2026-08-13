package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

/**
 * Interface for a user's SM9 (GM/T 0044.2) signature private key (ds_A), derived by the
 * KGC from the signature master private key and the user's identity.
 */
public interface SM9SigUserPrivateKey
    extends PrivateKey
{
    /**
     * The identity this key was derived for.
     *
     * @return the user's identity.
     */
    byte[] getIdentity();
}
