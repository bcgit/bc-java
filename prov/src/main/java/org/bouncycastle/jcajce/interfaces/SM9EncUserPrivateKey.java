package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

/**
 * Interface for a user's SM9 (GM/T 0044.4) encryption (KEM / decryption) private key (de),
 * derived by the KGC from the encryption master private key and the user's identity.
 */
public interface SM9EncUserPrivateKey
    extends PrivateKey
{
    /**
     * The identity this key was derived for.
     *
     * @return the user's identity.
     */
    byte[] getIdentity();
}
