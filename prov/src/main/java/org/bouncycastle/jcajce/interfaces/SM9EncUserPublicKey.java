package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

/**
 * Interface for an SM9 (GM/T 0044.4) recipient's encryption public key: an encryption
 * master public key bound to a recipient identity. Obtained from
 * {@link SM9EncMasterPublicKey#getUserPublicKey(byte[])}.
 */
public interface SM9EncUserPublicKey
    extends PublicKey
{
    /**
     * The identity this key was derived for.
     *
     * @return the recipient's identity.
     */
    byte[] getIdentity();

    /**
     * The encryption master public key this key was derived from.
     *
     * @return the encryption master public key.
     */
    SM9EncMasterPublicKey getMasterPublicKey();
}
